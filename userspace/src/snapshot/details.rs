//! On-demand heavy walks used by `GetProcessMetadata` and
//! `GetNamespaceDetails`. These are NOT cached — invoked only when the UI
//! opens the per-process details view, so the cost is paid once per click.
//!
//! `open_files` walks `/proc/<pid>/fd/*` and `readlink`s each entry.
//! `active_connections` parses `/proc/net/{tcp,tcp6,udp,udp6}` and matches
//! socket inode to the pid's fd set.
//!
//! `GetNamespaceDetails` falls back to the [`super::namespace_tree_cache`]
//! to resolve a reference pid when the caller provides `reference_pid = 0`.

use std::collections::HashMap;
use std::fs;

use procfs::net::{tcp, tcp6, udp, udp6};
use tracing::warn;

use crate::pb::pb::{GetNamespaceDetailsResponse, NetworkConnection, OpenFile, Process};

/// Return the given cached `Process` enriched with `open_files` and
/// `active_connections` populated by walking `/proc/<pid>/fd/*` and
/// `/proc/net/*`. If any read fails the corresponding list is left empty.
pub fn enrich(process: &mut Process) {
    process.open_files = read_open_files(process.pid);
    process.active_connections = read_active_connections(process.pid);
}

/// Walk `/proc/<pid>/fd/*` and produce `OpenFile` entries. On error returns `Vec::new()`.
fn read_open_files(pid: u32) -> Vec<OpenFile> {
    read_open_files_pub(pid)
}

/// Public version used by the gRPC service to enrich the requested `Process`
/// without going through `enrich()` (which would mutate the cached entry).
pub fn read_open_files_pub(pid: u32) -> Vec<OpenFile> {
    let fd_dir = format!("/proc/{pid}/fd");
    let mut out = Vec::new();
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for e in entries.flatten() {
        // fd name = the fd number; target = the link destination.
        let fd_name = match e.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let fd: u32 = match fd_name.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let target = match fs::read_link(e.path()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let path = target.to_string_lossy().to_string();
        // Classify by the link target shape: socket:[inode], pipe:[inode],
        // /dev/*, anon_inode:..., real paths.
        let ty = classify_fd(&path);
        out.push(OpenFile { fd, path, r#type: ty });
    }
    out
}

fn classify_fd(path: &str) -> String {
    if path.starts_with("socket:[") || path.starts_with("[socket:") {
        "socket".to_string()
    } else if path.starts_with("pipe:[") {
        "pipe".to_string()
    } else if path.starts_with("/dev/") {
        "char".to_string()
    } else if path.starts_with("anon_inode:") {
        "other".to_string()
    } else if let Some(rest) = path.strip_prefix("/proc/") {
        // `/proc/<pid>/...` style → directory
        if rest.contains('/') {
            "directory".to_string()
        } else {
            "directory".to_string()
        }
    } else if let Some(_suffix) = path.strip_prefix('/') {
        // Best-effort: real paths. Could be regular file or directory.
        match fs::metadata(path) {
            Ok(m) => {
                if m.is_dir() {
                    "directory"
                } else if m.is_file() {
                    "regular"
                } else if m.file_type().is_fifo() {
                    "fifo"
                } else {
                    "other"
                }
            }
            Err(_) => "regular", // assume regular; could be a deleted file
        }
        .to_string()
    } else {
        "other".to_string()
    }
}

/// Collect socket inode → link name from `/proc/<pid>/fd/*`. Used to match
/// network entries to this pid by inode.
fn socket_inodes_for_pid(pid: u32) -> Vec<u64> {
    let mut inodes = Vec::new();
    let fd_dir = format!("/proc/{pid}/fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return inodes;
    };
    for e in entries.flatten() {
        if let Ok(target) = fs::read_link(e.path()) {
            let s = target.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(end) = rest.strip_suffix(']') {
                    if let Ok(n) = end.parse::<u64>() {
                        inodes.push(n);
                    }
                }
            }
        }
    }
    inodes
}

/// Parse the four `/proc/net/*` socket tables and return every connection
/// whose inode matches one of the pid's socket fds.
fn read_active_connections(pid: u32) -> Vec<NetworkConnection> {
    read_active_connections_pub(pid)
}

/// Public version (see [`read_open_files_pub`]).
pub fn read_active_connections_pub(pid: u32) -> Vec<NetworkConnection> {
    let inodes = socket_inodes_for_pid(pid);
    if inodes.is_empty() {
        return Vec::new();
    }
    let inode_set: std::collections::HashSet<u64> = inodes.into_iter().collect();

    let mut out = Vec::new();
    // We attach a direction heuristic: TCP listener (state LISTEN, sport=0
    // remote) → "inbound"; outbound connection → "outbound".
    push_tcp(&mut out, &inode_set);
    push_udp(&mut out, &inode_set);
    out
}

fn push_tcp(out: &mut Vec<NetworkConnection>, inode_set: &std::collections::HashSet<u64>) {
    for entry_fn in [tcp, tcp6] {
        let entries = match entry_fn() {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "tcp read failed");
                continue;
            }
        };
        for e in entries {
            if !inode_set.contains(&e.inode) {
                continue;
            }
            let state = format!("{:?}", e.state);
            let direction = if matches!(e.state, procfs::net::TcpState::Listen) {
                "inbound"
            } else {
                "outbound"
            };
            out.push(NetworkConnection {
                local_address: e.local_address.to_string(),
                remote_address: e.remote_address.to_string(),
                state,
                direction: direction.to_string(),
            });
        }
    }
}

fn push_udp(out: &mut Vec<NetworkConnection>, inode_set: &std::collections::HashSet<u64>) {
    for entry_fn in [udp, udp6] {
        let entries = match entry_fn() {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "udp read failed");
                continue;
            }
        };
        for e in entries {
            if !inode_set.contains(&e.inode) {
                continue;
            }
            out.push(NetworkConnection {
                local_address: e.local_address.to_string(),
                remote_address: e.remote_address.to_string(),
                state: "UNCONNECTED".to_string(),
                direction: "outbound".to_string(),
            });
        }
    }
}

/// Implementation of `GetNamespaceDetails`. Walks the per-namespace files
/// under `/proc/<reference_pid>/` to derive the human-readable strings.
///
/// If `reference_pid == 0`, the namespace tree cache resolves any pid sharing
/// the requested `(ns_type, ns_inode)` — failing that, the response is empty.
pub fn read_namespace_details(
    ns_type: &str,
    ns_inode: &str,
    reference_pid: u32,
    namespace_tree: &super::namespace_tree_cache::NamespaceTreeCache,
) -> GetNamespaceDetailsResponse {
    let ref_pid = if reference_pid > 0 {
        reference_pid
    } else {
        // Parse the ns_inode string to a u64 and look up any pid in the
        // namespace tree cache.
        match ns_inode.parse::<u64>() {
            Ok(inode) => namespace_tree.find_any_pid(ns_type, inode).unwrap_or(0),
            Err(_) => 0,
        }
    };

    if ref_pid == 0 {
        // No reference pid available; return an empty (but valid) response
        // that echoes the requested inode/type. The UI renders an empty
        // details panel rather than 404'ing the whole RPC.
        return GetNamespaceDetailsResponse {
            ns_type: ns_type.to_string(),
            ns_inode: ns_inode.to_string(),
            mount_info: String::new(),
            net_links: String::new(),
            net_routes: String::new(),
            uts_info: String::new(),
            user_maps: String::new(),
        };
    }

    let mount_info = read_file_string(&format!("/proc/{ref_pid}/mountinfo"));
    let net_links = read_file_string(&format!("/proc/{ref_pid}/net/ip_tables_names"));
    let net_routes = read_file_string(&format!("/proc/{ref_pid}/net/route"));
    let uts_info = read_uts(ref_pid);
    let user_maps = read_user_maps(ref_pid);

    GetNamespaceDetailsResponse {
        ns_type: ns_type.to_string(),
        ns_inode: ns_inode.to_string(),
        mount_info,
        net_links,
        net_routes,
        uts_info,
        user_maps,
    }
}

fn read_file_string(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn read_uts(reference_pid: u32) -> String {
    let hostname = read_file_string(&format!("/proc/{reference_pid}/uts/hostname"));
    let domainname = read_file_string(&format!("/proc/{reference_pid}/uts/domainname"));
    format!("hostname={hostname}\ndomainname={domainname}")
}

fn read_user_maps(reference_pid: u32) -> String {
    let uid_map = read_file_string(&format!("/proc/{reference_pid}/uid_map"));
    let gid_map = read_file_string(&format!("/proc/{reference_pid}/gid_map"));
    format!("uid_map:\n{uid_map}\ngid_map:\n{gid_map}")
}

/// Resolve the children of `pid` by reading `/proc/<child>/stat.ppid` for
/// every running process and matching. Returns their cached `Process`
/// entries (light fields only; the UI rarely needs details for children).
pub fn resolve_children(parent_pid: u32, processes: &HashMap<u32, Process>) -> Vec<Process> {
    let mut children = Vec::new();
    for (_cpid, p) in processes.iter() {
        if p.ppid == parent_pid {
            children.push(p.clone());
        }
    }
    children.sort_by_key(|p| p.pid);
    children
}