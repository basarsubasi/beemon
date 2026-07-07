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
use std::os::unix::fs::FileTypeExt;

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

    let mut mount_info = String::new();
    let mut net_links = String::new();
    let mut net_routes = String::new();
    let mut uts_info = String::new();
    let mut user_maps = String::new();

    match ns_type {
        "mnt" => {
            if let Ok(m) = std::fs::read_to_string(format!("/proc/{}/mountinfo", ref_pid)) {
                mount_info = m;
            }
        }
        "user" => {
            let uid = std::fs::read_to_string(format!("/proc/{}/uid_map", ref_pid)).unwrap_or_default();
            let gid = std::fs::read_to_string(format!("/proc/{}/gid_map", ref_pid)).unwrap_or_default();
            user_maps = format!("UID Map:\n{}\nGID Map:\n{}", uid, gid);
        }
        "uts" => {
            // Read hostname from /proc/<pid>/environ if available, or fall back to native setns.
            let host_res = std::thread::spawn(move || {
                let ns_path = format!("/proc/{}/ns/uts", ref_pid);
                if let Ok(f) = std::fs::File::open(&ns_path) {
                    use std::os::unix::io::AsRawFd;
                    // Switch UTS namespace for this temporary thread if needed
                    let my_pid = std::process::id();
                    let needs_setns = ref_pid != my_pid;
                    if !needs_setns || unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWUTS) } == 0 {
                        let hostname = nix::unistd::gethostname()
                            .ok()
                            .into_iter()
                            .map(|s| s.to_string_lossy().to_string())
                            .next()
                            .unwrap_or_default();
                        // Domain name is technically available via getdomainname, but not easily accessible in nix 0.31 without unsafe.
                        // Let's just return hostname.
                        return format!("hostname={}", hostname);
                    }
                }
                String::new()
            })
            .join()
            .unwrap_or_default();
            uts_info = host_res;
        }
        "net" => {
            // Read route from proc
            if let Ok(r) = std::fs::read_to_string(format!("/proc/{}/net/route", ref_pid)) {
                net_routes = r;
            }

            // Spawn a thread to setns and read network interfaces
            net_links = std::thread::spawn(move || {
                let ns_path = format!("/proc/{}/ns/net", ref_pid);
                let f = match std::fs::File::open(&ns_path) {
                    Ok(f) => f,
                    Err(_) => return String::from("Error: Could not open network namespace"),
                };

                let my_pid = std::process::id();
                let needs_setns = ref_pid != my_pid;
                
                if needs_setns {
                    use std::os::unix::io::AsRawFd;
                    if unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                        return String::from("Error: Failed to setns to network namespace");
                    }
                }

                let mut out = String::new();
                if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
                    let mut iface_map: std::collections::BTreeMap<String, (String, Vec<String>)> = std::collections::BTreeMap::new();
                    
                    for iface in addrs {
                        let name = iface.interface_name;
                        let flags = format!("{:?}", iface.flags).replace(" | ", ",");
                        
                        let entry = iface_map.entry(name.clone()).or_insert_with(|| (flags, Vec::new()));
                        
                        if let Some(addr) = iface.address {
                            if let Some(sockaddr) = addr.as_sockaddr_in() {
                                entry.1.push(format!("inet {}", sockaddr.ip()));
                            } else if let Some(sockaddr6) = addr.as_sockaddr_in6() {
                                entry.1.push(format!("inet6 {}", sockaddr6.ip()));
                            }
                        }
                    }

                    // Format it to match the expected UI output (like ip addr)
                    let mut i = 1;
                    for (name, (flags, ips)) in iface_map {
                        out.push_str(&format!("{}: {}: <{}>\n", i, name, flags));
                        for ip in ips {
                            out.push_str(&format!("    {}\n", ip));
                        }
                        i += 1;
                    }
                }
                out
            })
            .join()
            .unwrap_or_default();
        }
        _ => {}
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::namespace_tree_cache::NamespaceTreeCache;
    use std::time::Duration;

    fn make_process(pid: u32, ppid: u32) -> Process {
        Process {
            pid,
            ppid,
            name: format!("process_{}", pid),
            state: "S".to_string(),
            memory_usage_bytes: 1024,
            cpu_usage_percent: 0.0,
            memory_limit_bytes: 0,
            cpu_quota_us: 0,
            cpu_period_us: 0,
            pids_limit: 0,
            namespaces: vec![],
            open_files: vec![],
            active_connections: vec![],
            io_read_bytes: 0,
            io_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
        }
    }

    #[test]
    fn test_resolve_children_empty() {
        let processes = HashMap::new();
        let children = resolve_children(1, &processes);
        assert!(children.is_empty());
    }

    #[test]
    fn test_resolve_children_no_children() {
        let mut processes = HashMap::new();
        processes.insert(1, make_process(1, 0));
        processes.insert(2, make_process(2, 0));
        processes.insert(3, make_process(3, 0));
        
        let children = resolve_children(1, &processes);
        assert!(children.is_empty());
    }

    #[test]
    fn test_resolve_children_with_children() {
        let mut processes = HashMap::new();
        processes.insert(1, make_process(1, 0));
        processes.insert(2, make_process(2, 1));
        processes.insert(3, make_process(3, 1));
        processes.insert(4, make_process(4, 2));
        
        let children = resolve_children(1, &processes);
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].pid, 2);
        assert_eq!(children[1].pid, 3);
    }

    #[test]
    fn test_resolve_children_sorted() {
        let mut processes = HashMap::new();
        processes.insert(1, make_process(1, 0));
        processes.insert(100, make_process(100, 1));
        processes.insert(50, make_process(50, 1));
        processes.insert(200, make_process(200, 1));
        
        let children = resolve_children(1, &processes);
        assert_eq!(children.len(), 3);
        assert_eq!(children[0].pid, 50);
        assert_eq!(children[1].pid, 100);
        assert_eq!(children[2].pid, 200);
    }

    #[test]
    fn test_resolve_children_multiple_parents() {
        let mut processes = HashMap::new();
        processes.insert(1, make_process(1, 0));
        processes.insert(2, make_process(2, 1));
        processes.insert(3, make_process(3, 2));
        processes.insert(4, make_process(4, 2));
        processes.insert(5, make_process(5, 3));
        
        let children_of_1 = resolve_children(1, &processes);
        assert_eq!(children_of_1.len(), 1);
        assert_eq!(children_of_1[0].pid, 2);
        
        let children_of_2 = resolve_children(2, &processes);
        assert_eq!(children_of_2.len(), 2);
        assert_eq!(children_of_2[0].pid, 3);
        assert_eq!(children_of_2[1].pid, 4);
        
        let children_of_3 = resolve_children(3, &processes);
        assert_eq!(children_of_3.len(), 1);
        assert_eq!(children_of_3[0].pid, 5);
    }

    #[test]
    fn test_read_namespace_details_with_reference_pid() {
        let ns_tree = NamespaceTreeCache::new(Duration::from_secs(10));
        
        let result = read_namespace_details("mnt", "4026531840", 1, &ns_tree);
        
        assert_eq!(result.ns_type, "mnt");
        assert_eq!(result.ns_inode, "4026531840");
        // mount_info, net_links, etc. may be empty or have content depending on system
    }

    #[test]
    fn test_read_namespace_details_zero_pid_not_found() {
        let ns_tree = NamespaceTreeCache::new(Duration::from_secs(10));
        
        let result = read_namespace_details("mnt", "9999999", 0, &ns_tree);
        
        assert_eq!(result.ns_type, "mnt");
        assert_eq!(result.ns_inode, "9999999");
        assert!(result.mount_info.is_empty());
        assert!(result.net_links.is_empty());
        assert!(result.net_routes.is_empty());
        assert!(result.uts_info.is_empty());
        assert!(result.user_maps.is_empty());
    }

    #[test]
    fn test_read_namespace_details_invalid_inode() {
        let ns_tree = NamespaceTreeCache::new(Duration::from_secs(10));
        
        let result = read_namespace_details("mnt", "not_a_number", 0, &ns_tree);
        
        assert_eq!(result.ns_type, "mnt");
        assert_eq!(result.ns_inode, "not_a_number");
        assert!(result.mount_info.is_empty());
    }

    #[test]
    fn test_read_namespace_details_native_reads_self() {
        let ns_tree = NamespaceTreeCache::new(Duration::from_secs(10));
        let my_pid = std::process::id();
        
        // Test MNT
        let mnt_res = read_namespace_details("mnt", "123", my_pid, &ns_tree);
        assert_eq!(mnt_res.ns_type, "mnt");
        assert!(!mnt_res.mount_info.is_empty(), "mount_info should not be empty for self");
        assert!(mnt_res.net_links.is_empty(), "net_links should be empty when requesting mnt");
        
        // Test NET
        let net_res = read_namespace_details("net", "123", my_pid, &ns_tree);
        assert_eq!(net_res.ns_type, "net");
        assert!(!net_res.net_links.is_empty(), "net_links should not be empty for self");
        // net_routes can sometimes be empty on minimal loopback only network ns, but typically not. We'll skip strict empty check on route.
        assert!(net_res.mount_info.is_empty(), "mount_info should be empty when requesting net");
        
        // Test UTS
        let uts_res = read_namespace_details("uts", "123", my_pid, &ns_tree);
        assert_eq!(uts_res.ns_type, "uts");
        assert!(uts_res.uts_info.contains("hostname="), "uts_info should contain hostname");
        
        // Test USER
        let user_res = read_namespace_details("user", "123", my_pid, &ns_tree);
        assert_eq!(user_res.ns_type, "user");
        assert!(user_res.user_maps.contains("UID Map:"), "user_maps should contain UID Map:");
    }

    #[test]
    fn test_net_links_formatting() {
        let ns_tree = NamespaceTreeCache::new(Duration::from_secs(10));
        let my_pid = std::process::id();
        let net_res = read_namespace_details("net", "123", my_pid, &ns_tree);
        
        // Assert the exact expected format that the BFF UI parser expects.
        // Format should be: "1: lo: <LOOPBACK,UP>\n    inet 127.0.0.1\n"
        let lines: Vec<&str> = net_res.net_links.lines().collect();
        assert!(!lines.is_empty(), "net_links should have lines");
        
        let mut found_interface = false;
        let mut found_inet = false;
        
        for line in lines {
            if line.contains(": ") && line.contains(": <") && line.contains(">") {
                found_interface = true;
            } else if line.trim().starts_with("inet ") || line.trim().starts_with("inet6 ") {
                found_inet = true;
            }
        }
        
        assert!(found_interface, "net_links should contain an interface header line matching the UI regex");
        assert!(found_inet, "net_links should contain at least one inet or inet6 line");
    }

    #[test]
    fn test_enrich_nonexistent_pid() {
        let mut process = make_process(999999999, 0);
        enrich(&mut process);
        
        assert!(process.open_files.is_empty());
        assert!(process.active_connections.is_empty());
    }

    #[test]
    fn test_read_open_files_pub_nonexistent_pid() {
        let files = read_open_files_pub(999999999);
        assert!(files.is_empty());
    }

    #[test]
    fn test_read_active_connections_pub_nonexistent_pid() {
        let connections = read_active_connections_pub(999999999);
        assert!(connections.is_empty());
    }
}