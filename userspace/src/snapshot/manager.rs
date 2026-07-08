use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Systemd,
    Containerd,
    Docker,
    Podman,
    Crio,
}

impl Manager {
    pub fn as_str(&self) -> &'static str {
        match self {
            Manager::Systemd => "systemd",
            Manager::Containerd => "containerd",
            Manager::Docker => "dockerd",
            Manager::Podman => "podman",
            Manager::Crio => "crio",
        }
    }
}

impl std::fmt::Display for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct ProcInfo {
    pub comm: String,
    pub ppid: u32,
}

pub fn read_proc_info(pid: u32) -> Option<ProcInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let comm_start = stat.find('(')?;
    let comm_end = stat.rfind(')')?;
    let comm = stat[comm_start + 1..comm_end].to_string();
    let rest: Vec<&str> = stat[comm_end + 2..].split_whitespace().collect();
    let ppid: u32 = rest.get(1)?.parse().ok()?;
    Some(ProcInfo { comm, ppid })
}

pub fn detect_manager(pid: u32, cache: &HashMap<u32, (String, u32)>) -> Option<Manager> {
    let mut current_pid = pid;
    let mut visited = std::collections::HashSet::new();
    let mut depth = 0u32;

    loop {
        if current_pid == 0 || visited.contains(&current_pid) {
            return None;
        }
        visited.insert(current_pid);

        let (comm, ppid) = if let Some((cached_comm, cached_ppid)) = cache.get(&current_pid) {
            (cached_comm.clone(), *cached_ppid)
        } else if let Some(info) = read_proc_info(current_pid) {
            (info.comm, info.ppid)
        } else {
            return None;
        };

        let manager = if depth == 0 {
            None
        } else {
            match comm.as_str() {
                "systemd" if depth == 1 => Some(Manager::Systemd),
                "containerd" => Some(Manager::Containerd),
                "dockerd" => Some(Manager::Docker),
                "podman" => Some(Manager::Podman),
                "crio" => Some(Manager::Crio),
                _ => None,
            }
        };

        if manager.is_some() {
            return manager;
        }

        if ppid == 0 || ppid == current_pid {
            return None;
        }

        depth += 1;
        current_pid = ppid;
    }
}
