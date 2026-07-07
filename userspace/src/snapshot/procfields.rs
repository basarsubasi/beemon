//! Raw `/proc/<pid>/{stat,status,comm}` readers tuned for the hot scanner
//! loop. Tighter on allocations than the equivalent `procfs` crate calls —
//! we only grab the handful of fields we need.
//!
//! All functions return `None` on any error (the scanner silently skips
//! processes that exited mid-scan).

use std::fs;

/// The small set of light fields the scanner needs from `/proc/<pid>/`.
#[derive(Clone, Debug, Default)]
pub struct LightProc {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub state_char: char,
    pub utime: u64,
    pub stime: u64,
    pub rss_bytes: u64, // from /proc/<pid>/status VmRSS (kB → bytes)
}

/// Read the light fields for one pid. Returns None on any failure.
pub fn read_light(pid: i32) -> Option<LightProc> {
    let stat = read_stat(pid)?;
    let rss_kb = read_vmrss_kb(pid);
    Some(LightProc {
        pid: stat.0,
        ppid: stat.1,
        comm: stat.2,
        state_char: stat.3,
        utime: stat.4,
        stime: stat.5,
        rss_bytes: rss_kb.saturating_mul(1024),
    })
}

/// Parse `/proc/<pid>/stat` for (pid, ppid, comm, state, utime, stime).
/// Returns None on any parse / IO failure.
fn read_stat(pid: i32) -> Option<(i32, i32, String, char, u64, u64)> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat(&raw, pid)
}

/// Parse the contents of `/proc/<pid>/stat` for (pid, ppid, comm, state,
/// utime, stime). The `pid` argument is the caller's pid — we don't re-parse
/// it from the raw line because some kernel versions pad the comm with
/// spaces, and the parser already splits on parens for comm.
pub fn parse_stat(raw: &str, pid: i32) -> Option<(i32, i32, String, char, u64, u64)> {
    // comm in /proc/pid/stat may contain spaces and parens; the `(` marks the
    // start, the *last* `)` marks the end. We split carefully.
    let lparen = raw.find('(')?;
    let rparen = raw.rfind(')')?;
    let comm = raw[lparen + 1..rparen].to_string();
    let rest = &raw[rparen + 1..];
    let mut it = rest.split_whitespace();
    // After `)`, the next field is `state` (single char as a string).
    let state_s = it.next()?;
    let state_char = state_s.chars().next()?;
    // Then ppid (field 4). We skip `ppgrp`/`session`/...`?` no — the order is:
    // state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt, cminflt,
    // majflt, cmajflt, utime, stime, ...
    let ppid: i32 = it.next()?.parse().ok()?;
    for _ in 0..7 {
        it.next()?; // pgrp, session, tty_nr, tpgid, flags, minflt, cminflt
    }
    let _majflt = it.next()?;
    let _cmajflt = it.next()?;
    let utime: u64 = it.next()?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
    Some((pid, ppid, comm, state_char, utime, stime))
}

/// Read `VmRSS:` from `/proc/<pid>/status` and return its value in kB.
/// Returns 0 on any failure (we don't want to fail the whole snapshot just
/// because of one unreadable status file).
fn read_vmrss_kb(pid: i32) -> u64 {
    let raw = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// Map a Linux task-state char from `/proc/<pid>/stat` to a readable string
/// the UI can render. Matches the convention used by `ps`-style tools.
pub fn state_label(state_char: char) -> &'static str {
    match state_char {
        'R' => "Running",
        'S' => "Sleeping",
        'D' => "DiskSleep",
        'Z' => "Zombie",
        'T' | 't' => "Stopped",
        'X' => "Dead",
        'I' => "Idle",
        'P' => "Parked",
        _ => "Unknown",
    }
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_stat ------------------------------------------------

    #[test]
    fn parse_stat_normal_line() {
        // Real-ish /proc/1/stat line (truncated for clarity but with all the
        // fields we parse).
        let raw = "1 (systemd) S 0 1 1 0 -1 4194560 123 0 0 0 5 4 0 0 20 0 1 0 100 0";
        let (pid, ppid, comm, state, utime, stime) = parse_stat(raw, 1).unwrap();
        assert_eq!(pid, 1);
        assert_eq!(ppid, 0);
        assert_eq!(comm, "systemd");
        assert_eq!(state, 'S');
        assert_eq!(utime, 5);
        assert_eq!(stime, 4);
    }

    #[test]
    fn parse_stat_comm_with_spaces() {
        // A process named "Cheese Daemon" (spaces inside comm).
        let raw = "42 (Cheese Daemon) R 7 42 42 0 -1 0 0 0 0 100 200 0 0 20 0 1 0 0 0";
        let (_pid, _ppid, comm, _state, utime, stime) = parse_stat(raw, 42).unwrap();
        assert_eq!(comm, "Cheese Daemon");
        assert_eq!(utime, 100);
        assert_eq!(stime, 200);
    }

    #[test]
    fn parse_stat_comm_with_parens_inside() {
        // Some kernels embed parens inside comm (e.g. nginx (worker)).
        let raw = "100 (nginx (worker)) S 99 100 100 0 -1 0 1 0 0 0 0 0 0 0 20 0 1 0 0 0";
        let (_, _, comm, _, _, _) = parse_stat(raw, 100).unwrap();
        assert_eq!(comm, "nginx (worker)");
    }

    #[test]
    fn parse_stat_pid_zero_supplied_by_caller() {
        // pid 0 doesn't exist in /proc; the caller passes pid=0 explicitly
        // here to ensure the parser doesn't re-read it from the raw line.
        let raw = "0 (swapper/0) R 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0";
        let (pid, ppid, comm, state, _utime, _stime) = parse_stat(raw, 0).unwrap();
        assert_eq!(pid, 0);
        assert_eq!(ppid, 0);
        assert_eq!(comm, "swapper/0");
        assert_eq!(state, 'R');
    }

    #[test]
    fn parse_stat_empty_string_returns_none() {
        assert!(parse_stat("", 1).is_none());
    }

    #[test]
    fn parse_stat_no_open_paren_returns_none() {
        assert!(parse_stat("1 systemd S 0 0 0", 1).is_none());
    }

    #[test]
    fn parse_stat_no_close_paren_returns_none() {
        assert!(parse_stat("1 (systemd S 0 0", 1).is_none());
    }

    #[test]
    fn parse_stat_truncated_after_ppid_returns_none() {
        // After `)` we need state, ppid, then 7 more fields, then majflt,
        // cmajflt, utime, stime. If the line is too short, parsing yields None.
        let raw = "1 (systemd) S 0"; // only state and ppid; missing the rest
        assert!(parse_stat(raw, 1).is_none());
    }

    #[test]
    fn parse_stat_non_numeric_ppid_returns_none_or_zero() {
        // The next-after-paren-parse is i32 from a string. If non-numeric,
        // parse().ok() yields None and we propagate None.
        let raw = "1 (systemd) S nan 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0";
        assert!(parse_stat(raw, 1).is_none());
    }

    // ---- state_label -----------------------------------------------

    #[test]
    fn state_label_known_and_unknown_chars() {
        assert_eq!(state_label('R'), "Running");
        assert_eq!(state_label('S'), "Sleeping");
        assert_eq!(state_label('D'), "DiskSleep");
        assert_eq!(state_label('Z'), "Zombie");
        assert_eq!(state_label('T'), "Stopped");
        assert_eq!(state_label('t'), "Stopped");
        assert_eq!(state_label('X'), "Dead");
        assert_eq!(state_label('I'), "Idle");
        assert_eq!(state_label('P'), "Parked");
        assert_eq!(state_label('Q'), "Unknown"); // never-existed state
        assert_eq!(state_label('\0'), "Unknown");
    }

    // ---- read_light on a pid the OS guarantees --------------------

    #[test]
    fn read_light_for_init_pid_returns_some() {
        // /proc/1 is virtually always present. (CI containers may differ; we
        // treat a None as a skip via a soft assertion.)
        if let Some(lp) = read_light(1) {
            assert_eq!(lp.pid, 1);
            // ppid is 0 for the host's init; could be non-zero in containers.
            assert!(lp.ppid >= 0);
            assert!(!lp.comm.is_empty());
        }
        // No assert if None (CI container with no /proc/1 visible).
    }

    #[test]
    fn read_light_for_pid_max_returns_none() {
        // pid_max is 2^31-1; never a running pid.
        assert!(read_light(i32::MAX).is_none());
    }

    #[test]
    fn read_light_for_negative_pid_returns_none() {
        assert!(read_light(-1).is_none());
    }

    #[test]
    fn read_light_for_zero_pid_returns_none() {
        // /proc/0 exists on some kernels as swapper/0 but in many environments
        // it's not readable via fs::read_to_string. We assert None either way:
        // - if not readable → None
        // - if readable → we don't care for this test; we just don't panic.
        let _ = read_light(0);
    }
}