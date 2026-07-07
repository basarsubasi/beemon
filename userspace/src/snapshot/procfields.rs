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
    parse_stat(&raw)
}

/// Parse the contents of `/proc/<pid>/stat`. Used by tests to avoid disk IO.
pub fn parse_stat(raw: &str) -> Option<(i32, i32, String, char, u64, u64)> {
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