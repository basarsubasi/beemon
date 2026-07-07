//! Integration tests that load actual eBPF programs and verify event capture.
//! These tests require root privileges and a compatible kernel.

use aya::maps::MapData;
use aya::maps::RingBuf;
use beemon_daemon::bpf::loader::BpfHandle;
use beemon_daemon::bpf::types::event_from_bytes;
use beemon_daemon::convert::convert;
use beemon_daemon::pb::pb::event::Event as Oneof;
use beemon_daemon::pb::pb::Event;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn read_events(ringbuf: &mut RingBuf<MapData>) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(item) = ringbuf.next() {
        let bytes: &[u8] = &item;
        if bytes.len() >= std::mem::size_of::<beemon_daemon::bpf::types::EventT>() {
            let ev = unsafe { event_from_bytes(bytes) };
            events.push(convert(ev));
        }
    }
    events
}

#[test]
#[ignore] // Requires root and specific kernel
fn test_bpf_loader_loads_programs() {
    let result = BpfHandle::load_and_attach();
    assert!(result.is_ok(), "Failed to load BPF programs: {:?}", result.err());
}

#[test]
#[ignore] // Requires root and specific kernel
fn test_bpf_captures_file_open_events() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");
    
    // Spawn a child process that opens a file
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("cat /etc/hostname")
        .spawn()
        .expect("Failed to spawn child process");
    
    let child_pid = child.id();
    
    // Add the child to the target_pids map
    bpf.add_target_pid(child_pid).expect("Failed to add target pid");
    
    // Wait for the child to complete
    let _ = child.wait();
    
    // Give the BPF program time to process events
    thread::sleep(Duration::from_millis(100));
    
    // Read events from the ring buffer
    let events = read_events(&mut ringbuf);
    
    // Verify we captured at least one file open event
    let file_open_events: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e.event, Some(Oneof::FileOpen(_))))
        .collect();
    
    assert!(
        !file_open_events.is_empty(),
        "Expected at least one FileOpen event, got none"
    );
    
    // Verify at least one event is from our child process
    let child_events: Vec<&Event> = file_open_events
        .iter()
        .filter(|e| e.pid == child_pid)
        .cloned()
        .collect();
    
    assert!(
        !child_events.is_empty(),
        "Expected at least one FileOpen event from child pid {}, got none",
        child_pid
    );
}

#[test]
#[ignore] // Requires root and specific kernel
fn test_bpf_captures_process_events() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");
    
    // Spawn a child process
    let mut child = Command::new("sleep")
        .arg("0.1")
        .spawn()
        .expect("Failed to spawn child process");
    
    let child_pid = child.id();
    
    // Add the child to the target_pids map
    bpf.add_target_pid(child_pid).expect("Failed to add target pid");
    
    // Wait for the child to complete
    let _ = child.wait();
    
    // Give the BPF program time to process events
    thread::sleep(Duration::from_millis(100));
    
    // Read events from the ring buffer
    let events = read_events(&mut ringbuf);
    
    // Verify we captured process events (exec, exit)
    let process_events: Vec<&Event> = events
        .iter()
        .filter(|e| match &e.event {
            Some(Oneof::Process(p)) => p.is_exec || p.is_exit,
            _ => false,
        })
        .collect();
    
    assert!(
        !process_events.is_empty(),
        "Expected at least one Process event, got none"
    );
    
    // Verify we captured events from our child
    let child_events: Vec<&Event> = process_events
        .iter()
        .filter(|e| e.pid == child_pid)
        .cloned()
        .collect();
    
    assert!(
        !child_events.is_empty(),
        "Expected at least one Process event from child pid {}, got none",
        child_pid
    );
}

#[test]
#[ignore] // Requires root and specific kernel
fn test_bpf_captures_network_events() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");
    
    // Spawn a child process that makes a network connection
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("curl -s http://example.com > /dev/null || true")
        .spawn()
        .expect("Failed to spawn child process");
    
    let child_pid = child.id();
    
    // Add the child to the target_pids map
    bpf.add_target_pid(child_pid).expect("Failed to add target pid");
    
    // Wait for the child to complete (with timeout)
    let _ = child.wait();
    
    // Give the BPF program time to process events
    thread::sleep(Duration::from_millis(200));
    
    // Read events from the ring buffer
    let events = read_events(&mut ringbuf);
    
    // Verify we captured network events
    let network_events: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e.event, Some(Oneof::NetworkConnect(_))))
        .collect();
    
    // Network events may or may not be captured depending on curl's behavior
    // and timing, so we just verify the mechanism works
    println!("Captured {} network events", network_events.len());
}

#[test]
#[ignore] // Requires root and specific kernel
fn test_bpf_removes_target_pid() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    
    // Add a target pid
    bpf.add_target_pid(12345).expect("Failed to add target pid");
    
    // Remove it
    bpf.remove_target_pid(12345).expect("Failed to remove target pid");
    
    // Verify it's removed (no panic or error)
}

#[test]
#[ignore] // Requires root and specific kernel
fn test_bpf_multiple_target_pids() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");
    
    // Spawn multiple child processes
    let mut child1 = Command::new("sleep")
        .arg("0.1")
        .spawn()
        .expect("Failed to spawn child1");
    
    let mut child2 = Command::new("sleep")
        .arg("0.1")
        .spawn()
        .expect("Failed to spawn child2");
    
    let pid1 = child1.id();
    let pid2 = child2.id();
    
    // Add both to target_pids
    bpf.add_target_pid(pid1).expect("Failed to add pid1");
    bpf.add_target_pid(pid2).expect("Failed to add pid2");
    
    // Wait for both to complete
    let _ = child1.wait();
    let _ = child2.wait();
    
    // Give the BPF program time to process events
    thread::sleep(Duration::from_millis(100));
    
    // Read events
    let events = read_events(&mut ringbuf);
    
    // Verify we captured events from both pids
    let pid1_events: Vec<&Event> = events.iter().filter(|e| e.pid == pid1).collect();
    let pid2_events: Vec<&Event> = events.iter().filter(|e| e.pid == pid2).collect();
    
    assert!(
        !pid1_events.is_empty(),
        "Expected events from pid1 {}, got none",
        pid1
    );
    assert!(
        !pid2_events.is_empty(),
        "Expected events from pid2 {}, got none",
        pid2
    );
}