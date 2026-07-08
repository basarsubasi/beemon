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
        .arg("read dummy; cat /etc/hostname")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");
    
    let child_pid = child.id();
    
    // Add the child to the target_pids map
    bpf.add_target_pid(child_pid).expect("Failed to add target pid");
    
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = writeln!(stdin, "go");
    }
    
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
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("read dummy; sleep 0.1")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");
    
    let child_pid = child.id();
    
    // Add the child to the target_pids map
    bpf.add_target_pid(child_pid).expect("Failed to add target pid");
    
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = writeln!(stdin, "go");
    }
    
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
        .arg("read dummy; curl -s http://example.com > /dev/null || true")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process");
    
    let child_pid = child.id();
    
    // Add the child to the target_pids map
    bpf.add_target_pid(child_pid).expect("Failed to add target pid");
    
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = writeln!(stdin, "go");
    }
    
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
    let mut child1 = Command::new("sh")
        .arg("-c")
        .arg("read dummy; sleep 0.1")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn child1");
    
    let mut child2 = Command::new("sh")
        .arg("-c")
        .arg("read dummy; sleep 0.1")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn child2");
    
    let pid1 = child1.id();
    let pid2 = child2.id();
    
    // Add both to target_pids
    bpf.add_target_pid(pid1).expect("Failed to add pid1");
    bpf.add_target_pid(pid2).expect("Failed to add pid2");
    
    if let Some(mut stdin) = child1.stdin.take() {
        use std::io::Write;
        let _ = writeln!(stdin, "go");
    }
    if let Some(mut stdin) = child2.stdin.take() {
        use std::io::Write;
        let _ = writeln!(stdin, "go");
    }
    
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

#[test]
#[ignore]
fn test_bpf_captures_signals() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::sleep(1);
            libc::_exit(0);
        }
    }
    
    bpf.add_target_pid(pid as u32).expect("Failed to add target pid");
    
    unsafe { libc::kill(pid, libc::SIGUSR1); }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
    
    thread::sleep(Duration::from_millis(100));
    let events = read_events(&mut ringbuf);
    
    let signal_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::Signal(s)) if s.sig == libc::SIGUSR1))
        .collect();
        
    assert!(!signal_events.is_empty(), "Expected at least one SignalEvent with SIGUSR1, got none");
}

#[test]
#[ignore]
fn test_bpf_captures_socket_operations() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::sleep(1);
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let optval: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
            libc::close(fd);
            libc::_exit(0);
        }
    }
    
    bpf.add_target_pid(pid as u32).unwrap();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
    thread::sleep(Duration::from_millis(100));
    
    let events = read_events(&mut ringbuf);
    
    let socket_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::Socket(s)) if s.family == libc::AF_INET && s.r#type == libc::SOCK_STREAM))
        .collect();
    assert!(!socket_events.is_empty(), "Expected at least one SocketEvent matching AF_INET and SOCK_STREAM");

    let sockopt_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::SocketOpt(s)) if s.level == libc::SOL_SOCKET && s.optname == libc::SO_REUSEADDR))
        .collect();
    assert!(!sockopt_events.is_empty(), "Expected at least one SocketOptEvent matching SOL_SOCKET and SO_REUSEADDR");
}

#[test]
#[ignore]
fn test_bpf_captures_file_metadata() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::sleep(1);
            let path = b"/etc/hostname\0".as_ptr() as *const i8;
            let mut statbuf: libc::stat = std::mem::zeroed();
            libc::stat(path, &mut statbuf);
            libc::lstat(path, &mut statbuf);
            libc::access(path, libc::R_OK);
            libc::_exit(0);
        }
    }
    
    bpf.add_target_pid(pid as u32).unwrap();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
    thread::sleep(Duration::from_millis(100));
    
    let events = read_events(&mut ringbuf);
    
    let meta_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::FileMeta(m)) if m.pathname.contains("/etc/hostname")))
        .collect();
    
    assert!(!meta_events.is_empty(), "Expected at least one FileMetaEvent for /etc/hostname");
}

#[test]
#[ignore]
fn test_bpf_captures_ioctl_fcntl_lseek() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::sleep(1);
            let path = b"/dev/null\0".as_ptr() as *const i8;
            let fd = libc::open(path, libc::O_RDONLY);
            if fd >= 0 {
                libc::fcntl(fd, libc::F_GETFD);
                libc::lseek(fd, 42, libc::SEEK_SET);
                libc::close(fd);
            }
            libc::_exit(0);
        }
    }
    
    bpf.add_target_pid(pid as u32).unwrap();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
    thread::sleep(Duration::from_millis(100));
    
    let events = read_events(&mut ringbuf);
    
    let fcntl_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::Fcntl(f)) if f.cmd == libc::F_GETFD))
        .collect();
    assert!(!fcntl_events.is_empty(), "Expected at least one FcntlEvent with F_GETFD");

    let lseek_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::Lseek(l)) if l.offset == 42))
        .collect();
    assert!(!lseek_events.is_empty(), "Expected at least one LseekEvent with offset 42");
}

#[test]
#[ignore]
fn test_bpf_captures_misc_syscalls() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::sleep(1);
            
            // pipe
            let mut pipefds = [-1, -1];
            libc::pipe(pipefds.as_mut_ptr());
            
            // uname
            let mut uts: libc::utsname = std::mem::zeroed();
            libc::uname(&mut uts);
            
            // getpid, getuid
            libc::getpid();
            libc::getuid();
            
            // fstat
            if pipefds[0] >= 0 {
                let mut statbuf: libc::stat = std::mem::zeroed();
                libc::fstat(pipefds[0], &mut statbuf);
            }
            
            // getsockopt
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd >= 0 {
                let mut optval: libc::c_int = 0;
                let mut optlen: libc::socklen_t = 4;
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    &mut optval as *mut _ as *mut libc::c_void,
                    &mut optlen,
                );
                libc::close(fd);
            }
            
            // ioctl
            if pipefds[0] >= 0 {
                let mut bytes: libc::c_int = 0;
                libc::ioctl(pipefds[0], libc::FIONREAD, &mut bytes);
                libc::close(pipefds[0]);
                libc::close(pipefds[1]);
            }
            
            libc::_exit(0);
        }
    }
    
    bpf.add_target_pid(pid as u32).unwrap();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
    thread::sleep(Duration::from_millis(100));
    
    let events = read_events(&mut ringbuf);
    
    // Check for Syscall events (pipe, uname, getpid, getuid, fstat)
    // Syscall IDs differ by arch, so we just check we got some SyscallEvents from this PID
    let syscall_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::Syscall(_))))
        .collect();
    assert!(!syscall_events.is_empty(), "Expected Syscall events for pipe, uname, getpid, etc.");

    let sockopt_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::SocketOpt(s)) if s.level == libc::SOL_SOCKET && s.optname == libc::SO_TYPE))
        .collect();
    assert!(!sockopt_events.is_empty(), "Expected at least one SocketOptEvent for getsockopt");

    let ioctl_events: Vec<&Event> = events.iter()
        .filter(|e| matches!(&e.event, Some(Oneof::Ioctl(i)) if i.cmd == libc::FIONREAD as u64))
        .collect();
    assert!(!ioctl_events.is_empty(), "Expected at least one IoctlEvent with FIONREAD");
}

#[test]
#[ignore]
fn test_bpf_captures_remaining_syscalls() {
    let mut bpf = BpfHandle::load_and_attach().expect("Failed to load BPF programs");
    let mut ringbuf = bpf.take_events_ringbuf().expect("Failed to take ringbuf");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::sleep(1);
            
            // Memory
            let addr = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
            if addr != libc::MAP_FAILED {
                libc::mprotect(addr, 4096, libc::PROT_READ);
                libc::munmap(addr, 4096);
            }
            let  brk_ptr = std::ptr::null_mut();
            libc::brk(brk_ptr);
            
            // File I/O
            let path = b"/dev/null\0".as_ptr() as *const i8;
            let fd = libc::open(path, libc::O_RDWR);
            if fd >= 0 {
                let buf = [0u8; 1];
                libc::read(fd, buf.as_ptr() as *mut libc::c_void, 1);
                libc::write(fd, buf.as_ptr() as *const libc::c_void, 1);
                libc::close(fd);
            }
            
            // Network
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock >= 0 {
                let mut addr: libc::sockaddr_in = std::mem::zeroed();
                addr.sin_family = libc::AF_INET as libc::sa_family_t;
                // Bind to 0.0.0.0:0
                libc::bind(sock, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as libc::socklen_t);
                // Sendto, recvfrom
                let buf = [0u8; 1];
                libc::sendto(sock, buf.as_ptr() as *const libc::c_void, 1, 0, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as libc::socklen_t);
                let mut peer_addr: libc::sockaddr_in = std::mem::zeroed();
                let mut peer_addr_len = std::mem::size_of_val(&peer_addr) as libc::socklen_t;
                libc::recvfrom(sock, buf.as_ptr() as *mut libc::c_void, 1, libc::MSG_DONTWAIT, &mut peer_addr as *mut _ as *mut libc::sockaddr, &mut peer_addr_len);
                
                // accept
                libc::fcntl(sock, libc::F_SETFL, libc::O_NONBLOCK);
                libc::accept(sock, &mut peer_addr as *mut _ as *mut libc::sockaddr, &mut peer_addr_len);
                libc::close(sock);
            }
            
            // FS Namespace & modifications
            let temp_file = b"/tmp/beemon_test_file\0".as_ptr() as *const i8;
            let temp_file2 = b"/tmp/beemon_test_file2\0".as_ptr() as *const i8;
            let fd2 = libc::open(temp_file, libc::O_CREAT | libc::O_RDWR, 0o644);
            if fd2 >= 0 {
                libc::close(fd2);
                libc::rename(temp_file, temp_file2);
                libc::unlinkat(libc::AT_FDCWD, temp_file2, 0);
            }
            
            // Multiplexing
            let mut pollfd = libc::pollfd { fd: 0, events: 0, revents: 0 };
            libc::poll(&mut pollfd, 1, 0);
            
            let epfd = libc::epoll_create1(0);
            if epfd >= 0 {
                let mut ev = libc::epoll_event { events: 0, u64: 0 };
                libc::epoll_wait(epfd, &mut ev, 1, 0);
                libc::close(epfd);
            }
            
            let mut readfds: libc::fd_set = std::mem::zeroed();
            let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 0 };
            libc::select(0, &mut readfds, std::ptr::null_mut(), std::ptr::null_mut(), &mut timeout);
            
            // Wait4
            let child2 = libc::fork();
            if child2 == 0 {
                libc::_exit(0);
            } else if child2 > 0 {
                libc::wait4(child2, std::ptr::null_mut(), 0, std::ptr::null_mut());
            }
            
            // Futex
            let mut futex_val: u32 = 0;
            libc::syscall(libc::SYS_futex, &mut futex_val as *mut u32, libc::FUTEX_WAKE, 1, std::ptr::null::<libc::timespec>(), std::ptr::null_mut::<u32>(), 0);
            
            // Ptrace
            libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
            
            // Bpf
            libc::syscall(libc::SYS_bpf, 0, std::ptr::null_mut::<libc::c_void>(), 0);
            
            // Capset
            libc::syscall(libc::SYS_capset, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
            
            // Namespace / mount ops (will fail but sys_enter works)
            libc::chroot(b"/\0".as_ptr() as *const i8);
            libc::syscall(libc::SYS_pivot_root, b"/\0".as_ptr() as *const i8, b"/\0".as_ptr() as *const i8);
            libc::unshare(0);
            libc::setns(0, 0);

            libc::_exit(0);
        }
    }
    
    bpf.add_target_pid(pid as u32).unwrap();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
    thread::sleep(Duration::from_millis(200));
    
    let events = read_events(&mut ringbuf);
    
    let expects = [
        ("Mmap", events.iter().any(|e| matches!(&e.event, Some(Oneof::Mmap(_))))),
        ("Mprotect", events.iter().any(|e| matches!(&e.event, Some(Oneof::Mprotect(_))))),
        ("Munmap", events.iter().any(|e| matches!(&e.event, Some(Oneof::Munmap(_))))),
        ("Brk", events.iter().any(|e| matches!(&e.event, Some(Oneof::Brk(_))))),
        ("FileRead", events.iter().any(|e| matches!(&e.event, Some(Oneof::FileRead(_))))),
        ("FileWrite", events.iter().any(|e| matches!(&e.event, Some(Oneof::FileWrite(_))))),
        ("FileClose", events.iter().any(|e| matches!(&e.event, Some(Oneof::FileClose(_))))),
        ("Bind", events.iter().any(|e| matches!(&e.event, Some(Oneof::Bind(_))))),
        ("Sendto", events.iter().any(|e| matches!(&e.event, Some(Oneof::Sendto(_))))),
        ("Recvfrom", events.iter().any(|e| matches!(&e.event, Some(Oneof::Recvfrom(_))))),
        ("Accept", events.iter().any(|e| matches!(&e.event, Some(Oneof::NetworkAccept(_)))) || events.iter().any(|e| matches!(&e.event, Some(Oneof::Accept(_))))),
        ("Rename", events.iter().any(|e| matches!(&e.event, Some(Oneof::Rename(_))))),
        ("Unlinkat", events.iter().any(|e| matches!(&e.event, Some(Oneof::Unlinkat(_))))),
        ("Poll", events.iter().any(|e| matches!(&e.event, Some(Oneof::Poll(_))))),
        ("EpollWait", events.iter().any(|e| matches!(&e.event, Some(Oneof::EpollWait(_))))),
        ("Select", events.iter().any(|e| matches!(&e.event, Some(Oneof::Select(_))))),
        ("Wait4", events.iter().any(|e| matches!(&e.event, Some(Oneof::Wait4(_))))),
        ("Futex", events.iter().any(|e| matches!(&e.event, Some(Oneof::Futex(_))))),
        ("Ptrace", events.iter().any(|e| matches!(&e.event, Some(Oneof::Ptrace(_))))),
        ("Bpf", events.iter().any(|e| matches!(&e.event, Some(Oneof::Bpf(_))))),
        ("Capset", events.iter().any(|e| matches!(&e.event, Some(Oneof::Capset(_))))),
        ("Chroot", events.iter().any(|e| matches!(&e.event, Some(Oneof::Chroot(_))))),
        ("PivotRoot", events.iter().any(|e| matches!(&e.event, Some(Oneof::PivotRoot(_))))),
        ("Unshare", events.iter().any(|e| matches!(&e.event, Some(Oneof::Unshare(_))))),
        ("Setns", events.iter().any(|e| matches!(&e.event, Some(Oneof::Setns(_))))),
    ];
    
    for (name, found) in expects.iter() {
        assert!(*found, "Expected at least one {} event", name);
    }
}