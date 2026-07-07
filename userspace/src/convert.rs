//! Translation from raw BPF-side [`EventT`] into wire-format [`pb::Event`].
//!
//! The BPF side emits a uniform flat ringbuffer record carrying all 30 event
//! types in one struct (`EventT`), dispatching on `r#type`. Here we translate
//! to the protobuf `oneof` surface.

use crate::pb::pb::event::Event as Oneof;
use crate::pb::pb::{
    AcceptEvent, BindEvent, BrkEvent, BpfEvent, CapsetEvent, ChrootEvent, EpollWaitEvent, Event,
    FutexEvent, FileCloseEvent, FileOpenEvent, FileReadEvent, FileWriteEvent,
    MmapEvent, MprotectEvent, MunmapEvent, NetworkAcceptEvent, NetworkConnectEvent,
    PivotRootEvent, PollEvent, ProcessEvent, PtraceEvent, RecvfromEvent, RenameEvent,
    SelectEvent, SendtoEvent, SetnsEvent, SyscallEvent, UnlinkatEvent, UnshareEvent,
    Wait4Event, SignalEvent, FileMetaEvent, IoctlEvent, FcntlEvent, LseekEvent,
    SocketEvent, SocketOptEvent,
};

use crate::bpf::types::{self as bpf, cstr, EventT};

/// Build a `pb::Event` from a raw BPF ring-buffer sample.
pub fn convert(e: &EventT) -> Event {
    let timestamp_ns = e.ts;
    let pid = e.tgid;
    let oneof = match e.r#type {
        bpf::EVENT_TYPE_SYSCALL => Oneof::Syscall(SyscallEvent {
            syscall_id: e.syscall.syscall_id,
        }),
        bpf::EVENT_TYPE_FILE_OPEN => Oneof::FileOpen(FileOpenEvent {
            filename: cstr(&e.file.filename).to_string(),
            flags: e.file.flags,
            fd: e.file.fd as u32,
        }),
        bpf::EVENT_TYPE_FILE_READ => Oneof::FileRead(FileReadEvent {
            fd: e.rw.fd,
            count: e.rw.count,
        }),
        bpf::EVENT_TYPE_FILE_WRITE => {
            // The BPF side captures up to 256 bytes of the write payload in
            // `rw.data`; emit only the bytes the kernel actually populated.
            let n = e
                .rw
                .count
                .min(usize::MAX as u64)
                .min(e.rw.data.len() as u64) as usize;
            Oneof::FileWrite(FileWriteEvent {
                fd: e.rw.fd,
                count: e.rw.count,
                data: e.rw.data[..n].to_vec(),
            })
        }
        bpf::EVENT_TYPE_FILE_CLOSE => Oneof::FileClose(FileCloseEvent { fd: e.close.fd }),
        bpf::EVENT_TYPE_NET_CONN => Oneof::NetworkConnect(NetworkConnectEvent {
            saddr: e.net.saddr,
            daddr: e.net.daddr,
            sport: e.net.sport as u32,
            dport: e.net.dport as u32,
            family: e.net.family as u32,
        }),
        bpf::EVENT_TYPE_NET_ACCEPT => Oneof::NetworkAccept(NetworkAcceptEvent {
            saddr: e.net.saddr,
            daddr: e.net.daddr,
            sport: e.net.sport as u32,
            dport: e.net.dport as u32,
            family: e.net.family as u32,
        }),
        bpf::EVENT_TYPE_PROCESS => {
            let args = (0..e.process.arg_count as usize)
                .take(6)
                .map(|i| cstr(&e.process.args[i]).to_string())
                .collect();
            Oneof::Process(ProcessEvent {
                is_exec: e.process.is_exec != 0,
                is_fork: e.process.is_fork != 0,
                is_exit: e.process.is_exit != 0,
                comm: cstr(&e.process.comm).to_string(),
                child_pid: e.process.child_pid,
                exit_code: e.process.exit_code,
                filename: cstr(&e.process.filename).to_string(),
                args,
            })
        }
        bpf::EVENT_TYPE_CHROOT => Oneof::Chroot(ChrootEvent {
            path: cstr(&e.isolate.path1).to_string(),
        }),
        bpf::EVENT_TYPE_PIVOT_ROOT => Oneof::PivotRoot(PivotRootEvent {
            new_root: cstr(&e.isolate.path1).to_string(),
            put_old: cstr(&e.isolate.path2).to_string(),
        }),
        bpf::EVENT_TYPE_SETNS => Oneof::Setns(SetnsEvent {
            fd: e.isolate.val1,
            nstype: e.isolate.val2,
        }),
        bpf::EVENT_TYPE_UNSHARE => Oneof::Unshare(UnshareEvent {
            flags: e.isolate.val1,
        }),
        bpf::EVENT_TYPE_WAIT4 => Oneof::Wait4(Wait4Event {
            pid: e.wait4.pid,
            options: e.wait4.options,
        }),
        bpf::EVENT_TYPE_MMAP => Oneof::Mmap(MmapEvent {
            addr: e.mmap.addr,
            len: e.mmap.len,
            prot: e.mmap.prot,
            flags: e.mmap.flags,
            fd: e.mmap.fd,
            offset: e.mmap.off,
        }),
        bpf::EVENT_TYPE_MUNMAP => Oneof::Munmap(MunmapEvent {
            addr: e.munmap.addr,
            len: e.munmap.len,
        }),
        bpf::EVENT_TYPE_MPROTECT => Oneof::Mprotect(MprotectEvent {
            start: e.mprotect.start,
            len: e.mprotect.len,
            prot: e.mprotect.prot,
        }),
        bpf::EVENT_TYPE_BRK => Oneof::Brk(BrkEvent { brk: e.brk.brk }),
        bpf::EVENT_TYPE_ACCEPT => Oneof::Accept(AcceptEvent { fd: e.accept.fd }),
        bpf::EVENT_TYPE_BIND => Oneof::Bind(BindEvent { fd: e.bind.fd }),
        bpf::EVENT_TYPE_SENDTO => Oneof::Sendto(SendtoEvent {
            fd: e.net_rw.fd,
            len: e.net_rw.len,
        }),
        bpf::EVENT_TYPE_RECVFROM => Oneof::Recvfrom(RecvfromEvent {
            fd: e.net_rw.fd,
            len: e.net_rw.len,
        }),
        bpf::EVENT_TYPE_UNLINKAT => Oneof::Unlinkat(UnlinkatEvent {
            dfd: e.unlinkat.dfd,
            pathname: cstr(&e.unlinkat.pathname).to_string(),
        }),
        bpf::EVENT_TYPE_RENAME => Oneof::Rename(RenameEvent {
            oldname: cstr(&e.rename.oldname).to_string(),
            newname: cstr(&e.rename.newname).to_string(),
        }),
        bpf::EVENT_TYPE_FUTEX => Oneof::Futex(FutexEvent {
            uaddr: e.futex.uaddr,
            op: e.futex.op,
            val: e.futex.val,
        }),
        bpf::EVENT_TYPE_EPOLL_WAIT => Oneof::EpollWait(EpollWaitEvent {
            epfd: e.epoll_wait.epfd,
            maxevents: e.epoll_wait.maxevents,
        }),
        bpf::EVENT_TYPE_SELECT => Oneof::Select(SelectEvent {
            nfds: e.select_poll.nfds,
        }),
        bpf::EVENT_TYPE_POLL => Oneof::Poll(PollEvent {
            nfds: e.select_poll.nfds,
        }),
        bpf::EVENT_TYPE_PTRACE => Oneof::Ptrace(PtraceEvent {
            request: e.ptrace.request,
            target_pid: e.ptrace.target_pid,
        }),
        bpf::EVENT_TYPE_BPF => Oneof::Bpf(BpfEvent { cmd: e.bpf.cmd }),
        bpf::EVENT_TYPE_CAPSET => Oneof::Capset(CapsetEvent {
            target_pid: e.capset.target_pid,
        }),
        bpf::EVENT_TYPE_SIGNAL => Oneof::Signal(SignalEvent {
            target_pid: e.signal.target_pid,
            target_tid: e.signal.target_tid,
            sig: e.signal.sig,
        }),
        bpf::EVENT_TYPE_FILE_META => Oneof::FileMeta(FileMetaEvent {
            pathname: cstr(&e.file_meta.pathname).to_string(),
            fd: e.file_meta.fd as i32,
            mode: e.file_meta.mode,
        }),
        bpf::EVENT_TYPE_IOCTL => Oneof::Ioctl(IoctlEvent {
            fd: e.ioctl_fcntl.fd,
            cmd: e.ioctl_fcntl.cmd,
        }),
        bpf::EVENT_TYPE_FCNTL => Oneof::Fcntl(FcntlEvent {
            fd: e.ioctl_fcntl.fd,
            cmd: e.ioctl_fcntl.cmd as i32,
        }),
        bpf::EVENT_TYPE_LSEEK => Oneof::Lseek(LseekEvent {
            fd: e.lseek.fd,
            offset: e.lseek.offset,
            whence: e.lseek.whence,
        }),
        bpf::EVENT_TYPE_SOCKET => Oneof::Socket(SocketEvent {
            family: e.socket.family,
            r#type: e.socket.type_,
            protocol: e.socket.protocol,
        }),
        bpf::EVENT_TYPE_SOCKOPT => Oneof::SocketOpt(SocketOptEvent {
            fd: e.sockopt.fd,
            level: e.sockopt.level,
            optname: e.sockopt.optname,
        }),

        // The BPF program doesn't emit LimitChanged; cgroup limit
        // changes are surfaced to the UI via the periodic scanner (which
        // reads the cgroup_tree_cache, refreshed every 10s) through the
        // ListProcesses/GetProcessMetadata RPCs. We therefore never emit a
        // LimitChangedEvent on the stream. Unknown event type ⇒ emit a
        // no-op Syscall event with syscall_id 0 so the client can still see
        // the timestamp/pid pair, accounting for forward-compat.
        unknown => {
            tracing::warn!(event_type = unknown, "unknown BPF event type");
            Oneof::Syscall(SyscallEvent { syscall_id: 0 })
        }
    };

    Event {
        timestamp_ns,
        pid,
        event: Some(oneof),
    }
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::types as bpf;

    /// Build an EventT with all fields zeroed, then set the common header
    /// (pid, type, ts). Tests call this and then fill the relevant payload
    /// sub-struct before passing it to `convert()`.
    fn make_event(pid: u32, ty: u32, ts: u64) -> bpf::EventT {
        let mut e = bpf::EventT {
            pid,
            tgid: pid,
            r#type: ty,
            ts,
            ..bpf::EventT::default_via_zeroed()
        };
        // Explicitly set header — default_via_zeroed already does this, but
        // we set here too so the helper is robust to impl changes.
        e.pid = pid;
        e.tgid = pid;
        e.r#type = ty;
        e.ts = ts;
        e
    }

    /// Tiny helper trait to make EventT::zeroed() available without depending
    /// on bytemuck on every test (we just want a fully-zeroed record).
    trait Zeroed {
        fn default_via_zeroed() -> Self;
    }
    impl Zeroed for bpf::EventT {
        fn default_via_zeroed() -> Self {
            // SAFETY: EventT contains plain scalar fields (u32, u64, i32, etc.)
            // and fixed-size byte arrays; all of those are valid as all-zero
            // bit patterns. No enums or nonzero markers.
            unsafe { std::mem::zeroed() }
        }
    }

    // ---- common header propagation tests ----------------------------

    #[test]
    fn convert_propagates_pid_and_timestamp() {
        let ev = make_event(4242, bpf::EVENT_TYPE_FILE_OPEN, 1_000_000);
        let pb = convert(&ev);
        assert_eq!(pb.pid, 4242);
        assert_eq!(pb.timestamp_ns, 1_000_000);
    }

    // ---- one case per event type (all 30) --------------------------

    #[test]
    fn event_type_syscall_converts_to_syscall_oneof() {
        let mut e = make_event(1, bpf::EVENT_TYPE_SYSCALL, 10);
        e.syscall.syscall_id = 42;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Syscall(s) => assert_eq!(s.syscall_id, 42),
            other => panic!("expected Syscall, got {other:?}"),
        }
    }

    #[test]
    fn event_type_file_open_includes_filename_and_flags() {
        let mut e = make_event(2, bpf::EVENT_TYPE_FILE_OPEN, 11);
        write_cstr(&mut e.file.filename, b"/etc/passwd");
        e.file.flags = 0;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::FileOpen(s) => {
                assert_eq!(s.filename, "/etc/passwd");
                assert_eq!(s.flags, 0);
            }
            other => panic!("expected FileOpen, got {other:?}"),
        }
    }

    #[test]
    fn event_type_file_read_carries_fd_and_count() {
        let mut e = make_event(3, bpf::EVENT_TYPE_FILE_READ, 12);
        e.rw.fd = 7;
        e.rw.count = 4096;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::FileRead(s) => {
                assert_eq!(s.fd, 7);
                assert_eq!(s.count, 4096);
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    #[test]
    fn event_type_file_write_clamps_data_bytes_to_count() {
        let mut e = make_event(4, bpf::EVENT_TYPE_FILE_WRITE, 13);
        e.rw.fd = 9;
        e.rw.count = 5;
        for (i, b) in b"hello world".iter().enumerate() {
            e.rw.data[i] = *b;
        }
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::FileWrite(s) => {
                assert_eq!(s.fd, 9);
                assert_eq!(s.count, 5);
                assert_eq!(s.data, b"hello");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn event_type_file_write_with_zero_count_emits_empty_data() {
        let mut e = make_event(5, bpf::EVENT_TYPE_FILE_WRITE, 14);
        e.rw.fd = 1;
        e.rw.count = 0;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::FileWrite(s) => assert_eq!(s.data.len(), 0),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn event_type_file_close_carries_fd() {
        let mut e = make_event(6, bpf::EVENT_TYPE_FILE_CLOSE, 15);
        e.close.fd = 3;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::FileClose(s) => assert_eq!(s.fd, 3),
            other => panic!("expected FileClose, got {other:?}"),
        }
    }

    #[test]
    fn event_type_net_conn_fields() {
        let mut e = make_event(7, bpf::EVENT_TYPE_NET_CONN, 16);
        e.net.saddr = 0x01020304;
        e.net.daddr = 0x05060708;
        e.net.sport = 5000;
        e.net.dport = 80;
        e.net.family = 2;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::NetworkConnect(s) => {
                assert_eq!(s.saddr, 0x01020304);
                assert_eq!(s.daddr, 0x05060708);
                assert_eq!(s.sport, 5000);
                assert_eq!(s.dport, 80);
                assert_eq!(s.family, 2);
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn event_type_net_accept_carries_same_payload_as_connect() {
        let mut e = make_event(8, bpf::EVENT_TYPE_NET_ACCEPT, 17);
        e.net.saddr = 1;
        e.net.daddr = 2;
        e.net.sport = 22;
        e.net.dport = 33;
        e.net.family = 2;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::NetworkAccept(s) => {
                assert_eq!(s.sport, 22);
                assert_eq!(s.dport, 33);
            }
            other => panic!("expected NetworkAccept, got {other:?}"),
        }
    }

    #[test]
    fn event_type_process_exec_carries_flags_comm_filename_and_args() {
        let mut e = make_event(9, bpf::EVENT_TYPE_PROCESS, 18);
        e.process.is_exec = 1;
        e.process.is_fork = 0;
        e.process.is_exit = 0;
        e.process.arg_count = 2;
        write_cstr(&mut e.process.comm, b"sleep");
        write_cstr(&mut e.process.filename, b"/bin/sleep");
        write_cstr(&mut e.process.args[0], b"sleep");
        write_cstr(&mut e.process.args[1], b"60");
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Process(p) => {
                assert!(p.is_exec);
                assert!(!p.is_fork);
                assert!(!p.is_exit);
                assert_eq!(p.comm, "sleep");
                assert_eq!(p.filename, "/bin/sleep");
                assert_eq!(p.args, vec!["sleep".to_string(), "60".to_string()]);
            }
            other => panic!("expected Process, got {other:?}"),
        }
    }

    #[test]
    fn event_type_process_exit_only_emits_exit_flag() {
        let mut e = make_event(10, bpf::EVENT_TYPE_PROCESS, 19);
        e.process.is_exit = 1;
        e.process.exit_code = 7;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Process(p) => {
                assert!(p.is_exit);
                assert!(!p.is_exec);
                assert!(!p.is_fork);
                assert_eq!(p.exit_code, 7);
            }
            other => panic!("expected Process, got {other:?}"),
        }
    }

    #[test]
    fn event_type_process_fork_includes_child_pid() {
        let mut e = make_event(11, bpf::EVENT_TYPE_PROCESS, 20);
        e.process.is_fork = 1;
        e.process.child_pid = 9999;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Process(p) => {
                assert!(p.is_fork);
                assert_eq!(p.child_pid, 9999);
            }
            other => panic!("expected Process, got {other:?}"),
        }
    }

    #[test]
    fn event_type_process_arg_count_clamps_to_six_args() {
        let mut e = make_event(12, bpf::EVENT_TYPE_PROCESS, 21);
        e.process.arg_count = 10; // clip to 6 actually present in args[] buffer
        for i in 0..6 {
            write_cstr(&mut e.process.args[i], format!("arg{i}").as_bytes());
        }
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Process(p) => assert_eq!(p.args.len(), 6),
            other => panic!("expected Process, got {other:?}"),
        }
    }

    #[test]
    fn event_type_process_arg_count_zero_emits_no_args() {
        let mut e = make_event(13, bpf::EVENT_TYPE_PROCESS, 22);
        e.process.arg_count = 0;
        write_cstr(&mut e.process.args[0], b"should-not-appear");
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Process(p) => assert!(p.args.is_empty()),
            other => panic!("expected Process, got {other:?}"),
        }
    }

    #[test]
    fn event_type_chroot_uses_path1() {
        let mut e = make_event(14, bpf::EVENT_TYPE_CHROOT, 23);
        write_cstr(&mut e.isolate.path1, b"/newroot");
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Chroot(c) => assert_eq!(c.path, "/newroot"),
            other => panic!("expected Chroot, got {other:?}"),
        }
    }

    #[test]
    fn event_type_pivot_root_uses_path1_and_path2() {
        let mut e = make_event(15, bpf::EVENT_TYPE_PIVOT_ROOT, 24);
        write_cstr(&mut e.isolate.path1, b"/newroot");
        write_cstr(&mut e.isolate.path2, b"/oldroot");
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::PivotRoot(p) => {
                assert_eq!(p.new_root, "/newroot");
                assert_eq!(p.put_old, "/oldroot");
            }
            other => panic!("expected PivotRoot, got {other:?}"),
        }
    }

    #[test]
    fn event_type_setns_uses_val1_and_val2() {
        let mut e = make_event(16, bpf::EVENT_TYPE_SETNS, 25);
        e.isolate.val1 = 7;
        e.isolate.val2 = 0x40000;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Setns(s) => {
                assert_eq!(s.fd, 7);
                assert_eq!(s.nstype, 0x40000);
            }
            other => panic!("expected Setns, got {other:?}"),
        }
    }

    #[test]
    fn event_type_unshare_uses_val1_as_flags() {
        let mut e = make_event(17, bpf::EVENT_TYPE_UNSHARE, 26);
        e.isolate.val1 = 0x68030000;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Unshare(u) => assert_eq!(u.flags, 0x68030000),
            other => panic!("expected Unshare, got {other:?}"),
        }
    }

    #[test]
    fn event_type_wait4_pid_and_options() {
        let mut e = make_event(18, bpf::EVENT_TYPE_WAIT4, 27);
        e.wait4.pid = 1234;
        e.wait4.options = 1;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Wait4(w) => {
                assert_eq!(w.pid, 1234);
                assert_eq!(w.options, 1);
            }
            other => panic!("expected Wait4, got {other:?}"),
        }
    }

    #[test]
    fn event_type_mmap_all_six_fields() {
        let mut e = make_event(19, bpf::EVENT_TYPE_MMAP, 28);
        e.mmap.addr = 0xdeadbeef;
        e.mmap.len = 4096;
        e.mmap.prot = 1;
        e.mmap.flags = 2;
        e.mmap.fd = 3;
        e.mmap.off = 0x1000;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Mmap(m) => {
                assert_eq!(m.addr, 0xdeadbeef);
                assert_eq!(m.len, 4096);
                assert_eq!(m.prot, 1);
                assert_eq!(m.flags, 2);
                assert_eq!(m.fd, 3);
                assert_eq!(m.offset, 0x1000);
            }
            other => panic!("expected Mmap, got {other:?}"),
        }
    }

    #[test]
    fn event_type_munmap_addr_and_len() {
        let mut e = make_event(20, bpf::EVENT_TYPE_MUNMAP, 29);
        e.munmap.addr = 0xabcd;
        e.munmap.len = 100;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Munmap(m) => {
                assert_eq!(m.addr, 0xabcd);
                assert_eq!(m.len, 100);
            }
            other => panic!("expected Munmap, got {other:?}"),
        }
    }

    #[test]
    fn event_type_mprotect_start_len_prot() {
        let mut e = make_event(21, bpf::EVENT_TYPE_MPROTECT, 30);
        e.mprotect.start = 0x600000;
        e.mprotect.len = 8192;
        e.mprotect.prot = 5;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Mprotect(m) => {
                assert_eq!(m.start, 0x600000);
                assert_eq!(m.len, 8192);
                assert_eq!(m.prot, 5);
            }
            other => panic!("expected Mprotect, got {other:?}"),
        }
    }

    #[test]
    fn event_type_brk_value() {
        let mut e = make_event(22, bpf::EVENT_TYPE_BRK, 31);
        e.brk.brk = 0x123456;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Brk(b) => assert_eq!(b.brk, 0x123456),
            other => panic!("expected Brk, got {other:?}"),
        }
    }

    #[test]
    fn event_type_accept_fd() {
        let mut e = make_event(23, bpf::EVENT_TYPE_ACCEPT, 32);
        e.accept.fd = -1; // error return - commonly seen
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Accept(a) => assert_eq!(a.fd, -1),
            other => panic!("expected Accept, got {other:?}"),
        }
    }

    #[test]
    fn event_type_bind_fd() {
        let mut e = make_event(24, bpf::EVENT_TYPE_BIND, 33);
        e.bind.fd = 4;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Bind(b) => assert_eq!(b.fd, 4),
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[test]
    fn event_type_sendto_fd_and_len() {
        let mut e = make_event(25, bpf::EVENT_TYPE_SENDTO, 34);
        e.net_rw.fd = 7;
        e.net_rw.len = 1234;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Sendto(s) => {
                assert_eq!(s.fd, 7);
                assert_eq!(s.len, 1234);
            }
            other => panic!("expected Sendto, got {other:?}"),
        }
    }

    #[test]
    fn event_type_recvfrom_fd_and_len() {
        let mut e = make_event(26, bpf::EVENT_TYPE_RECVFROM, 35);
        e.net_rw.fd = 8;
        e.net_rw.len = 5678;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Recvfrom(r) => {
                assert_eq!(r.fd, 8);
                assert_eq!(r.len, 5678);
            }
            other => panic!("expected Recvfrom, got {other:?}"),
        }
    }

    #[test]
    fn event_type_unlinkat_dfd_and_pathname() {
        let mut e = make_event(27, bpf::EVENT_TYPE_UNLINKAT, 36);
        e.unlinkat.dfd = 100;
        write_cstr(&mut e.unlinkat.pathname, b"/tmp/foo");
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Unlinkat(u) => {
                assert_eq!(u.dfd, 100);
                assert_eq!(u.pathname, "/tmp/foo");
            }
            other => panic!("expected Unlinkat, got {other:?}"),
        }
    }

    #[test]
    fn event_type_rename_oldname_newname() {
        let mut e = make_event(28, bpf::EVENT_TYPE_RENAME, 37);
        write_cstr(&mut e.rename.oldname, b"/tmp/old");
        write_cstr(&mut e.rename.newname, b"/tmp/new");
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Rename(r) => {
                assert_eq!(r.oldname, "/tmp/old");
                assert_eq!(r.newname, "/tmp/new");
            }
            other => panic!("expected Rename, got {other:?}"),
        }
    }

    #[test]
    fn event_type_futex_uaddr_op_val() {
        let mut e = make_event(29, bpf::EVENT_TYPE_FUTEX, 38);
        e.futex.uaddr = 0x7000000;
        e.futex.op = 1;
        e.futex.val = 0;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Futex(f) => {
                assert_eq!(f.uaddr, 0x7000000);
                assert_eq!(f.op, 1);
                assert_eq!(f.val, 0);
            }
            other => panic!("expected Futex, got {other:?}"),
        }
    }

    #[test]
    fn event_type_epoll_wait_epfd_maxevents() {
        let mut e = make_event(30, bpf::EVENT_TYPE_EPOLL_WAIT, 39);
        e.epoll_wait.epfd = 10;
        e.epoll_wait.maxevents = 64;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::EpollWait(w) => {
                assert_eq!(w.epfd, 10);
                assert_eq!(w.maxevents, 64);
            }
            other => panic!("expected EpollWait, got {other:?}"),
        }
    }

    #[test]
    fn event_type_select_nfds() {
        let mut e = make_event(31, bpf::EVENT_TYPE_SELECT, 40);
        e.select_poll.nfds = 7;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Select(s) => assert_eq!(s.nfds, 7),
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn event_type_poll_nfds() {
        let mut e = make_event(32, bpf::EVENT_TYPE_POLL, 41);
        e.select_poll.nfds = 1024;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Poll(p) => assert_eq!(p.nfds, 1024),
            other => panic!("expected Poll, got {other:?}"),
        }
    }

    #[test]
    fn event_type_ptrace_request_and_target_pid() {
        let mut e = make_event(33, bpf::EVENT_TYPE_PTRACE, 42);
        e.ptrace.request = 16; // PTRACE_ATTACH
        e.ptrace.target_pid = 12345;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Ptrace(p) => {
                assert_eq!(p.request, 16);
                assert_eq!(p.target_pid, 12345);
            }
            other => panic!("expected Ptrace, got {other:?}"),
        }
    }

    #[test]
    fn event_type_bpf_cmd() {
        let mut e = make_event(34, bpf::EVENT_TYPE_BPF, 43);
        e.bpf.cmd = 5; // BPF_PROG_LOAD
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Bpf(b) => assert_eq!(b.cmd, 5),
            other => panic!("expected Bpf, got {other:?}"),
        }
    }

    #[test]
    fn event_type_capset_target_pid() {
        let mut e = make_event(35, bpf::EVENT_TYPE_CAPSET, 44);
        e.capset.target_pid = 99;
        let pb = convert(&e);
        match pb.event.unwrap() {
            Oneof::Capset(c) => assert_eq!(c.target_pid, 99),
            other => panic!("expected Capset, got {other:?}"),
        }
    }

    // ---- unknown event type handling --------------------------------

    #[test]
    fn unknown_event_type_falls_back_to_syscall_id_zero() {
        let ev = make_event(36, 9999, 45); // 9999 not in the 1-30 range
        let pb = convert(&ev);
        match pb.event.unwrap() {
            Oneof::Syscall(s) => assert_eq!(s.syscall_id, 0),
            other => panic!("expected fallback Syscall, got {other:?}"),
        }
    }

    #[test]
    fn event_type_zero_falls_back_to_syscall() {
        let ev = make_event(37, 0, 46);
        let pb = convert(&ev);
        assert!(matches!(pb.event.unwrap(), Oneof::Syscall(_)));
    }

    /// Helper: write `src` (with trailing NUL terminator implicitly added by
    /// the caller-provided slice) into a fixed-size `[u8; N]` C-string
    /// field. Bytes after `src.len()` are left as zero (which already matches
    /// EventT::default_via_zeroed()).
    fn write_cstr<const N: usize>(dst: &mut [u8; N], src: &[u8]) {
        assert!(src.len() < N, "src is {} bytes, dst is {}", src.len(), N);
        dst[..src.len()].copy_from_slice(src);
        // dst[src.len()] is already 0 from EventT::default_via_zeroed();
    }
}