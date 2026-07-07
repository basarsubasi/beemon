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
    Wait4Event,
};

use crate::bpf::types::{self as bpf, cstr, EventT};

/// Build a `pb::Event` from a raw BPF ring-buffer sample.
pub fn convert(e: &EventT) -> Event {
    let timestamp_ns = e.ts;
    let pid = e.pid;
    let oneof = match e.r#type {
        bpf::EVENT_TYPE_SYSCALL => Oneof::Syscall(SyscallEvent {
            syscall_id: e.syscall.syscall_id,
        }),
        bpf::EVENT_TYPE_FILE_OPEN => Oneof::FileOpen(FileOpenEvent {
            filename: cstr(&e.file.filename).to_string(),
            flags: e.file.flags,
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