// kernelspace/arm64/beemon.bpf.c
#define bpf_target_arm64
#include "vmlinux.h"



#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 1024

// Event Types
#define EVENT_TYPE_SYSCALL     1
#define EVENT_TYPE_FILE_OPEN   2
#define EVENT_TYPE_NET_CONN    3
#define EVENT_TYPE_PROCESS     4
#define EVENT_TYPE_FILE_READ   5
#define EVENT_TYPE_FILE_WRITE  6
#define EVENT_TYPE_FILE_CLOSE  7
#define EVENT_TYPE_CHROOT      8
#define EVENT_TYPE_PIVOT_ROOT  9
#define EVENT_TYPE_SETNS       10
#define EVENT_TYPE_UNSHARE     11
#define EVENT_TYPE_WAIT4       12
#define EVENT_TYPE_MMAP        13
#define EVENT_TYPE_MUNMAP      14
#define EVENT_TYPE_MPROTECT    15
#define EVENT_TYPE_BRK         16
#define EVENT_TYPE_ACCEPT      17
#define EVENT_TYPE_BIND        18
#define EVENT_TYPE_SENDTO      19
#define EVENT_TYPE_RECVFROM    20
#define EVENT_TYPE_UNLINKAT    21
#define EVENT_TYPE_RENAME      22
#define EVENT_TYPE_FUTEX       23
#define EVENT_TYPE_EPOLL_WAIT  24
#define EVENT_TYPE_SELECT      25
#define EVENT_TYPE_POLL        26
#define EVENT_TYPE_PTRACE      27
#define EVENT_TYPE_BPF         28
#define EVENT_TYPE_CAPSET      29
#define EVENT_TYPE_NET_ACCEPT  30

struct event_t {
    u32 pid;
    u32 tgid;
    u32 type;
    u64 ts;
    // Flattened union to make bpf2go generation trivial
    struct {
        u32 syscall_id;
    } syscall;
    struct {
        char filename[256];
        int flags;
    } file;
    struct {
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u16 family;
    } net;
    struct {
        u32 child_pid;
        int exit_code;
        char comm[16];
        u8 is_exit;
        u8 is_exec;
        u8 is_fork;
        u8 arg_count;
        char filename[256];
        char args[6][64];
    } process;
    struct {
        u32 fd;
        u64 count;
        char data[256];
    } rw;
    struct {
        u32 fd;
    } close;
    struct {
        char path1[256];
        char path2[256];
        u32 val1;
        int val2;
    } isolate;
    struct {
        u32 pid;
        int options;
    } wait4;
    struct {
        u64 addr;
        u64 len;
        int prot;
        int flags;
        int fd;
        u64 off;
    } mmap;
    struct {
        u64 addr;
        u64 len;
    } munmap;
    struct {
        u64 start;
        u64 len;
        int prot;
    } mprotect;
    struct {
        u64 brk;
    } brk;
    struct {
        int fd;
    } accept;
    struct {
        int fd;
    } bind;
    struct {
        int fd;
        u64 len;
    } net_rw;
    struct {
        int dfd;
        char pathname[256];
    } unlinkat;
    struct {
        char oldname[256];
        char newname[256];
    } rename;
    struct {
        u64 uaddr;
        int op;
        u32 val;
    } futex;
    struct {
        int epfd;
        int maxevents;
    } epoll_wait;
    struct {
        int nfds;
    } select_poll;
    struct {
        long request;
        u32 target_pid;
    } ptrace;
    struct {
        int cmd;
    } bpf;
    struct {
        u32 target_pid;
    } capset;
};

// Force BTF generation for event_t so bpf2go can generate the Go struct
struct event_t _event_t_force_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map for target PIDs to trace. Key: pid (or tgid), Value: u8 (1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} target_pids SEC(".maps");

static __always_inline bool should_trace(u32 pid) {
    u8 *val = bpf_map_lookup_elem(&target_pids, &pid);
    return val != NULL;
}

// -----------------------------------------------------------------------------
// IO STATS ACCOUNTING PROBES
// -----------------------------------------------------------------------------

struct io_stat {
    u64 file_read_bytes;
    u64 file_write_bytes;
    u64 net_rx_bytes;
    u64 net_tx_bytes;
};

// Force BTF generation
struct io_stat _io_stat_force_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct io_stat);
} process_io_stats SEC(".maps");

struct net_flow_key {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    u16 protocol;
};

struct net_flow_stat {
    u64 rx_bytes;
    u64 tx_bytes;
    u64 rx_packets;
    u64 tx_packets;
    char dns_query[256];
};

struct net_flow_key _net_flow_key_force_btf __attribute__((unused));
struct net_flow_stat _net_flow_stat_force_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES * 10);
    __type(key, struct net_flow_key);
    __type(value, struct net_flow_stat);
} process_net_flow_stats SEC(".maps");

// For udp_recvmsg to pass sk between kprobe and kretprobe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32); // tid
    __type(value, struct sock *);
} udp_recv_sk SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32); // tid
    __type(value, struct msghdr *);
} udp_recv_msg SEC(".maps");

static __always_inline void add_net_io(struct sock *sk, u32 pid, u64 rx, u64 tx, struct msghdr *msg, u16 protocol) {
    if (pid == 0 || !sk) return;
    
    struct net_flow_key key = {};
    key.pid = pid;
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&key.sport, sizeof(key.sport), &sk->__sk_common.skc_num);
    
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key.dport = bpf_ntohs(dport);
    
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    key.family = family;
    
    key.protocol = protocol;

    struct net_flow_stat *stat = bpf_map_lookup_elem(&process_net_flow_stats, &key);
    if (stat) {
        if (rx) {
            __sync_fetch_and_add(&stat->rx_bytes, rx);
            __sync_fetch_and_add(&stat->rx_packets, 1);
        }
        if (tx) {
            __sync_fetch_and_add(&stat->tx_bytes, tx);
            __sync_fetch_and_add(&stat->tx_packets, 1);
        }
    } else {
        struct net_flow_stat new_stat = {};
        new_stat.rx_bytes = rx;
        new_stat.tx_bytes = tx;
        if (rx) new_stat.rx_packets = 1;
        if (tx) new_stat.tx_packets = 1;
        
        // If this is DNS (port 53 UDP), grab payload
        if ((key.dport == 53 || key.sport == 53) && msg && tx > 0) {
            // DNS parse. We need msg->msg_iter.iov->iov_base
            // Just read up to 256 bytes from user buffer
            struct iov_iter iter = {};
            bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
            if (iter.iter_type == 0 /* ITER_IOVEC */) {
                struct iovec iov = {};
                bpf_probe_read_kernel(&iov, sizeof(iov), (void *)iter.__iov);
                if (iov.iov_base) {
                    bpf_probe_read_user(&new_stat.dns_query, sizeof(new_stat.dns_query), iov.iov_base);
                }
            }
        }
        bpf_map_update_elem(&process_net_flow_stats, &key, &new_stat, BPF_ANY);
    }
    
    // Also update the aggregate map
    struct io_stat *agg_stat = bpf_map_lookup_elem(&process_io_stats, &pid);
    if (agg_stat) {
        if (rx) __sync_fetch_and_add(&agg_stat->net_rx_bytes, rx);
        if (tx) __sync_fetch_and_add(&agg_stat->net_tx_bytes, tx);
    } else {
        struct io_stat new_agg = {};
        new_agg.net_rx_bytes = rx;
        new_agg.net_tx_bytes = tx;
        bpf_map_update_elem(&process_io_stats, &pid, &new_agg, BPF_ANY);
    }
}

static __always_inline void add_file_io(u32 pid, u64 read_bytes, u64 write_bytes) {
    if (pid == 0) return;
    struct io_stat *stat = bpf_map_lookup_elem(&process_io_stats, &pid);
    if (stat) {
        if (read_bytes) __sync_fetch_and_add(&stat->file_read_bytes, read_bytes);
        if (write_bytes) __sync_fetch_and_add(&stat->file_write_bytes, write_bytes);
    } else {
        struct io_stat new_stat = {};
        new_stat.file_read_bytes = read_bytes;
        new_stat.file_write_bytes = write_bytes;
        bpf_map_update_elem(&process_io_stats, &pid, &new_stat, BPF_ANY);
    }
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(trace_vfs_read_ret, ssize_t ret) {
    if (ret <= 0) return 0;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    add_file_io(tgid, ret, 0);
    return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(trace_vfs_write_ret, ssize_t ret) {
    if (ret <= 0) return 0;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    add_file_io(tgid, 0, ret);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    add_net_io(sk, tgid, 0, size, msg, IPPROTO_TCP);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    add_net_io(sk, tgid, copied, 0, NULL, IPPROTO_TCP);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    add_net_io(sk, tgid, 0, len, msg, IPPROTO_UDP);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_recv_sk, &tid, &sk, BPF_ANY);
    bpf_map_update_elem(&udp_recv_msg, &tid, &msg, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(trace_udp_recvmsg_ret, int ret) {
    if (ret <= 0) {
        u32 tid = (u32)bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&udp_recv_sk, &tid);
        bpf_map_delete_elem(&udp_recv_msg, &tid);
        return 0;
    }
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    u32 tgid = id >> 32;
    struct sock **skpp = bpf_map_lookup_elem(&udp_recv_sk, &tid);
    struct msghdr **msgpp = bpf_map_lookup_elem(&udp_recv_msg, &tid);
    if (skpp) {
        add_net_io(*skpp, tgid, ret, 0, msgpp ? *msgpp : NULL, IPPROTO_UDP);
    }
    bpf_map_delete_elem(&udp_recv_sk, &tid);
    bpf_map_delete_elem(&udp_recv_msg, &tid);
    return 0;
}



// -----------------------------------------------------------------------------
// PROCESS LIFECYCLE
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;
    
    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_PROCESS;
    e->ts = bpf_ktime_get_ns();
    e->process.is_exec = 1;
    e->process.is_fork = 0;
    e->process.is_exit = 0;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    
    // args[0] is const char *filename
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->process.filename, sizeof(e->process.filename), filename);

    // args[1] is const char *const *argv
    const char **argv = (const char **)ctx->args[1];
    e->process.arg_count = 0;
    if (argv) {
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            const char *argp = NULL;
            bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
            if (!argp) break;
            bpf_probe_read_user_str(&e->process.args[i], sizeof(e->process.args[i]), argp);
            e->process.arg_count++;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;
    
    if (should_trace(parent_pid)) {
        // Automatically add child to trace map
        u8 val = 1;
        bpf_map_update_elem(&target_pids, &child_pid, &val, BPF_ANY);

        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;
        
        e->pid = parent_pid;
        e->tgid = parent_pid;
        e->type = EVENT_TYPE_PROCESS;
        e->ts = bpf_ktime_get_ns();
        e->process.is_exec = 0;
        e->process.is_fork = 1;
        e->process.is_exit = 0;
        e->process.child_pid = child_pid;
        bpf_probe_read_kernel_str(&e->process.comm, sizeof(e->process.comm), (void *)ctx + (ctx->__data_loc_child_comm & 0xffff));
        
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (user_pid == user_tid) {
        bpf_map_delete_elem(&process_io_stats, &user_pid);
    }

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_PROCESS;
    e->ts = bpf_ktime_get_ns();
    e->process.is_exec = 0;
    e->process.is_fork = 0;
    e->process.is_exit = 1;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// FILE I/O (READ, WRITE, OPEN, CLOSE)
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_FILE_READ;
    e->ts = bpf_ktime_get_ns();
    e->rw.fd = (u32)ctx->args[0];
    e->rw.count = (u64)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_FILE_WRITE;
    e->ts = bpf_ktime_get_ns();
    e->rw.fd = (u32)ctx->args[0];
    e->rw.count = (u64)ctx->args[2];
    
    // Read up to 256 bytes of data
    const char *buf = (const char *)ctx->args[1];
    u64 bytes_to_read = e->rw.count;
    if (bytes_to_read > sizeof(e->rw.data)) {
        bytes_to_read = sizeof(e->rw.data);
    }
    bpf_probe_read_user(&e->rw.data, bytes_to_read, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_FILE_CLOSE;
    e->ts = bpf_ktime_get_ns();
    e->close.fd = (u32)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_FILE_OPEN;
    e->ts = bpf_ktime_get_ns();
    e->file.flags = (int)ctx->args[2];
    
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->file.filename, sizeof(e->file.filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// NETWORK
// -----------------------------------------------------------------------------

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_NET_CONN;
    e->ts = bpf_ktime_get_ns();
    e->net.family = 2; // AF_INET
    
    // Read from uaddr since sk fields aren't populated at the start of tcp_v4_connect
    struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &usin->sin_port);
    
    bpf_probe_read_kernel(&e->net.saddr, sizeof(e->net.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->net.daddr, sizeof(e->net.daddr), &usin->sin_addr.s_addr);
    bpf_probe_read_kernel(&e->net.sport, sizeof(e->net.sport), &sk->__sk_common.skc_num);
    e->net.dport = bpf_ntohs(dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    if (!newsk) return 0; // Accept failed or returned NULL

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_NET_ACCEPT;
    e->ts = bpf_ktime_get_ns();
    e->net.family = 2; // AF_INET (We only support IPv4 for now)

    // The new socket is fully populated with local and remote addresses
    bpf_probe_read_kernel(&e->net.saddr, sizeof(e->net.saddr), &newsk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->net.daddr, sizeof(e->net.daddr), &newsk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&e->net.sport, sizeof(e->net.sport), &newsk->__sk_common.skc_num);
    
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &newsk->__sk_common.skc_dport);
    e->net.dport = bpf_ntohs(dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// NAMESPACE & ISOLATION
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_chroot")
int trace_sys_enter_chroot(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_CHROOT;
    e->ts = bpf_ktime_get_ns();
    
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->isolate.path1, sizeof(e->isolate.path1), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int trace_sys_enter_pivot_root(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_PIVOT_ROOT;
    e->ts = bpf_ktime_get_ns();
    
    const char *new_root = (const char *)ctx->args[0];
    const char *put_old = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->isolate.path1, sizeof(e->isolate.path1), new_root);
    bpf_probe_read_user_str(&e->isolate.path2, sizeof(e->isolate.path2), put_old);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_sys_enter_setns(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_SETNS;
    e->ts = bpf_ktime_get_ns();
    
    e->isolate.val1 = (u32)ctx->args[0]; // fd
    e->isolate.val2 = (int)ctx->args[1]; // nstype

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_sys_enter_unshare(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 user_pid = id >> 32;
    u32 user_tid = (u32)id;

    if (!should_trace(user_pid)) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = user_tid;
    e->tgid = user_pid;
    e->type = EVENT_TYPE_UNSHARE;
    e->ts = bpf_ktime_get_ns();
    
    e->isolate.val1 = (u32)ctx->args[0]; // flags

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// EXTENDED SYSCALLS
// -----------------------------------------------------------------------------

#define NEW_EVENT(TYPE) \
    u64 id = bpf_get_current_pid_tgid(); \
    u32 user_pid = id >> 32; \
    u32 user_tid = (u32)id; \
    if (!should_trace(user_pid)) return 0; \
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); \
    if (!e) return 0; \
    e->pid = user_tid; \
    e->tgid = user_pid; \
    e->type = TYPE; \
    e->ts = bpf_ktime_get_ns();

// -----------------------------------------------------------------------------
// PROCESS / SCHEDULING
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_wait4")
int trace_sys_enter_wait4(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_WAIT4)
    e->wait4.pid = (u32)ctx->args[0];
    e->wait4.options = (int)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// MEMORY MANAGEMENT
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_MMAP)
    e->mmap.addr = (u64)ctx->args[0];
    e->mmap.len = (u64)ctx->args[1];
    e->mmap.prot = (int)ctx->args[2];
    e->mmap.flags = (int)ctx->args[3];
    e->mmap.fd = (int)ctx->args[4];
    e->mmap.off = (u64)ctx->args[5];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_sys_enter_munmap(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_MUNMAP)
    e->munmap.addr = (u64)ctx->args[0];
    e->munmap.len = (u64)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_MPROTECT)
    e->mprotect.start = (u64)ctx->args[0];
    e->mprotect.len = (u64)ctx->args[1];
    e->mprotect.prot = (int)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int trace_sys_enter_brk(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_BRK)
    e->brk.brk = (u64)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// NETWORKING (EXTENDED)
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_ACCEPT)
    e->accept.fd = (int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_ACCEPT)
    e->accept.fd = (int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_BIND)
    e->bind.fd = (int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_SENDTO)
    e->net_rw.fd = (int)ctx->args[0];
    e->net_rw.len = (u64)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_RECVFROM)
    e->net_rw.fd = (int)ctx->args[0];
    e->net_rw.len = (u64)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// FILE SYSTEM / VFS (EXTENDED)
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_UNLINKAT)
    e->unlinkat.dfd = (int)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->unlinkat.pathname, sizeof(e->unlinkat.pathname), pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_RENAME)
    const char *oldname = (const char *)ctx->args[0];
    const char *newname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->rename.oldname, sizeof(e->rename.oldname), oldname);
    bpf_probe_read_user_str(&e->rename.newname, sizeof(e->rename.newname), newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_RENAME)
    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];
    bpf_probe_read_user_str(&e->rename.oldname, sizeof(e->rename.oldname), oldname);
    bpf_probe_read_user_str(&e->rename.newname, sizeof(e->rename.newname), newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_RENAME)
    const char *oldname = (const char *)ctx->args[1];
    const char *newname = (const char *)ctx->args[3];
    bpf_probe_read_user_str(&e->rename.oldname, sizeof(e->rename.oldname), oldname);
    bpf_probe_read_user_str(&e->rename.newname, sizeof(e->rename.newname), newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// IPC / SYNCHRONIZATION
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_futex")
int trace_sys_enter_futex(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_FUTEX)
    e->futex.uaddr = (u64)ctx->args[0];
    e->futex.op = (int)ctx->args[1];
    e->futex.val = (u32)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int trace_sys_enter_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_EPOLL_WAIT)
    e->epoll_wait.epfd = (int)ctx->args[0];
    e->epoll_wait.maxevents = (int)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_select")
int trace_sys_enter_select(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_SELECT)
    e->select_poll.nfds = (int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int trace_sys_enter_poll(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_POLL)
    e->select_poll.nfds = (int)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// SECURITY / PERMISSIONS
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_PTRACE)
    e->ptrace.request = (long)ctx->args[0];
    e->ptrace.target_pid = (u32)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_sys_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_BPF)
    e->bpf.cmd = (int)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_sys_enter_capset(struct trace_event_raw_sys_enter *ctx) {
    NEW_EVENT(EVENT_TYPE_CAPSET)
    e->capset.target_pid = 0;
    void *header = (void *)ctx->args[0];
    if (header) {
        int target_pid = 0;
        bpf_probe_read_user(&target_pid, sizeof(target_pid), header + 4);
        e->capset.target_pid = (u32)target_pid;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}
