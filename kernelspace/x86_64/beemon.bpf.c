// kernelspace/x86_64/beemon.bpf.c
#define bpf_target_x86
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
        bpf_probe_read_kernel_str(&e->process.comm, sizeof(e->process.comm), ctx->child_comm);
        
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
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
