# beemon

Beemon is a lightweight, real-time Linux process monitoring tool powered by eBPF.
It allows you to inspect running processes and monitor their low-level kernel activities—such as file I/O, network connections, process creation, and namespace isolation events—live from a web interface.



[<img width="1500" height="1500" alt="Image" src="https://github.com/user-attachments/assets/8cec8d38-7ecc-489a-88b5-27f33c43bcf7" />
](https://github.com/user-attachments/assets/0b27b0e8-e25a-44fe-a354-441fab42d49a)

## What it does

Beemon provides deep observability into Linux processes without requiring application-level instrumentation. It can capture:

- **Process Lifecycle:** Executions, forks, and exits (e.g., watching a container spawn processes).
- **File I/O:** Files being opened, read, written, and closed, including the actual bytes being written (up to 256 bytes per event).
- **Network Connections:** Outbound TCP IPv4 connections showing source and destination IPs and ports.
- **Namespaces & Isolation:** Events related to containerization such as `chroot`, `pivot_root`, `setns`, and `unshare`.
- **Resource Limits:** Real-time updates to cgroup v2 limits (memory, CPU, pids).

## How it works

The architecture is split into three main tiers:

### 1. Kernel Space (eBPF)
At its core, Beemon uses a highly efficient eBPF program written in C that hooks directly into Linux kernel tracepoints and kprobes. 
- When the UI requests to monitor a process, the daemon adds that PID to a `target_pids` eBPF map.
- The eBPF program hooks into critical kernel functions (like `sys_enter_read`, `sched_process_fork`, `tcp_v4_connect`), but only captures data if the triggering process is in the `target_pids` map. 
- Captured events are sent to userspace via a high-performance eBPF Ring Buffer.

### 2. Userspace Daemon & BFF (Go)
The backend consists of a privileged Go daemon and a Backend-For-Frontend (BFF):
- **Daemon (`beemon-daemon`):** Runs as root to load the eBPF program. It constantly reads the ring buffer, translates raw kernel C structs into Protobuf messages, and streams them over gRPC. It also reads `/proc` and `cgroup` data for static process information.
- **BFF (`beemon-bff`):** Acts as a bridge for the web UI. It exposes a REST API via grpc-gateway and handles WebSockets to bridge the gRPC event stream directly to the browser.

### 3. Web UI (React)
The frontend is a modern React application. It displays a dashboard of all running processes (fetched via REST) and allows you to click into any process. Once selected, it opens a WebSocket connection to stream and display the kernel events in real-time.

## Cross-Architecture Support
Beemon is designed to run on both **x86_64** and **arm64** (e.g., Raspberry Pi) architectures. It uses architecture-specific `vmlinux.h` headers and `bpf2go` to compile the correct eBPF bytecode for the target platform.

> [!WARNING]
> **Not CO-RE Compatible:** This project does **not** use CO-RE (Compile Once - Run Everywhere) relocations because the target environments lack BTF debug information (`/sys/kernel/btf/vmlinux`). 
> The struct offsets are hardcoded at compile time. This specific build is designed exactly for **6.18 arm64** and **6.12 amd64** Linux kernels. Running it on different kernel versions may cause it to fail to load or read incorrect data unless you generate a new `vmlinux.h` for your kernel and recompile.

## Directory Structure

```text
.
├── Makefile                # Build orchestration
├── docker-compose.yaml     # Docker deployment config
├── kernelspace/            # eBPF C programs and kernel headers
│   ├── arm64/              # Raspberry Pi/ARM64 specific eBPF and vmlinux.h
│   └── x86_64/             # Intel/AMD64 specific eBPF and vmlinux.h
├── protobuf/               # gRPC & Protocol Buffer definitions
│   └── api/v1/beemon.proto # API contract between Daemon and BFF
├── userspace/              # beemon-daemon (Go)
│   ├── main.go             # Daemon entry point
│   ├── link.go             # eBPF loader and ringbuffer reader
│   ├── event.go            # Event dispatcher and gRPC server
│   └── snapshot.go         # /proc process and cgroup limits reader
└── webui/                  # Frontend stack
    ├── bff/                # Backend-for-Frontend (Go, REST proxy + WebSockets)
    └── ui/                 # React SPA (TypeScript, Vite, Tailwind)
```

## Quick Start

You can run the entire stack locally for development using Make:

```bash
# Build eBPF programs, Protobufs, and Go binaries, then start the stack
make dev
```

Alternatively, you can run the stack using Docker Compose:

```bash
docker-compose up --build
```

The UI will be available at `http://localhost:3000` (or `http://localhost:5173` via Vite in dev mode), and the Swagger API docs at `http://localhost:8080/swagger/`.
