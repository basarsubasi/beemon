# beemon

Beemon is a lightweight, real-time Linux process monitoring tool powered by eBPF.
It inspects running processes and monitors their low-level kernel activities, file I/O, network connections, process creation, namespace isolation events, and cgroup resource limits, all from a single self-contained binary.



https://github.com/user-attachments/assets/872b7cef-b015-40c7-a1d5-570fcecae52f

## Features

- **Process Lifecycle:** Executions, forks, and exits with parent-child tracking.
- **File I/O Accounting:** Reads, writes, scatter-gather I/O (`readv`/`writev`), and zero-copy file copies (`copy_file_range`), aggregated as per-second rates.
- **Network Connections:** TCP and UDP flows with source/destination IPs, ports, and byte counters.
- **Namespace & Isolation Events:** `chroot`, `pivot_root`, `setns`, `unshare`, and namespace tree visualization.
- **Cgroup Resource Limits:** Real-time memory, CPU quota, and PID limits from cgroup v2.
- **Memory & CPU Monitoring:** Per-process RSS memory, CPU percentage, and host-wide core utilization.
- **Process Manager Detection:** Identifies systemd, containerd, dockerd, podman, and crio managed processes.
- **Live Event Streaming:** SSE and WebSocket streams for real-time kernel event monitoring per process.

1. **eBPF Programs (C):** Hook kernel tracepoints and kprobes. Events flow through a ring buffer; I/O and network stats accumulate in LRU hash maps. CO-RE enabled via `preserve_access_index`.
2. **Userspace (Rust):** Reads the ring buffer, translates raw C structs into typed events, polls BPF maps for rate computation, scans `/proc` for process metadata, and serves everything over HTTP.
3. **Web UI (React):** Embedded at compile time via `rust-embed`. Dashboard shows all processes with CPU, memory, I/O, and network stats. Click into any process for live kernel event streaming.

## Cross-Architecture Support

Beemon supports both **x86_64** and **arm64**. Each architecture has its own BPF C source and `vmlinux.h` header. The correct binary is selected at compile time.

> [!NOTE]
> **CO-RE Compatible:** Beemon uses CO-RE relocations (`preserve_access_index`) so the same BPF bytecode can run across different kernel versions without regenerating `vmlinux.h`, as long as the kernel has BTF enabled.

## Quick Start

### Build and run

```bash
make build
sudo ./bin/beemon
```

The UI is available at `http://localhost:5055`.


This builds everything and runs the binary in the foreground on port 5055.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `BEEMON_WEBUI_PORT` | `5055` | HTTP listen port |
| `BEEMON_LOG_LEVEL` | `warn` | Tracing log filter (e.g., `info`, `debug`, `beemon=debug`) |
| `BEEMON_EVENT_LIMIT` | `5000` | Max events per batch |
| `BEEMON_RATES_POLL_MILLIS` | `2000` | BPF map poll interval for rate computation |
| `BEEMON_SCANNER_PERIOD_SECS` | `1` | `/proc` scan interval in seconds |

Example:

```bash
sudo BEEMON_WEBUI_PORT=8080 BEEMON_LOG_LEVEL=info ./bin/beemon
```

## Requirements

- Linux with eBPF support (kernel 5.8+)
- Root privileges (or `CAP_BPF` + `CAP_SYS_ADMIN`)
- BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`) for CO-RE
- Targets: x86_64, aarch64

## Dependencies for building

- Rust nightly toolchain
- `clang` / `llvm` (for BPF compilation)
- Node.js + npm (for UI build)
