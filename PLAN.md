# Goal Description

The goal is to build a high-performance process monitor named **beemon**. The monitor will capture comprehensive data about processes, including:
- Namespaces
- Resource usage
- Cgroup limits
- Syscalls made
- Open files
- Open ports and network connections
- Process state
- Subprocesses

The user will be able to view and filter a list of active processes from the Web UI, and select a specific process to monitor in depth.

The architecture is divided into the following layers:
1. **Kernelspace (`kernelspace/`)**: eBPF programs written in C to capture real-time events. We will use kernel-specific `vmlinux.h` (non-CO-RE) generated via `bpftool` for the current kernel.
2. **Userspace (`userspace/`)**: A Go-based daemon that takes initial state snapshots from the `/proc` filesystem, loads and attaches the eBPF programs, and aggregates real-time events.
3. **Protobuf (`protobuf/`)**: We will use `buf` (`npx buf`) to manage our protocol buffers. We will utilize the `grpc-gateway` plugin for REST API translation, `protovalidate` for request validation, and `generate-go-embed4assets` for serving swagger/assets.
4. **BFF (`webui/bff/`)**: A Backend-For-Frontend service written in Go. It will serve the UI and Swagger UI, and communicate with the `userspace` daemon via gRPC (or act as a gateway).
5. **UI (`webui/ui/`)**: A Vite-powered React and TypeScript frontend using  CSS and shadcn/ui components.

## Proposed Architecture & Changes

### Protobuf (`protobuf/`)
We will use `npx buf` to manage the schema.
- **Plugins**: `go`, `go-grpc`, `grpc-gateway`, `protovalidate`, `openapiv2` (for swagger), and `generate-go-embed4assets` (for embedding assets/swagger).
- **Validation**: Define validation rules using `protovalidate` annotations in the `.proto` files to reject invalid requests (e.g., negative PIDs) before they hit the Go handlers.
- **Endpoints**:
  - `ListProcesses(ProcessFilter) returns (ProcessList)`
  - `StreamProcessEvents(ProcessRequest) returns (stream Event)`

### Kernelspace (eBPF)
eBPF programs (kprobes/tracepoints/kretprobes) to stream events into ringbuffers.
- **Syscalls**: Tracepoints on `raw_syscalls`.
- **Files**: Kprobes on `do_sys_openat2`, `filp_close`.
- **Network**: Kprobes on TCP/UDP send/recv.
- **Subprocesses**: Tracepoints on `sched_process_exec`, `sched_process_exit`.

#### [NEW] `kernelspace/vmlinux.h`
Generated via `bpftool vmlinux > vmlinux.h`.

#### [NEW] `kernelspace/beemon.bpf.c`
The eBPF C program containing ringbuffers and hook implementations.

### Userspace (Go Daemon)
A Go application that uses `cilium/ebpf` (via `bpf2go`) to compile and load the eBPF code.
Provides a gRPC server for the BFF.

#### [NEW] `userspace/main.go`
Entry point for the daemon, setting up the gRPC server and eBPF lifecycle.

#### [NEW] `userspace/snapshot/proc.go`
Functions to parse `/proc` for listing processes and getting initial state (namespaces, cgroups, etc.).

#### [NEW] `userspace/ebpf/manager.go`
Manages the ringbuffer polling from the eBPF programs.

### Web UI & BFF

#### [NEW] `webui/bff/`
A Go BFF application. It will act as the grpc-gateway, validating requests (using `protovalidate` interceptors) before proxying to the `userspace` daemon. It will embed the UI assets and Swagger UI (via `generate-go-embed4assets`). Real-time updates will be pushed to the UI.

#### [NEW] `webui/ui/`
Vite React TypeScript application.
- Uses shadcn/ui for a premium, rich aesthetic.
- Displays a process list with filtering capabilities.
- Detailed view for a selected process showing real-time stats, syscalls, files, and network connections dynamically.

## Verification Plan

### Automated Tests
- Build verification for eBPF using `clang` and `bpf2go`.
- `buf lint` and `buf build` for protobuf validation.
- Unit tests for Go `/proc` parsers.

### Manual Verification
1. Run the `userspace` daemon as root.
2. Run the `webui/bff` server.
3. Open the UI, filter and select a process.
4. Verify `protovalidate` rules work for the API endpoints.
5. Confirm real-time updates and initial snapshots match.
