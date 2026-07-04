package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// StartEBPF loads the eBPF objects, attaches the tracepoints, and spawns the ringbuffer reader.
// It returns a cleanup function that closes all resources.
func StartEBPF(srv *server) (func(), error) {
	var objs BeemonObjects
	if err := LoadBeemonObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	var closers []io.Closer
	closers = append(closers, &objs)

	// Link hooks
	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceSysEnterExecve, nil)
	if err == nil { closers = append(closers, tpExec) }

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceSchedProcessFork, nil)
	if err == nil { closers = append(closers, tpFork) }

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceSchedProcessExit, nil)
	if err == nil { closers = append(closers, tpExit) }

	tpRead, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceSysEnterRead, nil)
	if err == nil { closers = append(closers, tpRead) }

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysEnterWrite, nil)
	if err == nil { closers = append(closers, tpWrite) }

	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceSysEnterClose, nil)
	if err == nil { closers = append(closers, tpClose) }

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err == nil { closers = append(closers, tpOpenat) }

	kpConnect, err := link.Kprobe("tcp_v4_connect", objs.TcpV4Connect, nil)
	if err == nil { closers = append(closers, kpConnect) }

	srv.objs = &objs

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, c := range closers { c.Close() }
		return nil, fmt.Errorf("opening ringbuf reader: %v", err)
	}
	closers = append(closers, rd)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed || bytes.Contains([]byte(err.Error()), []byte("closed")) { return }
				log.Printf("reading from reader: %s", err)
				continue
			}

			var bpfEvent BeemonEventT
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfEvent); err != nil {
				continue
			}
			srv.dispatchEvent(bpfEvent)
		}
	}()

	cleanup := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close()
		}
	}

	return cleanup, nil
}
