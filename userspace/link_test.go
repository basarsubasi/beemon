package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/basarsubasi/beemon/userspace/gen/x86_64"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// requireRoot skips the test if not running as root. eBPF tests require root.
func requireRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping eBPF test: requires root privileges")
	}
}

func TestEBPF_FileOperations(t *testing.T) {
	requireRoot(t)

	var objs x86_64.BeemonObjects
	if err := x86_64.LoadBeemonObjects(&objs, nil); err != nil {
		t.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach hooks
	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err != nil {
		t.Fatalf("attaching openat: %v", err)
	}
	defer tpOpenat.Close()

	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceSysEnterClose, nil)
	if err != nil {
		t.Fatalf("attaching close: %v", err)
	}
	defer tpClose.Close()

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysEnterWrite, nil)
	if err != nil {
		t.Fatalf("attaching write: %v", err)
	}
	defer tpWrite.Close()

	// Setup Ringbuffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Register our own PID for tracing
	myPid := uint32(os.Getpid())
	if err := objs.TargetPids.Put(myPid, uint8(1)); err != nil {
		t.Fatalf("failed to add pid to map: %v", err)
	}
	defer objs.TargetPids.Delete(myPid)

	// Channel to collect events
	events := make(chan x86_64.BeemonEventT, 10)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			var bpfEvent x86_64.BeemonEventT
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfEvent); err != nil {
				continue
			}

			// Only capture events for our PID to avoid flakes from other threads/processes
			if bpfEvent.Tgid == myPid {
				select {
				case events <- bpfEvent:
				default:
				}
			}
		}
	}()

	// ---------------------------------------------------------
	// Perform actions to trigger eBPF
	// ---------------------------------------------------------
	tmpFile := filepath.Join(t.TempDir(), "ebpf_test_file.txt")

	// 1. Open
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	fd := f.Fd()

	// 2. Write
	testData := []byte("hello ebpf")
	if _, err := f.Write(testData); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// 3. Close
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	// ---------------------------------------------------------
	// Verify Events
	// ---------------------------------------------------------
	var foundOpen, foundWrite, foundClose bool

	timeout := time.After(2 * time.Second)
OuterLoop1:
	for i := 0; i < 10; i++ {
		select {
		case ev := <-events:
			switch ev.Type {
			case 2: // EVENT_TYPE_FILE_OPEN
				fname := int8ToStr(ev.File.Filename[:])
				if strings.Contains(fname, "ebpf_test_file.txt") {
					foundOpen = true
				}
			case 6: // EVENT_TYPE_FILE_WRITE
				if ev.Rw.Fd == uint32(fd) && ev.Rw.Count == uint64(len(testData)) {
					foundWrite = true
				}
			case 7: // EVENT_TYPE_FILE_CLOSE
				if ev.Close.Fd == uint32(fd) {
					foundClose = true
				}
			}
		case <-timeout:
			break OuterLoop1
		}
	}

	if !foundOpen {
		t.Errorf("Failed to capture openat event for %s", tmpFile)
	}
	if !foundWrite {
		t.Errorf("Failed to capture write event for fd %d with count %d", fd, len(testData))
	}
	if !foundClose {
		t.Errorf("Failed to capture close event for fd %d", fd)
	}
}

func TestEBPF_NetworkConnect(t *testing.T) {
	requireRoot(t)

	var objs x86_64.BeemonObjects
	if err := x86_64.LoadBeemonObjects(&objs, nil); err != nil {
		t.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpConnect, err := link.Kprobe("tcp_v4_connect", objs.TcpV4Connect, nil)
	if err != nil {
		t.Fatalf("attaching kprobe: %v", err)
	}
	defer kpConnect.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	myPid := uint32(os.Getpid())
	if err := objs.TargetPids.Put(myPid, uint8(1)); err != nil {
		t.Fatalf("failed to add pid to map: %v", err)
	}
	defer objs.TargetPids.Delete(myPid)

	events := make(chan x86_64.BeemonEventT, 10)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			var bpfEvent x86_64.BeemonEventT
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &bpfEvent); err != nil {
				continue
			}

			if bpfEvent.Tgid == myPid && bpfEvent.Type == 3 { // EVENT_TYPE_NET_CONN
				select {
				case events <- bpfEvent:
				default:
				}
			}
		}
	}()

	// Perform Action: Connect to localhost SSH or a known port
	// We'll just try to connect to a dummy port on localhost, it will fail but tcp_v4_connect will fire.
	targetPort := 54321
	conn, _ := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort), 100*time.Millisecond)
	if conn != nil {
		conn.Close()
	}

	foundConnect := false
	timeout := time.After(2 * time.Second)

OuterLoop2:
	for i := 0; i < 5; i++ {
		select {
		case ev := <-events:
			t.Logf("Caught net event! dport: %d, family: %d", ev.Net.Dport, ev.Net.Family)
			if ev.Net.Dport == uint16(targetPort) {
				foundConnect = true
			}
		case <-timeout:
			break OuterLoop2
		}
	}

	if !foundConnect {
		t.Errorf("Failed to capture tcp_v4_connect event to port %d", targetPort)
	}
}
