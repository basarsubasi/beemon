package main

import (
	"testing"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

func TestDispatchEvent_Syscall(t *testing.T) {
	srv := &server{
		streams: make(map[uint32]chan *pb.Event),
	}

	pid := uint32(100)
	ch := make(chan *pb.Event, 1)
	srv.streams[pid] = ch

	bpfEv := BeemonEventT{
		Ts:   12345,
		Pid:  pid,
		Type: 1, // Syscall
	}
	bpfEv.Syscall.SyscallId = 17

	srv.dispatchEvent(bpfEv)

	select {
	case ev := <-ch:
		if ev.Pid != pid {
			t.Errorf("expected pid %d, got %d", pid, ev.Pid)
		}
		sys, ok := ev.Event.(*pb.Event_Syscall)
		if !ok {
			t.Fatalf("expected Syscall event, got %T", ev.Event)
		}
		if sys.Syscall.SyscallId != 17 {
			t.Errorf("expected syscall 17, got %d", sys.Syscall.SyscallId)
		}
	default:
		t.Fatal("expected event in channel")
	}
}
