package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

type server struct {
	pb.UnimplementedBeemonServiceServer
	objs    *bpfObjects
	mu      sync.Mutex
	streams map[uint32]chan *pb.Event
}

func (s *server) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ListProcessesResponse, error) {
	res, err := ListProcesses(req.FilterName)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *server) StreamEvents(req *pb.StreamEventsRequest, stream pb.BeemonService_StreamEventsServer) error {
	pid := req.Pid

	val := uint8(1)
	err := s.objs.TargetPids.Put(pid, val)
	if err != nil {
		return fmt.Errorf("failed to add pid to map: %v", err)
	}

	ch := make(chan *pb.Event, 100)
	s.mu.Lock()
	if s.streams == nil {
		s.streams = make(map[uint32]chan *pb.Event)
	}
	s.streams[pid] = ch
	s.mu.Unlock()

	watcher, err := WatchCgroupLimits(pid, ch)
	if err != nil {
		log.Printf("failed to watch cgroup limits for pid %d: %v", pid, err)
	}

	defer func() {
		if watcher != nil {
			watcher.Close()
		}
		s.mu.Lock()
		delete(s.streams, pid)
		s.mu.Unlock()
		s.objs.TargetPids.Delete(pid)
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

func (s *server) dispatchEvent(bpfEvent bpfEventT) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// bpfEvent.Tgid is the Process ID (PID in userspace), bpfEvent.Pid is the Thread ID (TID)
	// The UI requests the stream using the Process ID.
	ch, ok := s.streams[bpfEvent.Tgid]
	if !ok {
		return // no one listening
	}

	event := &pb.Event{
		TimestampNs: bpfEvent.Ts,
		Pid:         bpfEvent.Tgid, // Send the Process ID to the UI so it matches
	}

	switch bpfEvent.Type {
	case 1: // EVENT_TYPE_SYSCALL
		event.Event = &pb.Event_Syscall{
			Syscall: &pb.SyscallEvent{
				SyscallId: bpfEvent.Syscall.SyscallId,
			},
		}
	case 2: // EVENT_TYPE_FILE_OPEN
		event.Event = &pb.Event_FileOpen{
			FileOpen: &pb.FileOpenEvent{
				Filename: int8ToStr(bpfEvent.File.Filename[:]),
				Flags:    bpfEvent.File.Flags,
			},
		}
	case 3: // EVENT_TYPE_NET_CONN
		event.Event = &pb.Event_NetworkConnect{
			NetworkConnect: &pb.NetworkConnectEvent{
				Saddr:  bpfEvent.Net.Saddr,
				Daddr:  bpfEvent.Net.Daddr,
				Sport:  uint32(bpfEvent.Net.Sport),
				Dport:  uint32(bpfEvent.Net.Dport),
				Family: uint32(bpfEvent.Net.Family),
			},
		}
	case 4: // EVENT_TYPE_PROCESS
		var args []string
		for i := uint8(0); i < bpfEvent.Process.ArgCount && i < 6; i++ {
			args = append(args, int8ToStr(bpfEvent.Process.Args[i][:]))
		}
		event.Event = &pb.Event_Process{
			Process: &pb.ProcessEvent{
				IsExec:   bpfEvent.Process.IsExec > 0,
				IsFork:   bpfEvent.Process.IsFork > 0,
				IsExit:   bpfEvent.Process.IsExit > 0,
				Comm:     int8ToStr(bpfEvent.Process.Comm[:]),
				ChildPid: bpfEvent.Process.ChildPid,
				ExitCode: bpfEvent.Process.ExitCode,
				Filename: int8ToStr(bpfEvent.Process.Filename[:]),
				Args:     args,
			},
		}
	case 5: // EVENT_TYPE_FILE_READ
		event.Event = &pb.Event_FileRead{
			FileRead: &pb.FileReadEvent{
				Fd:    bpfEvent.Rw.Fd,
				Count: bpfEvent.Rw.Count,
			},
		}
	case 6: // EVENT_TYPE_FILE_WRITE
		dataLen := bpfEvent.Rw.Count
		if dataLen > 256 {
			dataLen = 256
		}
		var dataBytes []byte
		for i := uint64(0); i < dataLen; i++ {
			dataBytes = append(dataBytes, byte(bpfEvent.Rw.Data[i]))
		}
		event.Event = &pb.Event_FileWrite{
			FileWrite: &pb.FileWriteEvent{
				Fd:    bpfEvent.Rw.Fd,
				Count: bpfEvent.Rw.Count,
				Data:  dataBytes,
			},
		}
	case 7: // EVENT_TYPE_FILE_CLOSE
		event.Event = &pb.Event_FileClose{
			FileClose: &pb.FileCloseEvent{
				Fd: bpfEvent.Close.Fd,
			},
		}
	case 8: // EVENT_TYPE_CHROOT
		event.Event = &pb.Event_Chroot{
			Chroot: &pb.ChrootEvent{
				Path: int8ToStr(bpfEvent.Isolate.Path1[:]),
			},
		}
	case 9: // EVENT_TYPE_PIVOT_ROOT
		event.Event = &pb.Event_PivotRoot{
			PivotRoot: &pb.PivotRootEvent{
				NewRoot: int8ToStr(bpfEvent.Isolate.Path1[:]),
				PutOld:  int8ToStr(bpfEvent.Isolate.Path2[:]),
			},
		}
	case 10: // EVENT_TYPE_SETNS
		event.Event = &pb.Event_Setns{
			Setns: &pb.SetnsEvent{
				Fd:     bpfEvent.Isolate.Val1,
				Nstype: bpfEvent.Isolate.Val2,
			},
		}
	case 11: // EVENT_TYPE_UNSHARE
		event.Event = &pb.Event_Unshare{
			Unshare: &pb.UnshareEvent{
				Flags: bpfEvent.Isolate.Val1,
			},
		}
	}

	select {
	case ch <- event:
	default: // drop if channel is full
	}
}
