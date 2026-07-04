package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

type server struct {
	pb.UnimplementedBeemonServiceServer
	objs    *BeemonObjects
	mu      sync.Mutex
	streams map[uint32]chan *pb.Event
}

func (s *server) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ListProcessesResponse, error) {
	procs, err := ListProcesses(req.FilterName)
	if err != nil {
		return nil, err
	}
	return &pb.ListProcessesResponse{Processes: procs}, nil
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

	defer func() {
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

func int8ToStr(arr []int8) string {
	var b []byte
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func (s *server) dispatchEvent(bpfEvent BeemonEventT) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.streams[bpfEvent.Pid]
	if !ok {
		return // no one listening
	}
	
	event := &pb.Event{
		TimestampNs: bpfEvent.Ts,
		Pid:         bpfEvent.Pid,
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
		event.Event = &pb.Event_Process{
			Process: &pb.ProcessEvent{
				IsExec:   bpfEvent.Process.IsExec > 0,
				IsFork:   bpfEvent.Process.IsFork > 0,
				IsExit:   bpfEvent.Process.IsExit > 0,
				Comm:     int8ToStr(bpfEvent.Process.Comm[:]),
				ChildPid: bpfEvent.Process.ChildPid,
				ExitCode: bpfEvent.Process.ExitCode,
				Filename: int8ToStr(bpfEvent.Process.Filename[:]),
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
		event.Event = &pb.Event_FileWrite{
			FileWrite: &pb.FileWriteEvent{
				Fd:    bpfEvent.Rw.Fd,
				Count: bpfEvent.Rw.Count,
			},
		}
	case 7: // EVENT_TYPE_FILE_CLOSE
		event.Event = &pb.Event_FileClose{
			FileClose: &pb.FileCloseEvent{
				Fd: bpfEvent.Close.Fd,
			},
		}
	}

	select {
	case ch <- event:
	default: // drop if channel is full
	}
}

func main() {
	var objs BeemonObjects
	if err := LoadBeemonObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Link hooks
	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceSysEnterExecve, nil)
	if err == nil { defer tpExec.Close() }

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceSchedProcessFork, nil)
	if err == nil { defer tpFork.Close() }

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceSchedProcessExit, nil)
	if err == nil { defer tpExit.Close() }

	tpRead, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceSysEnterRead, nil)
	if err == nil { defer tpRead.Close() }

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceSysEnterWrite, nil)
	if err == nil { defer tpWrite.Close() }

	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceSysEnterClose, nil)
	if err == nil { defer tpClose.Close() }

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err == nil { defer tpOpenat.Close() }

	kpConnect, err := link.Kprobe("tcp_v4_connect", objs.TcpV4Connect, nil)
	if err == nil { defer kpConnect.Close() }

	srv := &server{objs: &objs}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed { return }
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

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterBeemonServiceServer(s, srv)
	reflection.Register(s)

	log.Printf("server listening at %v", lis.Addr())
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down")
	s.GracefulStop()
}
