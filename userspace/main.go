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
	objs   *BeemonObjects
	mu     sync.Mutex
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

func (s *server) dispatchEvent(bpfEvent BeemonEventT) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.streams[bpfEvent.Pid]
	if !ok {
		return // no one listening
	}
	
	// Convert to pb.Event (simplified conversion for plan)
	event := &pb.Event{
		TimestampNs: bpfEvent.Ts,
		Pid:         bpfEvent.Pid,
	}

	// Just a basic mapping
	switch bpfEvent.Type {
	case 1: // EVENT_TYPE_SYSCALL
		event.EventData = &pb.Event_Syscall{
			Syscall: &pb.SyscallEvent{
				SyscallId: 0, // Need to parse union bytes
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
	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err == nil { defer tpEnter.Close() }
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceSchedProcessExec, nil)
	if err == nil { defer tpExec.Close() }

	kpOpen, err := link.Kprobe("do_sys_openat2", objs.DoSysOpenat2, nil)
	if err == nil { defer kpOpen.Close() }

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
