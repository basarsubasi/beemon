package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type mockBeemonServer struct {
	pb.UnimplementedBeemonServiceServer
}

func (s *mockBeemonServer) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ListProcessesResponse, error) {
	return &pb.ListProcessesResponse{
		Processes: []*pb.Process{
			{
				Pid:              100,
				Name:             "mock-proc",
				MemoryUsageBytes: 4096,
				CpuUsagePercent:  5.5,
			},
		},
	}, nil
}

func (s *mockBeemonServer) StreamEvents(req *pb.StreamEventsRequest, stream pb.BeemonService_StreamEventsServer) error {
	ev1 := &pb.Event{
		TimestampNs: 1000,
		Pid:         req.Pid,
		Event: &pb.Event_FileOpen{
			FileOpen: &pb.FileOpenEvent{
				Filename: "/etc/passwd",
				Flags:    0,
			},
		},
	}
	if err := stream.Send(ev1); err != nil {
		return err
	}
	
	ev2 := &pb.Event{
		TimestampNs: 2000,
		Pid:         req.Pid,
		Event: &pb.Event_FileRead{
			FileRead: &pb.FileReadEvent{
				Fd:    3,
				Count: 1024,
			},
		},
	}
	if err := stream.Send(ev2); err != nil {
		return err
	}
	
	return nil
}

func TestBFF_ListProcesses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Start mock gRPC server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterBeemonServiceServer(grpcServer, &mockBeemonServer{})
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// 2. Setup BFF mux
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err = pb.RegisterBeemonServiceHandlerFromEndpoint(ctx, mux, lis.Addr().String(), opts)
	if err != nil {
		t.Fatalf("failed to register handler: %v", err)
	}

	// 3. Start HTTP Test Server
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 4. Make HTTP Request
	resp, err := http.Get(ts.URL + "/api/v1/processes")
	if err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// 5. Verify JSON Data
	var res struct {
		Processes []struct {
			Pid              int     `json:"pid"`
			Name             string  `json:"name"`
			MemoryUsageBytes string  `json:"memoryUsageBytes"`
			CpuUsagePercent  float64 `json:"cpuUsagePercent"`
		} `json:"processes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(res.Processes) != 1 {
		t.Fatalf("expected 1 process, got %d", len(res.Processes))
	}

	p := res.Processes[0]
	if p.Pid != 100 {
		t.Errorf("expected pid 100, got %d", p.Pid)
	}
	if p.Name != "mock-proc" {
		t.Errorf("expected name 'mock-proc', got %s", p.Name)
	}
	if p.MemoryUsageBytes != "4096" {
		t.Errorf("expected memory '4096', got %s", p.MemoryUsageBytes)
	}
	if p.CpuUsagePercent != 5.5 {
		t.Errorf("expected cpu 5.5, got %f", p.CpuUsagePercent)
	}
}

func TestBFF_StreamEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterBeemonServiceServer(grpcServer, &mockBeemonServer{})
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err = pb.RegisterBeemonServiceHandlerFromEndpoint(ctx, mux, lis.Addr().String(), opts)
	if err != nil {
		t.Fatalf("failed to register handler: %v", err)
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/processes/100/events")
	if err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	
	var ev1 struct {
		Result struct {
			TimestampNs string `json:"timestampNs"`
			Pid         int    `json:"pid"`
			FileOpen    struct {
				Filename string `json:"filename"`
				Flags    int    `json:"flags"`
			} `json:"fileOpen"`
		} `json:"result"`
	}

	if err := decoder.Decode(&ev1); err != nil {
		t.Fatalf("failed to decode event 1: %v", err)
	}
	if ev1.Result.Pid != 100 {
		t.Errorf("expected pid 100, got %d", ev1.Result.Pid)
	}
	if ev1.Result.FileOpen.Filename != "/etc/passwd" {
		t.Errorf("expected filename /etc/passwd, got %s", ev1.Result.FileOpen.Filename)
	}

	var ev2 struct {
		Result struct {
			TimestampNs string `json:"timestampNs"`
			Pid         int    `json:"pid"`
			FileRead    struct {
				Fd    int    `json:"fd"`
				Count string `json:"count"`
			} `json:"fileRead"`
		} `json:"result"`
	}

	if err := decoder.Decode(&ev2); err != nil {
		t.Fatalf("failed to decode event 2: %v", err)
	}
	if ev2.Result.FileRead.Fd != 3 {
		t.Errorf("expected fd 3, got %d", ev2.Result.FileRead.Fd)
	}
	if ev2.Result.FileRead.Count != "1024" {
		t.Errorf("expected count 1024, got %s", ev2.Result.FileRead.Count)
	}
}
