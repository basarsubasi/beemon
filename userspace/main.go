package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)



func main() {
	srv := &server{}
	
	cleanup, err := StartEBPF(srv)
	if err != nil {
		log.Fatalf("failed to start eBPF: %v", err)
	}
	defer cleanup()

	cfg := LoadConfig()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
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
