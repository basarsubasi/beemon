package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

// handleSSE creates a Server-Sent Events stream from the gRPC stream.
func handleSSE(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract PID from URL path: /api/v1/processes/{pid}/events/sse
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		pidStr := parts[4]
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}

		// Set headers for SSE
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// CORS headers are handled by corsHandler in main.go, but we can set them here if needed.
		
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		// Connect to gRPC daemon
		conn, err := grpc.DialContext(r.Context(), cfg.GRPCEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("SSE failed to dial gRPC: %v", err)
			return
		}
		defer conn.Close()

		client := pb.NewBeemonServiceClient(conn)
		
		req := &pb.StreamEventsRequest{Pid: uint32(pid)}
		stream, err := client.StreamEvents(r.Context(), req)
		if err != nil {
			log.Printf("SSE failed to start stream: %v", err)
			return
		}

		marshaler := protojson.MarshalOptions{
			UseProtoNames:   true,
			EmitUnpopulated: true,
		}

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				ev, err := stream.Recv()
				if err == io.EOF {
					return
				}
				if err != nil {
					log.Printf("SSE stream read error: %v", err)
					return
				}

				jsonBytes, err := marshaler.Marshal(ev)
				if err != nil {
					continue
				}

				// Write in SSE format
				fmt.Fprintf(w, "data: %s\n\n", string(jsonBytes))
				flusher.Flush()
			}
		}
	}
}
