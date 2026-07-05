package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for dev
}

type WSPing struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

func handleWS(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract PID from URL path: /api/v1/processes/{pid}/stream/ws
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

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("WS upgrade failed", "error", err)
			return
		}
		defer conn.Close()

		grpcConn, err := grpc.NewClient(cfg.GRPCEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			slog.Error("WS failed to dial gRPC", "error", err)
			return
		}
		defer grpcConn.Close()

		client := pb.NewBeemonServiceClient(grpcConn)
		req := &pb.StreamEventsRequest{Pid: uint32(pid)}
		
		// Create a cancelable context tied to the WS connection
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		stream, err := client.StreamEvents(ctx, req)
		if err != nil {
			slog.Error("WS failed to start stream", "error", err)
			return
		}

		marshaler := protojson.MarshalOptions{
			UseProtoNames:   false,
			EmitUnpopulated: true,
		}

		// Read loop to detect client disconnect
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					cancel()
					return
				}
			}
		}()

		// Channel for gRPC events
		type eventOrErr struct {
			ev  *pb.Event
			err error
		}
		eventCh := make(chan eventOrErr)

		go func() {
			for {
				ev, err := stream.Recv()
				select {
				case <-ctx.Done():
					return
				case eventCh <- eventOrErr{ev, err}:
					if err != nil {
						return
					}
				}
			}
		}()

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingMsg := WSPing{
					Type:      "ping",
					Timestamp: time.Now().UnixMilli(),
				}
				if err := conn.WriteJSON(pingMsg); err != nil {
					slog.Error("WS ping write error", "error", err)
					return
				}
			case res := <-eventCh:
				if res.err == io.EOF {
					return
				}
				if res.err != nil {
					if st, ok := status.FromError(res.err); ok && st.Code() == codes.Canceled {
						return
					}
					if res.err.Error() != "rpc error: code = Canceled desc = context canceled" {
						slog.Error("WS stream read error", "error", res.err)
					}
					return
				}

				jsonBytes, err := marshaler.Marshal(res.ev)
				if err != nil {
					continue
				}

				if err := conn.WriteMessage(websocket.TextMessage, jsonBytes); err != nil {
					slog.Error("WS message write error", "error", err)
					return
				}
			}
		}
	}
}
