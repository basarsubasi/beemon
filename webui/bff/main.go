package main

import (
	"context"
	"embed"
	"flag"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

//go:embed assets/swagger/*
var swaggerAssets embed.FS

var (
	grpcServerEndpoint = flag.String("grpc-server-endpoint", "localhost:50051", "gRPC server endpoint")
)

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	
	err := pb.RegisterBeemonServiceHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts)
	if err != nil {
		return err
	}

	// Serve Swagger UI
	swaggerHandler := http.StripPrefix("/swagger/", http.FileServer(http.FS(swaggerAssets)))
	
	httpMux := http.NewServeMux()
	httpMux.Handle("/", mux)
	httpMux.Handle("/swagger/", swaggerHandler)

	// Add CORS for UI development
	corsHandler := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	log.Println("BFF Server listening on :8080")
	return http.ListenAndServe(":8080", corsHandler(httpMux))
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
