package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

//go:embed assets/swagger/*
var swaggerAssets embed.FS



func run() error {
	cfg := LoadConfig()
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	
	err := pb.RegisterBeemonServiceHandlerFromEndpoint(ctx, mux, cfg.GRPCEndpoint, opts)
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

	log.Printf("BFF Server listening on :%d\n", cfg.HTTPPort)
	return http.ListenAndServe(fmt.Sprintf(":%d", cfg.HTTPPort), corsHandler(httpMux))
}

func main() {
	// no flags to parse
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
