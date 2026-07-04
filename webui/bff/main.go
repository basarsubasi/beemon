package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

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
	subFS, err := fs.Sub(swaggerAssets, "assets/swagger")
	if err != nil {
		return err
	}
	swaggerHandler := http.StripPrefix("/swagger/", http.FileServer(http.FS(subFS)))
	
	httpMux := http.NewServeMux()
	
	httpMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/stream/ws") {
			handleWS(cfg)(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	httpMux.Handle("/swagger/", swaggerHandler)



	log.Printf("BFF Server listening on :%d\n", cfg.HTTPPort)
	return http.ListenAndServe(fmt.Sprintf(":%d", cfg.HTTPPort), corsHandler(httpMux))
}

func main() {
	// no flags to parse
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
