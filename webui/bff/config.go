package main

import (
	"os"
	"strconv"
)

type Config struct {
	GRPCEndpoint string
	HTTPPort     int
}

func LoadConfig() *Config {
	cfg := &Config{
		GRPCEndpoint: "unix:///tmp/beemon.sock",
		HTTPPort:     8080,
	}

	if ep := os.Getenv("BEEMON_GRPC_ENDPOINT"); ep != "" {
		cfg.GRPCEndpoint = ep
	}

	if portStr := os.Getenv("BEEMON_HTTP_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.HTTPPort = p
		}
	}

	return cfg
}
