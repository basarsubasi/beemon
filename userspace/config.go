package main

import (
	"os"
	"strconv"
)

type Config struct {
	GRPCPort int
}

func LoadConfig() *Config {
	cfg := &Config{
		GRPCPort: 50051, // default
	}

	if portStr := os.Getenv("BEEMON_GRPC_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.GRPCPort = p
		}
	}

	return cfg
}
