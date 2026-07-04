package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	fmt.Println("Starting network tester. My PID is:", time.Now().UnixNano())
	
	// Target Google DNS and Cloudflare
	targets := []string{"8.8.8.8:53", "1.1.1.1:80"}
	
	for {
		for _, target := range targets {
			fmt.Printf("Attempting connection to %s...\n", target)
			
			// Open a TCP connection
			conn, err := net.DialTimeout("tcp", target, 2*time.Second)
			if err != nil {
				fmt.Printf("Failed to connect to %s: %v\n", target, err)
			} else {
				fmt.Printf("Successfully connected to %s from local address %s\n", target, conn.LocalAddr().String())
				conn.Close()
			}
			
			time.Sleep(3 * time.Second)
		}
	}
}
