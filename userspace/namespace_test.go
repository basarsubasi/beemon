package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"strings"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

func TestGetNamespaceDetails(t *testing.T) {
	// Create a temporary mock /proc structure
	tmpDir := t.TempDir()
	mockProc := filepath.Join(tmpDir, "proc")
	if err := os.MkdirAll(mockProc, 0755); err != nil {
		t.Fatalf("failed to create mock proc: %v", err)
	}

	// Override procRoot for tests
	procRoot = mockProc

	procDir := filepath.Join(mockProc, "1234")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	// Write mock mountinfo
	mountContent := "25 30 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n"
	if err := os.WriteFile(filepath.Join(procDir, "mountinfo"), []byte(mountContent), 0644); err != nil {
		t.Fatalf("failed to write mountinfo: %v", err)
	}

	// Write mock user maps
	if err := os.WriteFile(filepath.Join(procDir, "uid_map"), []byte("         0          0 4294967295\n"), 0644); err != nil {
		t.Fatalf("failed to write uid_map: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "gid_map"), []byte("         0          0 4294967295\n"), 0644); err != nil {
		t.Fatalf("failed to write gid_map: %v", err)
	}

	s := &server{}
	
	// Test error when no reference_pid
	_, err := s.GetNamespaceDetails(context.Background(), &pb.GetNamespaceDetailsRequest{
		NsType: "mnt",
	})
	if err == nil {
		t.Errorf("Expected error when reference_pid is 0, got nil")
	}

	// Test Mnt namespace
	res, err := s.GetNamespaceDetails(context.Background(), &pb.GetNamespaceDetailsRequest{
		NsType:       "mnt",
		ReferencePid: 1234,
	})
	if err != nil {
		t.Fatalf("Failed to GetNamespaceDetails (mnt): %v", err)
	}
	if res.MountInfo != mountContent {
		t.Errorf("Expected MountInfo '%s', got '%s'", mountContent, res.MountInfo)
	}

	// Test User namespace
	res, err = s.GetNamespaceDetails(context.Background(), &pb.GetNamespaceDetailsRequest{
		NsType:       "user",
		ReferencePid: 1234,
	})
	if err != nil {
		t.Fatalf("Failed to GetNamespaceDetails (user): %v", err)
	}
	if !strings.Contains(res.UserMaps, "UID Map:") || !strings.Contains(res.UserMaps, "GID Map:") {
		t.Errorf("Expected UserMaps to contain UID/GID maps, got '%s'", res.UserMaps)
	}
}
