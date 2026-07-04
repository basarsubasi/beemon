package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

func TestWatchCgroupLimits(t *testing.T) {
	tmpDir := t.TempDir()
	procRoot = filepath.Join(tmpDir, "proc")
	cgroupRoot = filepath.Join(tmpDir, "cgroup")

	os.MkdirAll(procRoot, 0755)
	os.MkdirAll(cgroupRoot, 0755)

	pid := uint32(1234)
	procTargetDir := filepath.Join(procRoot, "1234")
	os.MkdirAll(procTargetDir, 0755)
	os.WriteFile(filepath.Join(procTargetDir, "cgroup"), []byte("0::/test-cgroup\n"), 0644)

	cgroupTargetDir := filepath.Join(cgroupRoot, "test-cgroup")
	os.MkdirAll(cgroupTargetDir, 0755)

	os.WriteFile(filepath.Join(cgroupTargetDir, "memory.max"), []byte("1048576\n"), 0644)
	os.WriteFile(filepath.Join(cgroupTargetDir, "cpu.max"), []byte("50000 100000\n"), 0644)
	os.WriteFile(filepath.Join(cgroupTargetDir, "pids.max"), []byte("250\n"), 0644)

	outChan := make(chan *pb.Event, 10)
	
	watcher, err := WatchCgroupLimits(pid, outChan)
	if err != nil {
		t.Fatalf("WatchCgroupLimits failed: %v", err)
	}
	defer watcher.Close()

	// Wait for watcher to attach
	time.Sleep(100 * time.Millisecond)

	// Simulate changing a limit
	os.WriteFile(filepath.Join(cgroupTargetDir, "memory.max"), []byte("2048\n"), 0644)

	timeout := time.After(2 * time.Second)
	select {
	case ev := <-outChan:
		lim := ev.GetLimitChanged()
		if lim == nil {
			t.Fatalf("expected LimitChangedEvent, got %T", ev.Event)
		}
		if lim.MemoryLimitBytes != 2048 {
			t.Errorf("expected 2048, got %d", lim.MemoryLimitBytes)
		}
		if lim.PidsLimit != 250 {
			t.Errorf("expected 250, got %d", lim.PidsLimit)
		}
	case <-timeout:
		t.Fatal("timed out waiting for event")
	}
}
