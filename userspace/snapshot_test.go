package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListProcesses(t *testing.T) {
	// Create a temporary mock /proc and /sys/fs/cgroup directory structure
	tmpDir := t.TempDir()
	mockProc := filepath.Join(tmpDir, "proc")
	mockCgroup := filepath.Join(tmpDir, "sys", "fs", "cgroup")

	if err := os.MkdirAll(mockProc, 0755); err != nil {
		t.Fatalf("failed to create mock proc: %v", err)
	}
	if err := os.MkdirAll(mockCgroup, 0755); err != nil {
		t.Fatalf("failed to create mock cgroup: %v", err)
	}

	// Override the globals for testing
	procRoot = mockProc
	cgroupRoot = mockCgroup

	// Setup a mock process directory for PID 1234
	procDir := filepath.Join(mockProc, "1234")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	// Write mock status file
	statusContent := "Name:\tbeemon-daemon\nState:\tS (sleeping)\nPPid:\t1\nVmRSS:\t   1024 kB\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(statusContent), 0644); err != nil {
		t.Fatalf("failed to write status: %v", err)
	}

	// Write mock cgroup file (cgroups v2)
	cgroupContent := "0::/user.slice/user-1000.slice/session-1.scope\n"
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to write cgroup: %v", err)
	}

	// Setup mock cgroup fs limits
	cgroupTargetDir := filepath.Join(mockCgroup, "user.slice", "user-1000.slice", "session-1.scope")
	if err := os.MkdirAll(cgroupTargetDir, 0755); err != nil {
		t.Fatalf("failed to create cgroup target dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(cgroupTargetDir, "memory.max"), []byte("104857600\n"), 0644); err != nil {
		t.Fatalf("failed to write memory.max: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupTargetDir, "cpu.max"), []byte("50000 100000\n"), 0644); err != nil {
		t.Fatalf("failed to write cpu.max: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupTargetDir, "pids.max"), []byte("250\n"), 0644); err != nil {
		t.Fatalf("failed to write pids.max: %v", err)
	}

	// Run the test
	res, err := ListProcesses("")
	if err != nil {
		t.Fatalf("ListProcesses failed: %v", err)
	}
	
	procs := res.Processes
	
	if len(procs) != 1 {
		t.Fatalf("Expected 1 process, got %d", len(procs))
	}

	p := procs[0]
	if p.Pid != 1234 {
		t.Errorf("Expected PID 1234, got %d", p.Pid)
	}
	if p.Name != "beemon-daemon" {
		t.Errorf("Expected Name 'beemon-daemon', got '%s'", p.Name)
	}
	if p.MemoryUsageBytes != 1024*1024 { // 1024 kB
		t.Errorf("Expected MemoryUsageBytes 1048576, got %d", p.MemoryUsageBytes)
	}
	if p.MemoryLimitBytes != 104857600 {
		t.Errorf("Expected MemoryLimitBytes 104857600, got %d", p.MemoryLimitBytes)
	}
	if p.CpuQuotaUs != 50000 {
		t.Errorf("Expected CpuQuotaUs 50000, got %d", p.CpuQuotaUs)
	}
	if p.CpuPeriodUs != 100000 {
		t.Errorf("Expected CpuPeriodUs 100000, got %d", p.CpuPeriodUs)
	}
	if p.PidsLimit != 250 {
		t.Errorf("Expected PidsLimit 250, got %d", p.PidsLimit)
	}
}
