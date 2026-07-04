package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

var (
	procRoot   = "/proc"
	cgroupRoot = "/sys/fs/cgroup"
	cachedHostNs []string
)

func getHostNamespaces() []string {
	if len(cachedHostNs) > 0 {
		return cachedHostNs
	}
	nsPath := filepath.Join(procRoot, "1", "ns")
	nsEntries, err := os.ReadDir(nsPath)
	if err == nil {
		for _, e := range nsEntries {
			target, err := os.Readlink(filepath.Join(nsPath, e.Name()))
			if err == nil {
				cachedHostNs = append(cachedHostNs, fmt.Sprintf("%s:%s", e.Name(), target))
			}
		}
	}
	return cachedHostNs
}

func GetCgroupPathForPid(pid uint32) string {
	cgroupData, err := os.ReadFile(filepath.Join(procRoot, fmt.Sprintf("%d", pid), "cgroup"))
	if err == nil {
		cgroupPath := ""
		for _, line := range strings.Split(string(cgroupData), "\n") {
			if strings.HasPrefix(line, "0::") {
				cgroupPath = strings.TrimPrefix(line, "0::")
				break
			}
		}
		if cgroupPath != "" {
			return filepath.Join(cgroupRoot, cgroupPath)
		}
	}
	return ""
}

func ReadCgroupLimits(sysFsCgroup string) (memLimit, cpuQuota, cpuPeriod, pidsLimit uint64) {
	// Memory Limit
	memMax, err := os.ReadFile(filepath.Join(sysFsCgroup, "memory.max"))
	if err == nil {
		memStr := strings.TrimSpace(string(memMax))
		if memStr != "max" {
			memLimit, _ = strconv.ParseUint(memStr, 10, 64)
		}
	}

	// CPU Limit
	cpuMax, err := os.ReadFile(filepath.Join(sysFsCgroup, "cpu.max"))
	if err == nil {
		cpuFields := strings.Fields(strings.TrimSpace(string(cpuMax)))
		if len(cpuFields) == 2 {
			if cpuFields[0] != "max" {
				cpuQuota, _ = strconv.ParseUint(cpuFields[0], 10, 64)
			}
			cpuPeriod, _ = strconv.ParseUint(cpuFields[1], 10, 64)
		}
	}
	
	// PIDs Limit
	pidsMax, err := os.ReadFile(filepath.Join(sysFsCgroup, "pids.max"))
	if err == nil {
		pidsStr := strings.TrimSpace(string(pidsMax))
		if pidsStr != "max" {
			pidsLimit, _ = strconv.ParseUint(pidsStr, 10, 64)
		}
	}
	return
}

// ListProcesses reads /proc to get all running processes, their usage, and limits
func ListProcesses(filter string) (*pb.ListProcessesResponse, error) {
	dirs, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	
	// Fetch CPU usages
	cpuUsages := make(map[uint32]float32)
	cmd := exec.Command("ps", "-eo", "pid,%cpu", "--no-headers")
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid, _ := strconv.ParseUint(fields[0], 10, 32)
				cpu, _ := strconv.ParseFloat(fields[1], 32)
				cpuUsages[uint32(pid)] = float32(cpu)
			}
		}
	}
	
	// Fetch total host memory
	var hostMemTotalBytes uint64
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(meminfo), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.ParseUint(fields[1], 10, 64)
					hostMemTotalBytes = kb * 1024
				}
				break
			}
		}
	}

	var processes []*pb.Process
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}

		procDir := filepath.Join(procRoot, d.Name())
		
		// Parse status
		statusData, err := os.ReadFile(filepath.Join(procDir, "status"))
		if err != nil {
			continue
		}

		var name, state string
		var ppid uint32
		var memoryUsage uint64

		lines := strings.Split(string(statusData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Name:\t") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:\t"))
			} else if strings.HasPrefix(line, "State:\t") {
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:\t"))
			} else if strings.HasPrefix(line, "PPid:\t") {
				p, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:\t")))
				ppid = uint32(p)
			} else if strings.HasPrefix(line, "VmRSS:\t") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.ParseUint(fields[1], 10, 64)
					memoryUsage = kb * 1024
				}
			}
		}

		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) && !strings.Contains(d.Name(), filter) {
			continue
		}

		cpuUsage := cpuUsages[uint32(pid)]

		// Read cgroup v2 limits
		var memLimit, cpuQuota, cpuPeriod, pidsLimit uint64
		sysFsCgroup := GetCgroupPathForPid(uint32(pid))
		if sysFsCgroup != "" {
			memLimit, cpuQuota, cpuPeriod, pidsLimit = ReadCgroupLimits(sysFsCgroup)
		}

		// Read namespaces
		var namespaces []string
		nsPath := filepath.Join(procDir, "ns")
		nsEntries, err := os.ReadDir(nsPath)
		if err == nil {
			for _, e := range nsEntries {
				target, err := os.Readlink(filepath.Join(nsPath, e.Name()))
				if err == nil {
					namespaces = append(namespaces, fmt.Sprintf("%s:%s", e.Name(), target))
				}
			}
		}

		processes = append(processes, &pb.Process{
			Pid:              uint32(pid),
			Ppid:             ppid,
			Name:             name,
			State:            state,
			MemoryUsageBytes: memoryUsage,
			CpuUsagePercent:  cpuUsage,
			MemoryLimitBytes: memLimit,
			CpuQuotaUs:       cpuQuota,
			CpuPeriodUs:      cpuPeriod,
			PidsLimit:        pidsLimit,
			Namespaces:       namespaces,
		})
	}

	return &pb.ListProcessesResponse{
		Processes: processes,
		HostMemoryTotalBytes: hostMemTotalBytes,
		HostNamespaces: getHostNamespaces(),
	}, nil
}
