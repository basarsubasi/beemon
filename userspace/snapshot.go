package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

// ListProcesses reads /proc to get all running processes, their usage, and limits
func ListProcesses(filter string) ([]*pb.Process, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
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

		procDir := filepath.Join("/proc", d.Name())
		
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

		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}

		var cpuUsage float32 = 0.0

		// Read cgroup v2 limits
		var memLimit, cpuQuota, cpuPeriod uint64
		cgroupData, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
		if err == nil {
			cgroupPath := ""
			for _, line := range strings.Split(string(cgroupData), "\n") {
				if strings.HasPrefix(line, "0::") {
					cgroupPath = strings.TrimPrefix(line, "0::")
					break
				}
			}

			if cgroupPath != "" {
				sysFsCgroup := filepath.Join("/sys/fs/cgroup", cgroupPath)
				
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
		})
	}

	return processes, nil
}
