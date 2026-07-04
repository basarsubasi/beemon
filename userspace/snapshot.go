package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

// ListProcesses reads /proc to get all running processes and optionally filters by name
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

		statusPath := filepath.Join("/proc", d.Name(), "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		var name, state string
		var ppid uint32
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Name:\t") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:\t"))
			} else if strings.HasPrefix(line, "State:\t") {
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:\t"))
			} else if strings.HasPrefix(line, "PPid:\t") {
				p, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:\t")))
				ppid = uint32(p)
			}
		}

		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}

		processes = append(processes, &pb.Process{
			Pid:   uint32(pid),
			Ppid:  ppid,
			Name:  name,
			State: state,
		})
	}

	return processes, nil
}
