package main

import (
	"log"
	"path/filepath"
	"time"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
	"github.com/fsnotify/fsnotify"
)

// WatchCgroupLimits sets up an fsnotify watcher for the cgroup limits of the given PID.
// It sends a LimitChangedEvent to the outChan when limits are updated.
func WatchCgroupLimits(pid uint32, outChan chan *pb.Event) (*fsnotify.Watcher, error) {
	cgroupPath := GetCgroupPathForPid(pid)
	if cgroupPath == "" {
		return nil, nil // Process might not have a cgroup or it's dead
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// We watch the directory to capture writes to files inside it.
	err = watcher.Add(cgroupPath)
	if err != nil {
		watcher.Close()
		return nil, err
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Check if the modified file is one of our limit files
				base := filepath.Base(event.Name)
				if event.Has(fsnotify.Write) && (base == "memory.max" || base == "cpu.max" || base == "pids.max") {
					memLimit, cpuQuota, cpuPeriod, pidsLimit := ReadCgroupLimits(cgroupPath)
					
					outChan <- &pb.Event{
						TimestampNs: uint64(time.Now().UnixNano()),
						Pid:         pid,
						Event: &pb.Event_LimitChanged{
							LimitChanged: &pb.LimitChangedEvent{
								MemoryLimitBytes: memLimit,
								CpuQuotaUs:       cpuQuota,
								CpuPeriodUs:      cpuPeriod,
								PidsLimit:        pidsLimit,
							},
						},
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error watching cgroup:", err)
			}
		}
	}()

	return watcher, nil
}
