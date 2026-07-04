package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	pb "github.com/basarsubasi/beemon/protobuf/gen/go/api/v1"
)

func (s *server) GetNamespaceDetails(ctx context.Context, req *pb.GetNamespaceDetailsRequest) (*pb.GetNamespaceDetailsResponse, error) {
	resp := &pb.GetNamespaceDetailsResponse{
		NsType:  req.NsType,
		NsInode: req.NsInode,
	}

	pid := req.ReferencePid
	if pid == 0 {
		return nil, fmt.Errorf("reference_pid is required")
	}

	switch req.NsType {
	case "mnt":
		data, err := os.ReadFile(filepath.Join(procRoot, fmt.Sprintf("%d", pid), "mountinfo"))
		if err == nil {
			resp.MountInfo = string(data)
		} else {
			resp.MountInfo = fmt.Sprintf("Error reading mounts: %v", err)
		}
	case "net":
		// Get Links
		linkCmd := exec.Command("nsenter", fmt.Sprintf("--net=%s", filepath.Join(procRoot, fmt.Sprintf("%d", pid), "ns", "net")), "ip", "-c=never", "addr", "show")
		linkOut, err := linkCmd.CombinedOutput()
		if err == nil {
			resp.NetLinks = string(linkOut)
		} else {
			resp.NetLinks = fmt.Sprintf("Error running ip addr: %v\nOutput: %s", err, string(linkOut))
		}

		// Get Routes
		routeCmd := exec.Command("nsenter", fmt.Sprintf("--net=%s", filepath.Join(procRoot, fmt.Sprintf("%d", pid), "ns", "net")), "ip", "-c=never", "route", "show")
		routeOut, err := routeCmd.CombinedOutput()
		if err == nil {
			resp.NetRoutes = string(routeOut)
		} else {
			resp.NetRoutes = fmt.Sprintf("Error running ip route: %v\nOutput: %s", err, string(routeOut))
		}
	case "uts":
		// uts namespace (hostname, domainname)
		hostnameCmd := exec.Command("nsenter", fmt.Sprintf("--uts=%s", filepath.Join(procRoot, fmt.Sprintf("%d", pid), "ns", "uts")), "hostname")
		hostOut, err := hostnameCmd.CombinedOutput()
		domainCmd := exec.Command("nsenter", fmt.Sprintf("--uts=%s", filepath.Join(procRoot, fmt.Sprintf("%d", pid), "ns", "uts")), "domainname")
		domainOut, _ := domainCmd.CombinedOutput()
		if err == nil {
			resp.UtsInfo = fmt.Sprintf("Hostname: %s\nDomainname: %s", string(hostOut), string(domainOut))
		} else {
			resp.UtsInfo = fmt.Sprintf("Error running hostname: %v", err)
		}
	case "user":
		// user namespace uid/gid maps
		uidMap, err1 := os.ReadFile(filepath.Join(procRoot, fmt.Sprintf("%d", pid), "uid_map"))
		gidMap, err2 := os.ReadFile(filepath.Join(procRoot, fmt.Sprintf("%d", pid), "gid_map"))
		if err1 == nil && err2 == nil {
			resp.UserMaps = fmt.Sprintf("UID Map:\n%s\n\nGID Map:\n%s", string(uidMap), string(gidMap))
		} else {
			resp.UserMaps = fmt.Sprintf("Error reading maps: %v, %v", err1, err2)
		}
	}

	return resp, nil
}
