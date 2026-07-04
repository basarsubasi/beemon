//go:build amd64
// +build amd64

package main

import (
	"github.com/basarsubasi/beemon/userspace/gen/x86_64"
	"github.com/cilium/ebpf"
)

type bpfObjects = x86_64.BeemonObjects
type bpfEventT = x86_64.BeemonEventT

func loadBpfObjects(obj *bpfObjects, opts *ebpf.CollectionOptions) error {
	return x86_64.LoadBeemonObjects(obj, opts)
}
