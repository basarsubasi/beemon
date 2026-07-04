//go:build arm64
// +build arm64

package main

import (
	"github.com/basarsubasi/beemon/userspace/gen/arm64"
	"github.com/cilium/ebpf"
)

type bpfObjects = arm64.BeemonObjects
type bpfEventT = arm64.BeemonEventT

func loadBpfObjects(obj *bpfObjects, opts *ebpf.CollectionOptions) error {
	return arm64.LoadBeemonObjects(obj, opts)
}
