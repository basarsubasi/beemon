package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target amd64 -cflags "-O2 -g -Wall -Werror" -output-dir gen/x86_64 -go-package x86_64 Beemon ../kernelspace/x86_64/beemon.bpf.c -- -I../kernelspace -I../kernelspace/x86_64
