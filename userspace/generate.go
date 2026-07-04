package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target amd64 -cflags "-O2 -g -Wall -Werror" Beemon ../kernelspace/beemon.bpf.c -- -I../kernelspace
