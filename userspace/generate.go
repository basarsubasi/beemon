package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target amd64 -cflags "-O2 -g -Wall -Werror" -output-dir gen/x86_64 -go-package x86_64 Beemon ../kernelspace/x86_64/beemon.bpf.c -- -I../kernelspace -I../kernelspace/x86_64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target arm64 -cflags "-O2 -g -Wall -Werror" -output-dir gen/arm64 -go-package arm64 Beemon ../kernelspace/arm64/beemon.bpf.c -- -I../kernelspace -I../kernelspace/arm64
