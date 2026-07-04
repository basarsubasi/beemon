.PHONY: generatevmlinux

ARCH ?= $(shell uname -m)

generatevmlinux:
	mkdir -p $(ARCH)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(ARCH)/vmlinux.h
