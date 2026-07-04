.PHONY: all generate-proto generate-ebpf build build-ebpf build-bff build-ui clean run

all: generate-proto generate-ebpf build build-ui

generate-proto:
	$(MAKE) -C protobuf generate

generate-ebpf:
	$(MAKE) -C userspace generate

build: build-ebpf build-bff

build-ebpf:
	$(MAKE) -C userspace build

build-bff:
	$(MAKE) -C webui/bff build

build-ui:
	$(MAKE) -C webui/ui build

run:
	$(MAKE) -C webui/bff run

clean:
	$(MAKE) -C protobuf clean
	$(MAKE) -C userspace clean
	$(MAKE) -C webui/bff clean
	$(MAKE) -C webui/ui clean
