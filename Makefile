.PHONY: all generate generate-ebpf build build-ui clean run

all: generate generate-ebpf build build-ui

generate:
	$(MAKE) -C protobuf generate

generate-ebpf:
	$(MAKE) -C userspace generate

build:
	$(MAKE) -C userspace build
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
