.PHONY: all generate-proto generate-ebpf build build-ebpf build-bff build-ui clean run dev run-daemon run-bff run-ui

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

dev: build
	@echo "Starting Beemon stack..."
	@echo "NOTE: You may be prompted for your sudo password for the eBPF daemon."
	sudo -v
	$(MAKE) -j3 run-daemon run-bff run-ui

run-daemon:
	sudo ./bin/beemon-daemon

run-bff:
	./bin/beemon-bff

run-ui:
	$(MAKE) -C webui/ui dev

