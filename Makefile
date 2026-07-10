.PHONY: all build build-ebpf build-bff build-ui clean run dev run-daemon run-bff run-ui

all: build build-ui

build: build-ebpf build-bff

build-ebpf:
	$(MAKE) -C userspace build

build-bff:
	$(MAKE) -C beemon-aggregator build

build-ui:
	$(MAKE) -C webui build

run:
	$(MAKE) -C beemon-aggregator run

clean:
	$(MAKE) -C userspace clean
	$(MAKE) -C beemon-aggregator clean
	$(MAKE) -C webui clean

dev: build
	@echo "Starting Beemon stack..."
	@echo "NOTE: You may be prompted for your sudo password for the eBPF daemon."
	sudo -v
	$(MAKE) -j3 run-daemon run-bff run-ui

run-daemon:
	sudo ./bin/beemon-daemon

run-bff:
	./bin/beemon-aggregator

run-ui:
	$(MAKE) -C webui dev
