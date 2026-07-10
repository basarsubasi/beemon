.PHONY: all build build-ui clean run dev

all: build build-ui

build: build-ui
	cargo build --release
	mkdir -p bin
	cp target/release/beemon bin/beemon

build-ui:
	$(MAKE) -C webui build

clean:
	cargo clean
	$(MAKE) -C webui clean

run: build
	sudo ./bin/beemon

dev: build
	@echo "Starting Beemon..."
	@echo "NOTE: You may be prompted for your sudo password for the eBPF daemon."
	sudo -v
	sudo ./bin/beemon &
	$(MAKE) -C webui dev
