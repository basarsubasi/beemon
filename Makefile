.PHONY: all build build-ui clean run dev

STATIC_TARGET := x86_64-unknown-linux-gnu
DYNAMIC_TARGET := x86_64-unknown-linux-musl

all: build build-ui

build: build-ui
	cargo build --release --target=$(STATIC_TARGET)
	cargo build --release --target=$(DYNAMIC_TARGET)
	mkdir -p bin
	cp target/$(STATIC_TARGET)/release/beemon bin/beemon-gnu
	cp target/$(DYNAMIC_TARGET)/release/beemon bin/beemon-musl

build-ui:
	$(MAKE) -C webui build

clean:
	cargo clean
	$(MAKE) -C webui clean

run: build
	sudo ./bin/beemon

dev: build
	@echo "Starting Beemon on port 5055..."
	sudo -v
	sudo BEEMON_WEBUI_PORT=5055 ./bin/beemon
