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
	@echo "Starting Beemon on port 5055..."
	sudo -v
	sudo BEEMON_WEBUI_PORT=5055 ./bin/beemon
