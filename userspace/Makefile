# userspace Makefile -- bridges the top-level Makefile targets to cargo.

GRUB ?= sudo
CARGO ?= cargo
BIN_DIR ?= ../bin
BIN := $(BIN_DIR)/beemon-daemon

# Map host uname -m to cargo target triple used for static musl binaries.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    TARGET ?= x86_64-unknown-linux-musl
else ifeq ($(UNAME_M),aarch64)
    TARGET ?= aarch64-unknown-linux-musl
else
    $(error Unsupported arch: $(UNAME_M). Set TARGET explicitly.)
endif

.PHONY: generate build clean fmt lint test install-strip

# cargo build already drives the build.rs generator (proto + BPF ELFs),
# but the top-level Makefile expects a separate `generate` target.
generate:
	$(CARGO) build --release --target $(TARGET)

build: $(BIN)

$(BIN): Cargo.toml rust-toolchain.toml build.rs $(shell find src -type f)
	$(CARGO) build --release --target $(TARGET)
	mkdir -p $(BIN_DIR)
	cp target/$(TARGET)/release/beemon-daemon $(BIN)

clean:
	$(CARGO) clean
	rm -rf $(BIN_DIR)/beemon-daemon

fmt:
	$(CARGO) +nightly fmt

lint:
	$(CARGO) +nightly clippy --all-targets -- -D warnings

test:
	$(CARGO) +nightly test