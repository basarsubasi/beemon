.PHONY: build clean run

build:
	cargo build --release
	mkdir -p ../../bin
	cp target/release/beemon-bff ../../bin/beemon-bff

clean:
	cargo clean
	rm -f ../../bin/beemon-bff

run:
	../../bin/beemon-bff
