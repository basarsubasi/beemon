.PHONY: build clean run

build:
	cargo build --release
	mkdir -p ../../bin
	cp target/release/beemon-aggregator ../../bin/beemon-aggregator

clean:
	cargo clean
	rm -f ../../bin/beemon-aggregator

run:
	../../bin/beemon-aggregator
