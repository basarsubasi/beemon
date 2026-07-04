.PHONY: generate build clean

generate:
	go generate ./...

build:
	go build -o ../bin/beemon-daemon main.go

clean:
	rm -f beemon_bpfeb.go beemon_bpfeb.o beemon_bpfel.go beemon_bpfel.o
