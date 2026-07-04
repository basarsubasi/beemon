module github.com/basarsubasi/beemon/webui/bff

go 1.26.4

require (
	github.com/basarsubasi/beemon/protobuf v0.0.0-00010101000000-000000000000
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	google.golang.org/grpc v1.82.0
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20260415201107-50325440f8f2.1 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260630182238-925bb5da69e7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260622175928-b703f567277d // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/basarsubasi/beemon/protobuf => ../../protobuf
