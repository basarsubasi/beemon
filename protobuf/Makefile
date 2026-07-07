.PHONY: generate clean

generate:
	@echo "Generating protobuf and openapi specs..."
	npx -y @bufbuild/buf generate
	@echo "Preparing assets for go:embed in BFF..."
	mkdir -p ../webui/bff/assets/swagger
	cp gen/openapiv2/api/v1/beemon.swagger.json ../webui/bff/assets/swagger/
	cp swagger-ui/index.html ../webui/bff/assets/swagger/

clean:
	rm -rf ../webui/bff/gen/go/
	rm -rf gen/
	rm -rf ../webui/bff/assets/swagger/
