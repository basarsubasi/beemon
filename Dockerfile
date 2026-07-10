# Stage 1: Build UI
FROM node:20-alpine AS ui
WORKDIR /app/webui
COPY webui/package.json webui/package-lock.json ./
RUN npm ci
COPY webui/ ./
RUN npm run build

# Stage 2: Build Rust binary
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev protobuf-dev clang lld make
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY src/ src/
COPY protobuf/ protobuf/
COPY kernelspace/ kernelspace/
COPY webui/dist/ webui/dist/
RUN cargo build --release

# Stage 3: Runtime
FROM alpine:latest
RUN apk add --no-cache libgcc
COPY --from=builder /app/target/release/beemon /usr/local/bin/beemon
EXPOSE 8080
ENTRYPOINT ["beemon"]
