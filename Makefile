.PHONY: all build build-linux build-windows build-mac test clean install demo help

COMPILER_DIR := compiler
SERVER_DIR   := server
BIN          := $(COMPILER_DIR)/target/release/jocky-compile
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

## Default: build + test
all: build test

## Build release binary for the current platform
build:
	@echo "Building jocky-compile $(VERSION)..."
	cd $(COMPILER_DIR) && cargo build --release
	@echo "Binary: $(BIN)"

## Cross-compile for all platforms (requires cross + Docker)
build-all: build-linux build-linux-arm64 build-windows build-mac build-mac-arm64

build-linux:
	cd $(COMPILER_DIR) && cargo build --release --target x86_64-unknown-linux-gnu
	cp $(COMPILER_DIR)/target/x86_64-unknown-linux-gnu/release/jocky-compile \
	   dist/jocky-linux-x86_64

build-linux-arm64:
	cd $(COMPILER_DIR) && cross build --release --target aarch64-unknown-linux-gnu
	cp $(COMPILER_DIR)/target/aarch64-unknown-linux-gnu/release/jocky-compile \
	   dist/jocky-linux-arm64

build-windows:
	cd $(COMPILER_DIR) && cargo build --release --target x86_64-pc-windows-gnu
	cp $(COMPILER_DIR)/target/x86_64-pc-windows-gnu/release/jocky-compile.exe \
	   dist/jocky-windows-x86_64.exe

build-mac:
	cd $(COMPILER_DIR) && cargo build --release --target x86_64-apple-darwin
	cp $(COMPILER_DIR)/target/x86_64-apple-darwin/release/jocky-compile \
	   dist/jocky-macos-x86_64

build-mac-arm64:
	cd $(COMPILER_DIR) && cargo build --release --target aarch64-apple-darwin
	cp $(COMPILER_DIR)/target/aarch64-apple-darwin/release/jocky-compile \
	   dist/jocky-macos-arm64

## Run all tests (Rust + Go)
test:
	@echo "Running Rust tests..."
	cd $(COMPILER_DIR) && JOCKY_ALLOW_DEV_KEY=1 cargo test
	@echo "Running Go tests..."
	cd $(SERVER_DIR) && go test ./...

## Install binary to /usr/local/bin (Unix)
install: build
	@echo "Installing to /usr/local/bin/jocky-compile..."
	cp $(BIN) /usr/local/bin/jocky-compile
	@echo "Done. Run: jocky-compile --help"

## Start the demo (builds, starts server, opens browser)
demo: build
	./demo.sh

## Generate mTLS certificates
certs:
	./scripts/gen-certs.sh certs/

## Start Go server (dev mode)
server: build
	cd $(SERVER_DIR) && \
	JOCKY_ALLOW_DEV_KEY=1 \
	JOCKY_COMPILER_PATH=../$(BIN) \
	JOCKY_WEB_DIR=../web \
	go run . --port 8080

## Package VSCode extension
vscode:
	cd vscode-extension && npm install && npx vsce package

## Clean build artifacts
clean:
	cd $(COMPILER_DIR) && cargo clean
	rm -f dist/jocky-*
	rm -f /tmp/jocky_*.ll

## Create dist directory
dist:
	mkdir -p dist

## Show this help
help:
	@echo "JOCKY Build System"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^##' Makefile | sed 's/^## /  /'
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:' Makefile | grep -v '^\.' | awk -F: '{print "  " $$1}'
