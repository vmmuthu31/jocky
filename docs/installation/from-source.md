# Build from Source

Building from source gives you the latest unreleased code and allows you to modify the compiler or server.

---

## 1. Clone the Repository

```bash
git clone https://github.com/vmmuthu31/jocky.git
cd jocky
```

---

## 2. Build the Compiler

```bash
cd compiler
cargo build --release
# Binary: target/release/jocky-compile  (Linux/macOS)
#         target/release/jocky-compile.exe  (Windows)
```

**Cross-compile for Windows from Linux:**
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

**Cross-compile for ARM64 Linux:**
```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
```

---

## 3. Run Compiler Tests

```bash
cd compiler
JOCKY_ALLOW_DEV_KEY=1 cargo test
# expected: 114 tests passed
```

---

## 4. Build the Server

```bash
cd ../server
go build -o jocky-server .
```

**Run server tests:**
```bash
go test ./...
# expected: 24 tests passed
```

---

## 5. Install Locally

```bash
# From repo root
make install
```

This copies both binaries to `/usr/local/bin/` (macOS/Linux) or the equivalent on Windows.

Or manually:
```bash
sudo cp compiler/target/release/jocky-compile /usr/local/bin/
sudo cp server/jocky-server /usr/local/bin/
```

---

## 6. One-Command Demo

```bash
./demo.sh
```

This builds the compiler, runs a dry-run test, starts the server, and opens the dashboard.

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build compiler (debug) |
| `make build-all` | Build compiler (release) |
| `make test` | Run all Rust + Go tests |
| `make install` | Build release + install to /usr/local/bin |
| `make server` | Start the Go server (dev mode) |
| `make demo` | Full demo: build + server + dashboard |
| `make certs` | Generate mTLS certificates |
| `make vscode` | Install VS Code extension |
| `make clean` | Remove build artifacts |
| `make help` | List all targets |
