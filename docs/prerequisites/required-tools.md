# Required Tools

These tools are needed to **build JOCKY from source**. If you install a pre-built binary (Homebrew, `.deb`, `.rpm`, `.exe`), you only need Go for the server.

---

## 1. Rust (≥ 1.75)

The JOCKY DSL compiler is written in Rust.

**Install via rustup (all platforms):**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup update stable
```

**Verify:**
```bash
rustc --version    # rustc 1.75.0 or higher
cargo --version    # cargo 1.75.0 or higher
```

---

## 2. Go (≥ 1.22)

The JOCKY server is written in Go.

**macOS:**
```bash
brew install go
```

**Ubuntu / Debian:**
```bash
sudo apt-get install -y golang-go
# If the packaged version is too old:
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

**Windows:**  
Download the installer from [go.dev/dl](https://go.dev/dl/) and run it.

**Verify:**
```bash
go version    # go1.22.0 or higher
```

---

## 3. OpenSSL (for mTLS certificate generation)

Used by `scripts/gen-certs.sh` to generate CA, server, and client certificates for mTLS.

**macOS:**
```bash
brew install openssl
```

**Ubuntu / Debian:**
```bash
sudo apt-get install -y openssl
```

**Windows:**  
Included in Git for Windows, or install [Win32 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html).

---

## 4. LLVM (optional — for compiling IR to native binary)

`jocky-compile` produces LLVM IR (`.ll` files). To compile IR to a native binary:

```bash
# macOS
brew install llvm
echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc

# Ubuntu
sudo apt-get install -y llvm clang

# Compile IR to native binary
clang output.ll -o agent
```

This step is optional for development — the IR file can be dispatched directly to agents with an LLVM toolchain.

---

## 5. Node.js + vsce (optional — for VS Code extension development)

Only needed if you are modifying or publishing the VS Code extension.

```bash
npm install -g @vscode/vsce
cd vscode-extension
npm install
```

---

## Tool Summary

| Tool | Required For | Install Command |
|------|-------------|-----------------|
| Rust ≥ 1.75 | Building compiler | `curl … rustup.rs \| sh` |
| Go ≥ 1.22 | Building server | `brew install go` / `apt install golang-go` |
| OpenSSL | mTLS certs | `brew install openssl` / `apt install openssl` |
| LLVM / clang | IR → binary | `brew install llvm` / `apt install llvm clang` |
| Node.js + vsce | VSCode extension dev | `npm install -g @vscode/vsce` |
