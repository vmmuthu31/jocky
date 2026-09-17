# Install on macOS

## Option A — Homebrew (Recommended)

```bash
brew tap vmmuthu31/jocky
brew install jocky
```

To update:
```bash
brew upgrade jocky
```

To uninstall:
```bash
brew uninstall jocky
brew untap vmmuthu31/jocky
```

---

## Option B — curl one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

---

## Option C — Manual Download

1. Go to [github.com/vmmuthu31/jocky/releases/latest](https://github.com/vmmuthu31/jocky/releases/latest).
2. Download:
   - **Apple Silicon (M1/M2/M3/M4):** `jocky-macos-arm64`
   - **Intel:** `jocky-macos-x86_64`
3. Install:

```bash
# Apple Silicon example
chmod +x jocky-macos-arm64
sudo mv jocky-macos-arm64 /usr/local/bin/jocky-compile
```

---

## Verify

```bash
jocky-compile --version
# JOCKY compiler v1.0.0
```

### Gatekeeper (first run)

macOS may block the binary because it is not signed with an Apple Developer certificate. To allow it:

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine /usr/local/bin/jocky-compile
```

Or: System Settings → Privacy & Security → scroll to "jocky-compile was blocked" → click **Allow Anyway**.

---

## Install the Server (Go)

```bash
git clone https://github.com/vmmuthu31/jocky.git
cd jocky/server
go build -o jocky-server .
sudo mv jocky-server /usr/local/bin/
```

Start the server:
```bash
JOCKY_ALLOW_DEV_KEY=1 \
JOCKY_COMPILER_PATH=/usr/local/bin/jocky-compile \
jocky-server --port 8080
```

Open the dashboard at [http://localhost:8080/dashboard/](http://localhost:8080/dashboard/).
