# Install on Debian / Ubuntu

## Option A — .deb Package (Recommended)

```bash
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky_amd64.deb
sudo dpkg -i jocky_amd64.deb
```

This installs `jocky-compile` to `/usr/bin/jocky-compile`.

To upgrade later:
```bash
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky_amd64.deb
sudo dpkg -i jocky_amd64.deb   # dpkg upgrades in-place
```

To uninstall:
```bash
sudo dpkg -r jocky
```

---

## Option B — curl one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

---

## Option C — Manual Binary

```bash
# x86_64
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky-linux-x86_64
chmod +x jocky-linux-x86_64
sudo mv jocky-linux-x86_64 /usr/local/bin/jocky-compile

# ARM64 (Raspberry Pi 4, AWS Graviton, etc.)
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky-linux-arm64
chmod +x jocky-linux-arm64
sudo mv jocky-linux-arm64 /usr/local/bin/jocky-compile
```

---

## Install Server Dependencies

```bash
# Go runtime (for building the server from source)
sudo apt-get update
sudo apt-get install -y golang-go git openssl

# Or use the packaged Go if the version is >= 1.22
go version
```

---

## Build and Install the Server

```bash
git clone https://github.com/vmmuthu31/jocky.git
cd jocky/server
go build -o jocky-server .
sudo mv jocky-server /usr/local/bin/
```

---

## Run as a systemd Service

```ini
# /etc/systemd/system/jocky-server.service
[Unit]
Description=JOCKY Digital Forensics Server
After=network.target

[Service]
ExecStart=/usr/local/bin/jocky-server --port 8080
Environment=JOCKY_HSM_MASTER_KEY=<your-64-hex-key>
Environment=JOCKY_COMPILER_PATH=/usr/bin/jocky-compile
Restart=always
User=jocky
Group=jocky

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /bin/false jocky
sudo systemctl daemon-reload
sudo systemctl enable --now jocky-server
sudo systemctl status jocky-server
```

---

## Verify

```bash
jocky-compile --version
# JOCKY compiler v1.0.0
```
