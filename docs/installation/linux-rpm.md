# Install on RHEL / Fedora / CentOS

## Option A — .rpm Package (Recommended)

```bash
# Direct URL install
sudo rpm -i https://github.com/vmmuthu31/jocky/releases/latest/download/jocky-x86_64.rpm

# Or download first, then install
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky-x86_64.rpm
sudo rpm -i jocky-x86_64.rpm
```

To upgrade:
```bash
sudo rpm -U jocky-x86_64.rpm
```

To uninstall:
```bash
sudo rpm -e jocky
```

---

## Option B — curl one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

---

## Option C — Manual Binary

```bash
wget https://github.com/vmmuthu31/jocky/releases/latest/download/jocky-linux-x86_64
chmod +x jocky-linux-x86_64
sudo mv jocky-linux-x86_64 /usr/local/bin/jocky-compile
```

---

## Server Setup

```bash
# Install Go
sudo dnf install -y golang git openssl    # Fedora
sudo yum install -y golang git openssl    # CentOS/RHEL

git clone https://github.com/vmmuthu31/jocky.git
cd jocky/server
go build -o jocky-server .
sudo mv jocky-server /usr/local/bin/
```

## Run as a systemd Service

Same as the Debian guide — create `/etc/systemd/system/jocky-server.service` with the same content and run `systemctl enable --now jocky-server`.

---

## SELinux Note

If SELinux is enforcing, you may need to label the binary:

```bash
sudo chcon -t bin_t /usr/local/bin/jocky-compile
sudo chcon -t bin_t /usr/local/bin/jocky-server
```

Or add a custom SELinux policy module for JOCKY. Contact your security team.

---

## Verify

```bash
jocky-compile --version
# JOCKY compiler v1.0.0
```
