# Install on Windows

## Option A — Installer .exe (Recommended)

1. Go to [github.com/vmmuthu31/jocky/releases/latest](https://github.com/vmmuthu31/jocky/releases/latest).
2. Download `jocky-setup-1.0.0-x86_64.exe`.
3. Right-click → **Run as administrator**.
4. Follow the installer wizard.

The installer:
- Installs `jocky-compile.exe` to `C:\Program Files\JOCKY\`.
- Adds `C:\Program Files\JOCKY\` to the **system PATH** automatically.
- Creates Start Menu shortcuts.
- Registers an uninstaller (Control Panel → Programs → JOCKY).

Open a new Command Prompt or PowerShell:
```powershell
jocky-compile --version
# JOCKY compiler v1.0.0
```

---

## Option B — PowerShell one-liner

```powershell
irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex
```

Installs to `%USERPROFILE%\.jocky\bin\`. Opens a new terminal to use immediately.

---

## Option C — Winget (Windows Package Manager)

```powershell
winget install NTRO.jocky
```

---

## Option D — Chocolatey

```powershell
choco install jocky
```

---

## Option E — Manual Download

1. Download `jocky-windows-x86_64.exe` from [Releases](https://github.com/vmmuthu31/jocky/releases/latest).
2. Rename to `jocky-compile.exe`.
3. Copy to a directory on your PATH (e.g. `C:\tools\`).

---

## Install the Server on Windows

```powershell
# Install Go from https://go.dev/dl/
# Then:
git clone https://github.com/vmmuthu31/jocky.git
cd jocky\server
go build -o jocky-server.exe .

# Run
$env:JOCKY_ALLOW_DEV_KEY = "1"
$env:JOCKY_COMPILER_PATH = "C:\Program Files\JOCKY\jocky-compile.exe"
.\jocky-server.exe --port 8080
```

Open [http://localhost:8080/dashboard/](http://localhost:8080/dashboard/).

---

## Windows Defender / Antivirus Note

Because `jocky-compile.exe` produces polymorphic LLVM IR (a feature of the tool), some AV engines may flag it with a heuristic. Add `C:\Program Files\JOCKY\` to your AV exclusions list.

This is expected behavior from a forensics tool — not a false positive in the traditional sense. The binary itself is clean; the AV is reacting to the tool's capabilities.

---

## Verify

```powershell
jocky-compile --version
# JOCKY compiler v1.0.0

jocky-compile --help
```
