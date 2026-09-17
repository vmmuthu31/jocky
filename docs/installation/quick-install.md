# Quick Install (One Line)

If you just want `jocky-compile` available on your PATH as fast as possible:

---

## macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
```

This script:
1. Detects your OS and CPU architecture.
2. Fetches the latest release tag from the GitHub API.
3. Downloads the correct pre-built binary.
4. Installs it to `/usr/local/bin/jocky-compile`.

After installation:
```bash
jocky-compile --version
jocky-compile --help
```

---

## Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex
```

This script installs to `%USERPROFILE%\.jocky\bin\` and adds that directory to your user PATH.

Open a new terminal, then:
```powershell
jocky-compile --version
```

---

## Verify

```bash
jocky-compile --version
# JOCKY compiler v1.0.0

jocky-compile --help
# JOCKY Digital Forensics Compiler
# ...
```

If the command is not found, check that `/usr/local/bin` (Unix) or `%USERPROFILE%\.jocky\bin` (Windows) is on your PATH.
