# VS Code Extension

The JOCKY VS Code extension adds:
- **Syntax highlighting** for `.jocky` files
- **Snippets** for common session templates
- **Compile command** runnable from the editor
- **Status bar button** to trigger compilation

---

## Install from VSIX

1. Download `jocky-forensics-1.0.0.vsix` from [Releases](https://github.com/vmmuthu31/jocky/releases/latest).
2. In VS Code: `Ctrl+Shift+P` → **Extensions: Install from VSIX…**
3. Select the downloaded `.vsix` file.

Or via the command line:
```bash
code --install-extension jocky-forensics-1.0.0.vsix
```

---

## Install from Source

```bash
cd vscode-extension
npm install
npm run compile          # Compiles TypeScript to JS
make vscode              # Packages and installs the extension
```

---

## Features

### Syntax Highlighting

`.jocky` files get full syntax highlighting:
- Keywords (`forensic`, `session`, `collect`, `encrypt`, `transmit`) in purple
- String literals in orange
- Comments (`//`) in grey
- Warrant IDs highlighted as special tokens

### Snippets

Type a snippet prefix and press `Tab`:

| Prefix | Description |
|--------|-------------|
| `fsession-linux` | Linux triage session template |
| `fsession-windows` | Windows forensics session template |
| `fsession-triage` | Quick triage (both platforms) |
| `fsession-pqc` | Post-quantum ML-KEM-768 session |

### Compile Command

Press `Ctrl+Shift+P` → **JOCKY: Compile Session** (or click the `⚙ JOCKY` button in the status bar).

This runs:
```bash
jocky-compile compile --target <auto-detected> <current-file>.jocky
```

Output appears in the integrated terminal.

### New Session

`Ctrl+Shift+P` → **JOCKY: New Forensic Session** — opens a picker for the session template (Linux / Windows / Triage / PQC), creates a new `.jocky` file, and inserts the template.

---

## Configuration

In VS Code settings (`settings.json`):

```json
{
  "jocky.compilerPath": "/usr/local/bin/jocky-compile",
  "jocky.defaultTarget": "linux"
}
```

---

## Screenshot

After installation, open any `.jocky` file and you will see:

```jocky
forensic session {               ← keyword highlighted
    target: "10.0.5.42";         ← string in orange
    warrant: "NTRO-2026-0089";   ← warrant highlighted
    collect {
        proc: all_processes,     ← artifact type highlighted
        network: active_sockets
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://...";
}
```
