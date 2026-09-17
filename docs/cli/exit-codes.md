# Exit Codes

`jocky-compile` exits with one of these codes:

| Code | Meaning | Common Cause |
|------|---------|-------------|
| `0` | Success | Compilation, validation, or dry-run completed normally |
| `1` | General error | Runtime error (file not found, I/O error, network failure) |
| `2` | Parse / validation error | Missing `warrant:`, invalid syntax, bad target format |
| `3` | Obfuscation error | PolyBuilder pipeline failure (internal error) |
| `4` | HSM key error | `JOCKY_HSM_MASTER_KEY` not set and `JOCKY_ALLOW_DEV_KEY` not `1` |
| `5` | Output write error | Cannot write to output file (permissions, disk full) |

## Checking Exit Codes in Scripts

```bash
jocky-compile compile --target linux session.jocky
if [ $? -ne 0 ]; then
    echo "Compilation failed — check warrant format and syntax"
    exit 1
fi
```

```bash
# Validate before submitting to CI
jocky-compile validate "$SESSION_FILE" || exit 2
```

## Common Error Messages

### Missing warrant
```
error[E001]: missing mandatory field `warrant`
Compilation failed (exit code 2).
```

### Invalid warrant format
```
error[E001]: invalid warrant "NTRO2026CYBER0089" — format must be NTRO-YYYY-TYPE-NNNN
Compilation failed (exit code 2).
```

### Missing HSM key
```
error[E004]: no encryption key available
  JOCKY_HSM_MASTER_KEY is not set.
  For development, set JOCKY_ALLOW_DEV_KEY=1.
  For production, set a 64-character hex key.
Compilation failed (exit code 4).
```
