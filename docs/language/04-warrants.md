# Warrants

The `warrant:` field is the legal anchor of every JOCKY session. It is the only field that is enforced at the **grammar level** — not as a runtime check, not as a configuration option, but as a hard compile-time requirement.

---

## Syntax

```jocky
warrant: "NTRO-YYYY-TYPE-NNNN";
```

---

## Format

| Component | Description | Valid Values |
|-----------|-------------|-------------|
| `NTRO` | Issuing agency prefix | Always `NTRO` |
| `YYYY` | Four-digit calendar year | `2020`–`2099` |
| `TYPE` | Case category | `CYBER`, `LINUX`, `WIN`, `TRIAGE`, `NET`, `INT` |
| `NNNN` | Zero-padded sequence number | `0001`–`9999` |

**Examples:**
```
NTRO-2026-CYBER-0089
NTRO-2026-LINUX-0421
NTRO-2026-WIN-0003
NTRO-2026-TRIAGE-1234
```

---

## What Happens Without a Warrant

Attempting to compile a session without `warrant:`:

```jocky
forensic session {
    target: "10.0.5.42";
    // warrant field intentionally omitted
    collect { proc: all_processes };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://server/telemetry";
}
```

Compiler output:
```
error[E001]: missing mandatory field `warrant`
  --> triage.jocky:3:5
  |
  | forensic session {
  |     target: "10.0.5.42";
  |     ^^^^^ expected `warrant:` field here
  |
  = note: All forensic sessions require a valid IT Act 2000 §69 warrant ID.
  = note: Format: NTRO-YYYY-TYPE-NNNN  (e.g. NTRO-2026-CYBER-0089)

Compilation failed (exit code 2).
```

No IR is produced. No partial output is written.

---

## Warrant Validation Rules

1. **Format check** — must match regex `^NTRO-[0-9]{4}-(CYBER|LINUX|WIN|TRIAGE|NET|INT)-[0-9]{4}$`
2. **Year range** — must be between 2020 and 2099
3. **Non-empty** — empty string `""` is an error

The compiler does **not** verify the warrant against an external database (that is the officer's responsibility). It enforces format, not existence.

---

## Warrant in the Audit Ledger

The warrant ID is written into the genesis block for the session's audit chain. Every subsequent block in that chain is linked to the warrant ID, making it impossible to detach evidence from its legal authorisation.

---

## Best Practice

Use a warrant numbering system that:
- Monotonically increases the sequence number per year
- Maps one-to-one to physical §69 authorisation orders
- Is tracked in the official case management system

Example workflow:
1. Receive §69 order → assign warrant ID `NTRO-2026-CYBER-0089`
2. Record in case management system
3. Insert warrant ID into `.jocky` source
4. Compile and dispatch session
