# Targets

The `target:` field identifies the forensic target — the machine being analysed.

---

## Syntax

```jocky
target: "<value>";
```

The value is a string. Accepted formats:

| Format | Example |
|--------|---------|
| IPv4 address | `"192.168.1.105"` |
| IPv6 address | `"2001:db8::1"` |
| Hostname | `"workstation-42.corp.ntro.gov.in"` |
| FQDN | `"victim.example.com"` |
| `localhost` | `"localhost"` or `"127.0.0.1"` (testing only) |

---

## IPv4 Examples

```jocky
// Single host
target: "10.0.5.42";

// Corporate workstation
target: "192.168.100.25";

// Public IP (external target)
target: "203.0.113.50";
```

---

## Hostname Examples

```jocky
// Internal hostname
target: "WIN-LAPTOP-001";

// FQDN
target: "suspect-pc.corp.example.in";
```

---

## Validation

The compiler validates the `target` value:
- IPv4: must be a valid four-octet address
- Hostname: must match `[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]...)*`
- Empty string is an error

If validation fails, the compiler prints:
```
error[E002]: invalid target "foo bar" — must be an IP address or valid hostname
```

---

## Target in the Audit Ledger

The target IP is recorded in every blockchain audit block associated with the session. This ensures the chain-of-custody record documents exactly which host was forensically analysed.
