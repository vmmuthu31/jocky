# Polymorphic Compilation

Every compilation of a JOCKY source file produces a structurally unique LLVM IR binary. Two runs of `jocky-compile compile` on the same `.jocky` file will produce output with different function names, different control-flow graphs, different junk block counts, and different build digests.

---

## Why Polymorphism?

Static analysis and signature-based detection work by matching known byte patterns. A polymorphic binary defeats this approach:

- AV/EDR signature databases cannot fingerprint a binary that changes every build.
- Threat intelligence sharing becomes less effective — two analysts comparing samples will see different files.
- Reverse engineering effort cannot be reused — deobfuscating one build does not reveal the next.

---

## The Build Seed

Every compilation is seeded with a 64-bit Unix nanosecond timestamp:

```
build_seed = SystemTime::now().duration_since(UNIX_EPOCH).as_nanos() as u64
build_id   = format!("jocky-{:016x}", build_seed)
```

The seed drives all randomization decisions in the 7-pass pipeline. Two compilations in the same nanosecond (impossible in practice) would produce identical output.

---

## Compile and Compare

```bash
# Compile twice
jocky-compile compile --target linux triage.jocky -o triage-1.ll
jocky-compile compile --target linux triage.jocky -o triage-2.ll

# Count function names (all unique per-build hex identifiers)
grep "^define" triage-1.ll | wc -l   # e.g. 31
grep "^define" triage-2.ll | wc -l   # e.g. 31 (same count, different names)

# Compare — should show all names differ
diff <(grep "^define" triage-1.ll) <(grep "^define" triage-2.ll)
```

Expected: every function name differs. The function count and high-level structure are the same, but all identifiers are re-randomized.

---

## Compile Output

```
✓ Compiled  triage.jocky → triage.ll
  build-id  : jocky-17d43a8b2f001c44
  digest    : sha256:a1b2c3d4...64chars
  junk-blks : 55
  apis-masked: 12
```

| Field | Meaning |
|-------|---------|
| `build-id` | Unique identifier for this compilation |
| `digest` | SHA-256 of the obfuscated IR — used for chain-of-custody verification |
| `junk-blks` | Number of dead basic blocks injected by PolyEngine |
| `apis-masked` | Number of API import names obfuscated by IatMasker |

---

## Deterministic Rebuild

If you need to reproduce an exact build (for evidence reproducibility), record the build seed from the output and pass it:

```bash
# Record seed on first compile
jocky-compile compile --target linux triage.jocky 2>&1 | tee compile.log
# build-id: jocky-17d43a8b2f001c44 → seed = 0x17d43a8b2f001c44

# Reproduce exactly (future feature — v1.1.0)
jocky-compile compile --target linux --seed 0x17d43a8b2f001c44 triage.jocky
```

> **Note:** Deterministic rebuild via `--seed` is planned for v1.1.0. In v1.0.0, record the compile log and the `.ll` output to preserve the evidence artifact.

---

## Impact on Forensics

The polymorphic output is the **agent binary** — what runs on the target. The **source** (`.jocky` file) and **audit ledger** are the fixed, legally admissible artifacts.

Forensic reproducibility is maintained by:
1. Storing the compiled `.ll` file (or the resulting binary) alongside the case file.
2. Recording the build digest in the blockchain ledger.
3. Verifying the digest at any future point: `sha256sum triage.ll` must match the ledger.
