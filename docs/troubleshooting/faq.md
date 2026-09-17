# Frequently Asked Questions

## General

**Q: Is JOCKY open-source?**
A: Yes. JOCKY is licensed under MIT. Source code is at [github.com/vmmuthu31/jocky](https://github.com/vmmuthu31/jocky).

**Q: Can I use JOCKY without a warrant?**
A: No. The warrant field is enforced at compile time — the compiler hard-fails without a valid `NTRO-YYYY-TYPE-NNNN` warrant ID. There is no bypass.

**Q: Does JOCKY work on macOS targets?**
A: Not in v1.0.0. The field agent supports Windows and Linux targets. macOS support is planned for v1.2.0.

**Q: Can I extend the DSL with new artifact types?**
A: Yes. Add a new artifact keyword to the parser (`compiler/src/parser.rs`), a codegen handler in `compiler/src/codegen.rs`, and a runtime module in `compiler/src/runtime/`. See [LLVM IR Internals](../language/17-llvm-ir.md) for a guide.

---

## Compilation

**Q: Why do two compilations of the same file produce different output?**
A: Each compilation uses a fresh timestamp-based seed for the 7-pass PolyBuilder pipeline. This is intentional — polymorphic output defeats signature-based detection. See [Polymorphic Compilation](../language/13-polymorphic.md).

**Q: Can I reproduce a previous compilation exactly?**
A: In v1.0.0, store the `.ll` file alongside the case file. Deterministic rebuild via `--seed` is planned for v1.1.0.

**Q: The compiler says `junk-blks: 0`. Is something wrong?**
A: PolyEngine injects 40–80 junk blocks by default. If you see 0, ensure you are not running with `--no-obfuscate` (a development flag). This does not affect correctness.

---

## Security

**Q: My AV flags `jocky-compile` as malicious. Is it?**
A: `jocky-compile` itself is clean. Some AV engines apply heuristics to tools that generate polymorphic code. Add the binary to your AV exclusions list.

**Q: Does JOCKY phone home or collect telemetry about my usage?**
A: No. JOCKY has no telemetry, no analytics, and no network calls outside of what you explicitly configure in your `.jocky` sessions.

**Q: Can the BYOVD techniques be detected?**
A: Kernel-telemetry products (e.g. Microsoft Defender for Endpoint) may detect driver loading events. This is expected and documented in the operation plan. JOCKY cleans up the driver after collection, leaving minimal persistent indicators.

---

## Compliance

**Q: What happens if the audit ledger is lost?**
A: The ledger is stored at `server/data/ledger.json`. Back it up alongside the case file. If lost, only the copies already transmitted to evidence management survive. Use a RAID or network filesystem for production deployments.

**Q: Can the ledger be used in court under §65B?**
A: Yes. The SHA-256 hash chain with officer signatures satisfies §65B requirements for authenticated electronic records. Prepare a §65B certificate signed by the responsible NTRO officer referencing the ledger's genesis block hash.

**Q: What is the minimum number of officers needed?**
A: Two — one to create a session, one to approve it. They must be different people. There is no technical upper limit on team size.
