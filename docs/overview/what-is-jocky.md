# What is JOCKY?

JOCKY is a three-tier digital forensics platform consisting of:

1. **A domain-specific language (DSL)** — `forensic session { ... }` — that enforces IT Act §69 warrant IDs at the language level. A session without a valid warrant is a compile-time hard error, not a runtime warning.

2. **A Rust compiler** that translates `.jocky` scripts into polymorphic LLVM IR through a 7-pass obfuscation pipeline. Each compilation is unique — token names, control-flow graphs, and metadata change every build.

3. **A Go server** with a REST + WebSocket API, blockchain audit ledger, multi-officer dual-control approval workflow, and mTLS 1.3 agent transport.

4. **A web dashboard** for operators to compile sessions, dispatch agents, approve operations, and monitor live telemetry.

---

## Why a Custom Language?

Standard scripting languages (Python, PowerShell, Bash) leave forensic intent in plain text, trigger EDR/AV heuristics on keywords, and provide no structural mechanism to mandate legal authorization. JOCKY solves all three:

- **Warrant field is mandatory** — the parser hard-fails on any session missing `warrant:`, making compliance impossible to accidentally skip.
- **Polymorphic output** — every compile run produces structurally different IR; no two builds share the same function names, control-flow layout, or metadata.
- **LLVM IR target** — compiles to the same intermediate representation as Clang/Rust, giving access to any LLVM backend (x86, ARM, RISC-V).

---

## Platform Components

```
┌─────────────────────┐    LLVM IR     ┌──────────────────────┐
│  JOCKY DSL (.jocky) │ ──────────────▶│  Rust Compiler       │
│  Warrant-gated DSL  │                │  7-pass poly engine  │
└─────────────────────┘                └──────────┬───────────┘
                                                  │ binary
                                       ┌──────────▼───────────┐
┌─────────────────────┐   mTLS/WSS     │  Field Agent         │
│  Go Server          │ ◀──────────────│  (Windows / Linux)   │
│  Gin + WebSocket    │                └──────────────────────┘
│  Blockchain ledger  │
└──────────┬──────────┘
           │  HTTP API
┌──────────▼──────────┐
│  Web Dashboard      │
│  (plain HTML/JS)    │
└─────────────────────┘
```

| Component | Language | Purpose |
|-----------|----------|---------|
| `compiler/` | Rust | DSL → LLVM IR, 7-pass poly pipeline, runtime modules |
| `server/` | Go | REST + WebSocket, dual-control, blockchain ledger |
| `web/` | HTML / JS | Operator dashboard |
| `vscode-extension/` | TypeScript | IDE syntax highlighting + compile command |
