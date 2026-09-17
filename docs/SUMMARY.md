# JOCKY Documentation

## Overview
* [Introduction](README.md)
* [What is JOCKY?](overview/what-is-jocky.md)
* [Architecture](overview/architecture.md)
* [Compliance & Legal](overview/compliance.md)

## Prerequisites
* [System Requirements](prerequisites/system-requirements.md)
* [Required Tools](prerequisites/required-tools.md)
* [Network & Certificates](prerequisites/network-certs.md)
* [Authorization Setup](prerequisites/authorization.md)

## Installation
* [Quick Install (One Line)](installation/quick-install.md)
* [macOS](installation/macos.md)
* [Linux — Debian / Ubuntu](installation/linux-debian.md)
* [Linux — RHEL / Fedora / CentOS](installation/linux-rpm.md)
* [Windows](installation/windows.md)
* [Build from Source](installation/from-source.md)
* [VS Code Extension](installation/vscode.md)
* [Verify Installation](installation/verify.md)

## Getting Started
* [Your First Session](getting-started/first-session.md)
* [Dashboard Tour](getting-started/dashboard.md)
* [Running a Dry-Run](getting-started/dry-run.md)
* [Understanding Output](getting-started/output.md)

## JOCKY DSL — Basic
* [Language Overview](language/01-overview.md)
* [Session Structure](language/02-session-structure.md)
* [Targets](language/03-targets.md)
* [Warrants](language/04-warrants.md)
* [Collect Block](language/05-collect.md)
* [Encryption Directives](language/06-encryption.md)
* [Transmit Directive](language/07-transmit.md)

## JOCKY DSL — Intermediate
* [Multiple Artifact Types](language/08-multi-artifact.md)
* [Linux-Specific Collection](language/09-linux.md)
* [Windows-Specific Collection](language/10-windows.md)
* [Post-Quantum Cryptography](language/11-pqc.md)
* [Domain Fronting](language/12-domain-fronting.md)

## JOCKY DSL — Advanced
* [Polymorphic Compilation](language/13-polymorphic.md)
* [In-Memory Execution](language/14-in-memory.md)
* [Kernel-Level Techniques (BYOVD)](language/15-byovd.md)
* [7-Pass Obfuscation Pipeline](language/16-poly-pipeline.md)
* [LLVM IR Internals](language/17-llvm-ir.md)

## CLI Reference
* [jocky-compile](cli/compile.md)
* [Subcommands & Flags](cli/flags.md)
* [Exit Codes](cli/exit-codes.md)
* [Environment Variables](cli/env-vars.md)

## Server & API
* [Starting the Server](server/start.md)
* [REST API Reference](server/api.md)
* [WebSocket Feed](server/websocket.md)
* [mTLS Configuration](server/mtls.md)
* [Dual-Control Approval](server/dual-control.md)

## Blockchain Audit Ledger
* [How the Ledger Works](ledger/how-it-works.md)
* [Verifying Chain Integrity](ledger/verify.md)
* [IT Act §65B Compliance](ledger/65b.md)

## Troubleshooting
* [Common Errors](troubleshooting/common-errors.md)
* [Build Issues](troubleshooting/build.md)
* [Runtime Issues](troubleshooting/runtime.md)
* [FAQ](troubleshooting/faq.md)
