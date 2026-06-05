# Anchor Sentinel

> Static security analysis for Solana Anchor programs. Catches
> missing signer checks, missing ownership constraints, unsafe
> arithmetic, weak PDAs, and other common pitfalls — before you
> ship.

[![crates.io](https://img.shields.io/crates/v/anchor-sentinel)](https://crates.io/crates/anchor-sentinel)
[![CI](https://github.com/Eniyanyosuva/anchor-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Eniyanyosuva/anchor-sentinel/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

---

## Demo

![anchor-sentinel in action](demo.gif)

## What it does

Anchor Sentinel reads your program's IDL (`target/idl/*.json`) and
Rust source (`programs/*/src/lib.rs`), and runs **14 rules** against
the combination. It catches the classes of bug that have shipped
to mainnet in real Anchor programs — see [the rules catalog](docs/rules.md)
for the full list.

```text
$ sentinel scan ./my-anchor-program
╭───────────────────────────────────────────────────────────────────╮
│ ⚓ anchor-sentinel v0.4.0                                          │
│ Solana smart contract security analyzer                            │
╰──────────────────────────────────────────────────────────────────╯
Scanning  ./my-anchor-program
Rules     14 active  ·  3 critical  ·  7 high  ·  4 medium

╭────────────────────────────────────────────────────────────── CRITICAL ─╮
│ ▸  missing_balance_check (withdraw)                                │
│                                                                      │
│ acct     vault                                                       │
│ file     programs/my_program/src/lib.rs:42:8                        │
│                                                                      │
│  Account `vault` has lamports debited by `amount` in `withdraw`     │
│  without a preceding balance check.                                 │
│                                                                      │
│  ▶ Add a guard before the debit:                                    │
│    `require!(vault.lamports() >= amount, ErrorCode::InsufficientFunds)` …
╰──────────────────────────────────────────────────────────────────────╯

(... more findings ...)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ⚠  14 issues found  ·  scanned in 0.42s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CRITICAL  7  ███████████████░░░░░░░░░░░░░░░  (50%)
 HIGH      3  ██████░░░░░░░░░░░░░░░░░░░░░░░░  (21%)
 MEDIUM    4  ████████░░░░░░░░░░░░░░░░░░░░░░  (28%)
 LOW       0  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

→ Run with --format sarif to upload to GitHub Code Scanning.
→ Run with --ignore <rule> to suppress a specific rule.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

The output uses rounded Unicode boxes, per-severity colors, and
brief reveal animations on a real TTY. Piped output (CI, log
files) gets clean plain text with no ANSI codes.

## Why

Most Anchor vulnerabilities are mechanical to detect with a static
scan: a missing `Signer<'info>` here, an `#[account(mut)]` skipped
there, a `bump = bump` argument trap. Anchor Sentinel encodes the
patterns into typed rules so you don't have to remember them.

It's not a replacement for a security audit. It's the cheap first
pass that catches the obvious stuff before the auditor (or the
attacker) does.

## Install

```sh
cargo install anchor-sentinel
```

That's it. The binary lands at `~/.cargo/bin/sentinel` and is
picked up by your shell's `$PATH` automatically. To upgrade:

```sh
cargo install --force anchor-sentinel
```

If you don't have a Rust toolchain, [install rustup](https://rustup.rs)
first.

You can also try the [WASM playground](https://eniyanyosuva.github.io/anchor-sentinel/)
in your browser — no install required.

## Quickstart

Inside an Anchor project (the directory that contains `Anchor.toml`),
make sure you've built the IDL at least once:

```sh
anchor build        # generates target/idl/<program>.json
```

Then run:

```sh
# Human-readable scan, default
sentinel scan .

# Machine-readable, for piping to other tools
sentinel scan . --format json

# SARIF for GitHub Code Scanning / VS Code
sentinel scan . --format sarif

# Treat any non-info finding as a build failure
sentinel scan . --strict

# Only show high/critical
sentinel scan . --min-severity high

# Skip a rule
sentinel scan . --ignore missing_mut

# List all 14 registered rules
sentinel rules
```

For the full flag reference, run `sentinel scan --help` or see
[CLI reference](docs/cli.md).

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | No findings (or findings below the threshold) |
| `1`  | Findings present and `--strict` (or `--min-severity`) triggered |
| `2`  | Tool error — bad path, no IDL files, parse failure |
| `130` | Interrupted (Ctrl+C) |

Use these in CI: `sentinel scan . --strict` makes the build red on
any non-info finding. `sentinel scan . --min-severity high` makes it
red only on high or critical.

## GitHub Action

One-line CI integration. Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Anchor project
        run: anchor build
      - uses: Eniyanyosuva/anchor-sentinel/.github/actions/scan@main
        with:
          fail-on-severity: high
```

Findings show up as PR annotations and in the **Security** tab via
SARIF. See [CI integration](docs/ci.md) for the full action
reference and raw-CLI recipes for other CI systems.

## Rules

Anchor Sentinel ships with **14 rules** spanning three severity
levels and two analysis layers (IDL and AST). The full reference —
including the exact pattern each rule checks, the test fixtures
that exercise it, and a "false positives" note where applicable —
lives in [docs/rules.md](docs/rules.md).

Quick summary:

| Severity | Rules |
| -------- | ----- |
| Critical | `cpi_signer_seed_validation`, `missing_balance_check`, `missing_signer` |
| High | `duplicate_mutable_accounts`, `lamports_drain`, `missing_bump_seed_canonicalization`, `missing_close_authority`, `missing_ownership`, `missing_reinit_guard`, `pda_misconfig` |
| Medium | `integer_cast_truncation`, `missing_mut`, `unchecked_balance_flow`, `unsafe_arithmetic` |

## Sealevel Attacks Coverage

Anchor Sentinel covers 8 of the 9 canonical [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks):

| # | Attack Class               | Status     | Rule(s)                                                    |
|---|----------------------------|------------|------------------------------------------------------------|
| 1 | Signer Authorization       | ✅ covered | missing_signer                                             |
| 2 | Account Data Matching      | ✅ covered | missing_ownership                                          |
| 3 | Owner Checks               | ✅ covered | missing_ownership                                          |
| 4 | Arbitrary CPI              | ✅ covered | cpi_signer_seed_validation                                 |
| 5 | Duplicate Mutable Accounts | ✅ covered | duplicate_mutable_accounts                                 |
| 6 | Type Cosplay               | ⚠️ partial | missing_ownership (discriminator check TBD)                |
| 7 | Reinitialization           | ✅ covered | missing_reinit_guard                                       |
| 8 | Bump Seed Canonicalization | ✅ covered | missing_bump_seed_canonicalization + pda_misconfig         |
| 9 | Closing Accounts           | ✅ covered | missing_close_authority + lamports_drain                   |

## Real-World References

| Rule | Reference |
|------|-----------|
| missing_signer | [Wormhole bridge hack, Feb 2022 — $320M loss](https://extropy-io.medium.com/solanas-wormhole-hack-post-mortem-analysis-3b68b9e88e13) |
| pda_misconfig | [Sealevel Attacks #8 — Bump Seed Canonicalization](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/8-bump-seed-canonicalization) |
| cpi_signer_seed_validation | [Sealevel Attacks #4 — Arbitrary CPI](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/4-arbitrary-cpi) |
| duplicate_mutable_accounts | [Sealevel Attacks #5 — Duplicate Mutable Accounts](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/5-duplicate-mutable-accounts) |
| missing_close_authority | [Sealevel Attacks #9 — Closing Accounts](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/9-closing-accounts) |
| missing_ownership | [Sealevel Attacks #2 — Account Data Matching](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/2-account-data-matching) |
| missing_reinit_guard | [Sealevel Attacks #7 — Reinitialization](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/7-reinitialization) |

## What it does NOT do

- **No runtime simulation.** Anchor Sentinel is static analysis. It
  reads the source and the IDL; it doesn't run your program.
- **No fuzzing / property-based testing.** Pair it with
  [trident](https://github.com/Ackee-Labs-Blockchain/trident) or
  [arbiter](https://github.com/Helios-CLI/arbiter) for that.
- **No dependency audit.** Use `cargo audit` for crate vulnerabilities.
- **No business-logic review.** A finding from sentinel is a
  *symptom* of a class of bug; you still need to understand
  whether the bug actually applies to your program.
- **No IDL-only analysis.** If the IDL is out of date, findings
  may be stale. Always run `anchor build` before `sentinel scan`.

## Troubleshooting

**`error: no IDL files found`**
Run `anchor build` inside the project first. Sentinel looks for
`target/idl/*.json` (the path Anchor writes IDLs to). If you keep
IDLs elsewhere, point the loader at it by symlinking the
directory.

**`error: could not parse IDL`**
Your IDL is malformed or from a version Sentinel doesn't support.
Sentinel auto-detects Anchor 0.30+ and legacy 0.29 IDLs. If
neither parses, please open an issue with the IDL attached
(strip account data first).

**`warning: field is typed AccountInfo, not Signer` fires on a field
that *is* a Signer**
This means the IDL and the source disagree — the field is a
`Signer<'info>` in the Rust source but `signer: false` in the IDL.
Re-run `anchor build` to regenerate the IDL, or fix the IDL
manually.

**Plain text output on what should be a TTY**
Some shells and CI runners don't allocate a real PTY for the
binary, so `is_terminal::IsTerminal::is_terminal(stdout)` returns
false. Run in a fresh Terminal.app or iTerm session to see the
polished output. You can also force it with
`script -q /dev/null sentinel scan .`.

**`sentinel` not found after `cargo install`**
Your shell's `$PATH` may not include `~/.cargo/bin`. Add
`export PATH="$HOME/.cargo/bin:$PATH"` to your shell profile
(`~/.zshrc`, `~/.bashrc`).

## License

MIT OR Apache-2.0 — your choice. See [LICENSE](LICENSE) and
[LICENSE-APACHE](LICENSE-APACHE).
