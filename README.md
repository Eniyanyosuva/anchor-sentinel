# Anchor Sentinel

> Static security analysis CLI for Solana Anchor programs. Catches common
> vulnerabilities — missing signer checks, missing ownership constraints,
> missing mutability, weak PDAs, unsafe arithmetic — **before deployment**.

## Quickstart

```bash
cargo install anchor-sentinel
sentinel scan ./my-program --format sarif
```

```
[HIGH] missing_signer
  instruction: withdraw
  account:     authority
  message:     Account `authority` on instruction `withdraw` is not marked as a signer but its name implies authority.
  hint:        Type the field as `Signer` or add `#[account(signer)]`.
```

## Why?

Solana programs are easy to ship with subtle bugs: a missing `Signer` type
or an unwritten `mut` lets an attacker drain a vault. Most of these are
mechanical to detect with a static scan of the IDL + Anchor source.

Anchor Sentinel is that scanner. Local, fast, open-source, JSON-friendly.

## Status — MVP (Weeks 1–3 done)

- [x] CLI: `sentinel scan <path> [--json] [--strict] [--ignore …] [--min-severity …]`
- [x] CLI: `sentinel rules` — list registered rules
- [x] IDL parser: auto-detects Anchor ≤ 0.29 (legacy) and ≥ 0.30 (modern)
- [x] Rule engine: 10 rules registered via plugin registry (`inventory`)
- [x] AST visitors: `#[derive(Accounts)]` structs and `#[program] mod/impl` bodies
- [x] Reports: pretty text + JSON, with severity summary and stable schema
- [x] Loader: discovers `target/idl/*.json` and `programs/**/src/lib.rs`
- [x] Public-fixture fetch script (with in-tree fallbacks)
- [x] JSON snapshot tests (`insta`) for the report shape
- [ ] Public-fixture vendoring (SPL / anchor examples) — script ready, network-gated
- [x] Source `file:line:column` resolution from `proc_macro2::Span`.
- [x] SARIF 2.1.0 output (`--format sarif`) for GitHub Code Scanning.
- [x] GitHub Action (`.github/actions/scan`) — one-line CI integration.
- [x] Published to crates.io (`cargo install anchor-sentinel`).

## Install

```bash
cargo install anchor-sentinel
```

## Usage

Run inside an Anchor project (the directory that contains `Anchor.toml`).
You need `target/idl/<program>.json` present — `anchor build` will generate
that for you.

```bash
# Human-readable scan (default)
sentinel scan .

# Machine-readable, for CI
sentinel scan . --format json

# SARIF output for GitHub Code Scanning / VS Code
sentinel scan . --format sarif

# Treat any non-info finding as a build failure
sentinel scan . --strict

# Skip a rule
sentinel scan . --ignore missing_mut

# Only show high/critical
sentinel scan . --min-severity high

# List all registered rules
sentinel rules
```

## GitHub Action

Add security scanning to your CI in one line. Create `.github/workflows/security.yml`:

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

Findings appear inline on PR diffs and in the GitHub Security tab via SARIF.

### Exit codes

| Code | Meaning                                                          |
| ---- | ---------------------------------------------------------------- |
| 0    | Clean (or findings below the threshold)                          |
| 1    | Findings present and `--strict` (or `--min-severity`) triggered |
| 2    | Tool error (bad path, no IDL, parse failure)                     |

## Rules (current)

| Rule                 | Severity | Source | Notes                                                                                              |
| -------------------- | -------- | ------ | -------------------------------------------------------------------------------------------------- |
| `missing_signer`     | Critical | IDL+AST | High-confidence when the field is typed `AccountInfo`; name-based fallback when AST is absent.    |
| `missing_balance_check` | Critical | AST | Lamports debited (`-=`, `try_borrow_mut_lamports`) without a preceding `require!` or `>=` guard. |
| `duplicate_mutable_accounts` | High | IDL+AST | ≥2 mutable `AccountInfo` args in the same instruction — confusion attack vector. |
| `missing_ownership`  | High     | IDL+AST | Flags mutable `AccountInfo` on `vault`/`pool`/`state` accounts lacking an `owner` constraint.    |
| `lamports_drain`     | High     | IDL+AST | Lamports explicitly zeroed (`lamports = 0`, `set_lamports(0)`) without authorization.            |
| `missing_bump_seed_canonicalization` | High | AST | PDA bump set to user-controlled value instead of `ctx.bumps` or canonical form. |
| `pda_misconfig`      | High     | IDL+AST | PDA seeds with no `bump`, or `bump = <ident>` trap (Sealevel-Attacks pattern).                    |
| `unsafe_arithmetic`  | Medium   | AST     | `+ - * / %` on integer types in `#[program]` handlers, not wrapped in `checked_*`/`saturating_*`. |
| `missing_mut`        | Medium   | IDL+AST | `destination`/`recipient`/`to` accounts not declared `#[account(mut)]`.                            |
| `unchecked_balance_flow` | Medium | IDL+AST | Writable accounts debited without matching credit (lamports conservation heuristic).              |

## Architecture

```
CLI → Loader → IDL Parser → AST Parser → Rule Engine → Report Generator
                                 ↓
                          unified ProgramIr
```

A rule is a struct that implements:

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
}
```

Adding a new rule is a 3-step loop: drop a `src/rules/<name>.rs` file, add a
`pub mod <name>;` line, and submit a `RuleFactory` — no central registration
to remember.

## Test

```bash
cargo test
```

The test suite runs the compiled `sentinel` binary against:

- `tests/fixtures/vault-vulnerable/` — a vulnerable Anchor vault (signer
  escape hatches, unchecked arithmetic, missing balance checks, duplicate mutable accounts).
  Should produce ~14 findings.
- `tests/fixtures/vault-clean/` — a clean Anchor vault. Should report
  zero findings.
- `tests/fixtures/legacy-029/` — an Anchor ≤ 0.29 program (legacy IDL).
  Should report one `missing_signer` finding.
- `tests/fixtures/public/pda-insecure/` — Sealevel-Attacks-style PDA
  with `bump = bump` trap and unchecked subtraction. Should flag both.
- `tests/fixtures/public/pda-secure/` — the same vault, fixed. Should
  report zero findings.
- `tests/fixtures/balance-drain-vulnerable/` — a vault with balance-related
  vulnerabilities (missing balance checks, lamports drain via `set_lamports(0)`).
  Should flag `missing_balance_check` and `lamports_drain` rules.
- 4 JSON snapshot tests via `insta` to lock the report schema.

### Vendoring public fixtures (optional)

For higher-fidelity integration samples, fetch real Anchor programs:

```bash
./scripts/fetch-fixtures.sh
```

This clones `anchor-counter`, `anchor-examples`, `sealevel-attacks`, and
`anchor-zero-copy` (depth 1) into `tests/fixtures/public/`. The script
is idempotent and network-gated — the in-tree fixtures cover the same
patterns when offline. **The script is optional; CI and `cargo test`
do not require it.** Running it pulls several hundred MB of git history
and is intended for local development only.

## License

MIT OR Apache-2.0
