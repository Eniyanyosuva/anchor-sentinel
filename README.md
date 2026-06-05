# Anchor Sentinel

> Detect critical Solana smart contract vulnerabilities before deployment.

[![crates.io](https://img.shields.io/crates/v/anchor-sentinel)](https://crates.io/crates/anchor-sentinel)
[![CI](https://github.com/Eniyanyosuva/anchor-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Eniyanyosuva/anchor-sentinel/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

---

Anchor Sentinel analyzes Anchor programs for security vulnerabilities
before deployment. It detects missing signer checks, ownership
validation gaps, PDA misconfigurations, reinitialization risks,
unsafe arithmetic, and other common Solana security mistakes —
the same classes of bug that have shipped to mainnet in real
programs.

It is a first-pass security review system: fast, deterministic,
and CI-friendly. Run it on every push. Treat a failing scan as
a build break.

## What it catches

- Missing signer and ownership checks
- PDA seed and bump canonicalization flaws
- Account reinitialization via `init_if_needed`
- Lamports conservation violations and unsafe arithmetic
- Unsafe CPIs with dynamic signer seeds
- Closing-account authorization gaps

14 rules across 3 severity levels, covering 8 of 9 canonical
[Sealevel Attack](https://github.com/coral-xyz/sealevel-attacks)
classes. Full reference: [docs/rules.md](docs/rules.md).

## Example

Run against a vulnerable vault program:

```text
$ sentinel scan ./tests/fixtures/vault-vulnerable

Anchor Sentinel v0.4.0
Static Security Analysis for Solana Programs

Target:  ./tests/fixtures/vault-vulnerable
✓  Loaded rules                   1ms
✓  Parsed IDL                     0ms
✓  Built AST                      2ms
✓  Indexed accounts               2ms
✓  Executed security checks       0ms

Completed in 4ms

Security Overview

Critical       7
High           3
Medium         4
Low            0

Risk Score     0/100
Grade          F
Verdict        DEPLOYMENT BLOCKED

7 Critical findings must be resolved before deployment.

CRITICAL

●  missing_balance_check  ·  deposit

Location:
  ./tests/fixtures/vault-vulnerable/programs/vault/src/lib.rs:21:42

Account:
  user

Problem:
  Account `user` has lamports debited by `amount` in `deposit` without a preceding balance check. An
  attacker can drain the account by calling with `amount > account.lamports()`.

Recommendation:
  Add a guard before the debit: `require!(user.lamports() >= amount, ErrorCode::InsufficientFunds)` or
  use `checked_sub`.

(... 13 more findings ...)

DEPLOYMENT BLOCKED

7 Critical findings must be resolved before deployment.
```

Run against a clean program:

```text
$ sentinel scan ./tests/fixtures/vault-clean

Anchor Sentinel v0.4.0
Static Security Analysis for Solana Programs

Target:  ./tests/fixtures/vault-clean
✓  Loaded rules                   0ms
✓  Parsed IDL                     0ms
✓  Built AST                      1ms
✓  Indexed accounts               1ms
✓  Executed security checks       0ms

Completed in 1ms

Security Overview

Critical       0
High           0
Medium         0
Low            0

Risk Score     100/100
Grade          A
Verdict        DEPLOYMENT APPROVED

No findings detected. Codebase is clean.
✔ no findings

DEPLOYMENT APPROVED

No findings detected. Codebase is clean.
```

## Deployment Verdict

Every scan ends with one of three verdicts:

| Verdict                     | Condition                                               |
| --------------------------- | ------------------------------------------------------- |
| `DEPLOYMENT APPROVED`       | No Critical findings. Risk Score 90-100.                |
| `DEPLOYMENT REVIEW REQUIRED`| No Critical findings. Risk Score 50-89.                 |
| `DEPLOYMENT BLOCKED`        | One or more Critical findings, OR Risk Score below 50.  |

**The Verdict is authoritative.** A single Critical finding always
overrides the score and blocks deployment, regardless of how
benign the rest of the report looks.

The **Risk Score** is informational: a 0-100 number derived from
severity weights (`crit*25 + high*8 + med*3 + low`, clamped at 0).
It is useful for tracking security posture over time but never
overrides the Verdict.

| Score  | Grade |
| ------ | ----- |
| 90-100 | A     |
| 75-89  | B     |
| 50-74  | C     |
| 25-49  | D     |
| 0-24   | F     |

## Install

```sh
cargo install anchor-sentinel
```

The binary lands at `~/.cargo/bin/sentinel`. To upgrade:

```sh
cargo install --force anchor-sentinel
```

Requires a stable Rust toolchain (1.70+). Get one at
[rustup.rs](https://rustup.rs).

You can also try the [WASM playground](https://eniyanyosuva.github.io/anchor-sentinel/)
in your browser — no install required.

## Quickstart

Inside an Anchor project (the directory containing `Anchor.toml`),
make sure the IDL is built:

```sh
anchor build        # writes target/idl/<program>.json
```

Then:

```sh
sentinel scan .                                # human-readable
sentinel scan . --format json                   # machine-readable
sentinel scan . --format sarif                  # GitHub Code Scanning
sentinel scan . --strict                        # exit 1 on any non-info
sentinel scan . --min-severity high             # exit 1 on high+
sentinel scan . --ignore missing_mut            # suppress one rule
sentinel rules                                  # list all rules
```

For the full flag reference, run `sentinel scan --help` or see
[docs/cli.md](docs/cli.md).

## CI integration

Drop a workflow into `.github/workflows/security.yml`:

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

Findings show up as PR annotations and in the **Security** tab
via SARIF. See [docs/ci.md](docs/ci.md) for raw-CLI recipes for
other CI systems.

## Exit codes

| Code  | Meaning                                                   |
| ----- | --------------------------------------------------------- |
| `0`   | No findings (or findings below the threshold)             |
| `1`   | Findings present and `--strict` (or `--min-severity`) hit |
| `2`   | Tool error — bad path, no IDL files, parse failure        |
| `130` | Interrupted (Ctrl+C)                                      |

## Rules

14 rules spanning three severity levels and two analysis layers
(IDL + AST). Coverage summary:

- **3 Critical**: `cpi_signer_seed_validation`, `missing_balance_check`, `missing_signer`
- **7 High**: `duplicate_mutable_accounts`, `lamports_drain`, `missing_bump_seed_canonicalization`, `missing_close_authority`, `missing_ownership`, `missing_reinit_guard`, `pda_misconfig`
- **4 Medium**: `integer_cast_truncation`, `missing_mut`, `unchecked_balance_flow`, `unsafe_arithmetic`

Each rule has a dedicated fixture under `tests/fixtures/`. See
[docs/rules.md](docs/rules.md) for the full reference, including
the exact pattern each rule checks, when it does not fire, and
the real-world exploit it corresponds to.

## Sealevel Attacks coverage

8 of 9 canonical [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)
classes are covered:

| Class                         | Status   | Rule(s)                                      |
| ----------------------------- | -------- | -------------------------------------------- |
| Signer Authorization          | covered  | `missing_signer`                             |
| Account Data Matching         | covered  | `missing_ownership`                          |
| Owner Checks                  | covered  | `missing_ownership`                          |
| Arbitrary CPI                 | covered  | `cpi_signer_seed_validation`                 |
| Duplicate Mutable Accounts    | covered  | `duplicate_mutable_accounts`                 |
| Type Cosplay                  | partial  | `missing_ownership` (discriminator pending)  |
| Reinitialization              | covered  | `missing_reinit_guard`                       |
| Bump Seed Canonicalization    | covered  | `missing_bump_seed_canonicalization`         |
| Closing Accounts              | covered  | `missing_close_authority` + `lamports_drain` |

## What it does NOT do

Anchor Sentinel is a static analyzer and the first security
layer — not a replacement for the rest.

- **No runtime simulation.** It reads the IDL and the source. It
  does not run your program.
- **No fuzzing or property-based testing.** Pair it with
  [trident](https://github.com/Ackee-Labs-Blockchain/trident) or
  [arbiter](https://github.com/Helios-CLI/arbiter).
- **No dependency audit.** Use `cargo audit` for crate CVEs.
- **No business-logic review.** A finding is a symptom of a
  class of bug. You still need to understand whether the bug
  applies to your program.
- **No IDL-only analysis.** Always run `anchor build` first.
  Stale IDLs produce stale findings.

A passing scan reduces risk. It does not eliminate it. Pair
Anchor Sentinel with a human audit, a fuzz harness, and
runtime testing before mainnet.

## Troubleshooting

**`error: no IDL files found`**
Run `anchor build` inside the project first. Sentinel reads
`target/idl/*.json` (the path Anchor writes IDLs to).

**`error: could not parse IDL`**
The IDL is malformed or from a version Sentinel doesn't support.
Sentinel auto-detects Anchor 0.30+ and legacy 0.29. If neither
parses, open an issue with the IDL attached (strip account data).

**A `Signer` field triggers a missing-signer warning**
The IDL and source disagree: the field is typed `Signer<'info>`
in the source but `signer: false` in the IDL. Re-run
`anchor build`.

**Plain text output on what should be a TTY**
Some shells and CI runners don't allocate a real PTY, so
`is_terminal` returns false. Run in a fresh Terminal.app or
iTerm session, or use `script -q /dev/null sentinel scan .`.

**`sentinel` not found after `cargo install`**
Add `~/.cargo/bin` to your `$PATH` (e.g. `export PATH="$HOME/.cargo/bin:$PATH"`
in `~/.zshrc`).

## License

MIT OR Apache-2.0 — your choice. See [LICENSE](LICENSE) and
[LICENSE-APACHE](LICENSE-APACHE).
