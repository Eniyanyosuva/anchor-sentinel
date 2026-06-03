//! End-to-end integration tests for the `sentinel` CLI.

use assert_cmd::Command;
use predicates::prelude::*;

/// `Command::cargo_bin` (from `assert_cmd`) is the recommended way to locate
/// the test-built binary. It honors `CARGO_BIN_EXE_<name>` and falls back to
/// `cargo metadata` discovery if the env var is absent.
fn sentinel() -> Command {
    Command::cargo_bin("sentinel").expect("resolve sentinel binary")
}

#[test]
fn vulnerable_vault_triggers_findings() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-vulnerable");
    let assert = sentinel()
        .args(["scan", fixture.to_str().unwrap()])
        .assert()
        .success();

    // We expect at least one of each: missing_signer, missing_ownership,
    // missing_mut, and unsafe_arithmetic (now that the AST layer is wired).
    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        output.contains("missing_signer"),
        "expected missing_signer finding, got:\n{output}"
    );
    assert!(
        output.contains("missing_ownership") || output.contains("missing_mut"),
        "expected at least one of missing_ownership / missing_mut, got:\n{output}"
    );
}

#[test]
fn vulnerable_vault_ast_unsafe_arithmetic() {
    // The vulnerable lib.rs uses raw `+` and `-` on u64 lamports — the
    // AST visitor should pick those up.
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-vulnerable");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let has_arith = arr.iter().any(|f| f["rule"] == "unsafe_arithmetic");
    assert!(
        has_arith,
        "expected at least one unsafe_arithmetic finding in:\n{stdout}"
    );
}

#[test]
fn clean_vault_has_no_idl_findings() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-clean");
    let assert = sentinel()
        .args(["scan", fixture.to_str().unwrap()])
        .assert()
        .success();

    let output = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        output.contains("no findings"),
        "expected no findings on clean vault, got:\n{output}"
    );
}

#[test]
fn legacy_v29_idl_is_parsed() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-029");
    sentinel()
        .args(["scan", fixture.to_str().unwrap()])
        .assert()
        // `newAdmin` is not marked signer — should produce at least one finding.
        .stdout(predicate::str::contains("missing_signer"));
}

#[test]
fn json_output_is_valid_json_with_findings_array() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-vulnerable");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");

    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\n{stdout}"));

    assert!(v.get("findings").is_some(), "expected `findings` field");
    assert!(v.get("summary").is_some(), "expected `summary` field");
    let arr = v["findings"].as_array().expect("findings is array");
    assert!(!arr.is_empty(), "expected at least one finding");
}

#[test]
fn strict_mode_fails_on_findings() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-vulnerable");
    sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--strict"])
        .assert()
        .failure();
}

#[test]
fn rules_subcommand_lists_all_rules() {
    sentinel()
        .args(["rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("missing_signer"))
        .stdout(predicate::str::contains("missing_ownership"))
        .stdout(predicate::str::contains("unsafe_arithmetic"))
        .stdout(predicate::str::contains("missing_mut"))
        .stdout(predicate::str::contains("pda_misconfig"))
        .stdout(predicate::str::contains("missing_balance_check"))
        .stdout(predicate::str::contains("lamports_drain"))
        .stdout(predicate::str::contains("unchecked_balance_flow"))
        .stdout(predicate::str::contains(
            "missing_bump_seed_canonicalization",
        ))
        .stdout(predicate::str::contains("duplicate_mutable_accounts"))
        .stdout(predicate::str::contains("integer_cast_truncation"))
        .stdout(predicate::str::contains("missing_close_authority"))
        .stdout(predicate::str::contains("cpi_signer_seed_validation"));
}

#[test]
fn cast_vulnerable_triggers_integer_cast_truncation() {
    // The cast-vulnerable fixture narrows `u64` `amount` parameters into
    // `u8`/`u16` fields. The rule should fire on those and skip the
    // widening cast (`u8 → u16`) and the same-width cast (`u64 → u64`).
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cast-vulnerable");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let rules: Vec<&str> = arr.iter().map(|f| f["rule"].as_str().unwrap()).collect();
    let cast_findings: Vec<_> = arr
        .iter()
        .filter(|f| f["rule"] == "integer_cast_truncation")
        .collect();
    assert!(
        rules.contains(&"integer_cast_truncation"),
        "expected integer_cast_truncation, got: {rules:?}"
    );
    // Two narrowing casts in the fixture: `u64 → u8` (deposit) and
    // `u64 → u16` (withdraw). The widening `u8 → u16` in `audit` and
    // the same-width `u64 → u64` must not appear.
    assert_eq!(
        cast_findings.len(),
        2,
        "expected 2 integer_cast_truncation findings, got {}: {}",
        cast_findings.len(),
        serde_json::to_string_pretty(&cast_findings).unwrap()
    );
}

#[test]
fn clean_vault_has_no_integer_cast_truncation() {
    // The clean vault uses no narrowing casts.
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-clean");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let has = arr.iter().any(|f| f["rule"] == "integer_cast_truncation");
    assert!(
        !has,
        "expected no integer_cast_truncation findings on clean vault, got:\n{stdout}"
    );
}

#[test]
fn close_vulnerable_triggers_missing_close_authority() {
    // The close-vulnerable fixture has three handlers whose `close = receiver`
    // constraint hands the rent to a plain `AccountInfo` receiver with no
    // signer, has_one, or constraint binding. Each should produce one
    // `missing_close_authority` finding pointing at the `vault` field.
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/close-vulnerable");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let close_findings: Vec<_> = arr
        .iter()
        .filter(|f| f["rule"] == "missing_close_authority")
        .collect();
    assert_eq!(
        close_findings.len(),
        3,
        "expected 3 missing_close_authority findings, got {}: {}",
        close_findings.len(),
        serde_json::to_string_pretty(&close_findings).unwrap()
    );
    // Each finding must point at the `vault` field (the one with `close = …`).
    for f in &close_findings {
        assert_eq!(f["account"], "vault", "expected account=vault, got: {f}");
        assert!(
            f["message"]
                .as_str()
                .unwrap()
                .contains("close target `receiver`"),
            "expected message to mention `receiver`, got: {}",
            f["message"]
        );
    }
}

#[test]
fn close_clean_has_no_missing_close_authority() {
    // The close-clean fixture exercises three safe bindings:
    //   1. close target is a `Signer<'info>`
    //   2. close target is bound via `has_one = authority`
    //   3. close target appears in a `constraint = …authority…` expression
    // None of these should trigger `missing_close_authority`.
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/close-clean");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let has = arr.iter().any(|f| f["rule"] == "missing_close_authority");
    assert!(
        !has,
        "expected no missing_close_authority findings on close-clean, got:\n{stdout}"
    );
}

#[test]
fn cpi_vulnerable_triggers_cpi_signer_seed_validation() {
    // The cpi-vulnerable fixture has three handlers that call
    // `invoke_signed` with seeds the AST layer can't verify:
    //   1. `withdraw_arg_bump` uses a `user_bump` function arg
    //   2. `withdraw_arg_bump_byte` uses a `bump` function arg
    //   3. `withdraw_local_bump` uses a locally-bound `bump` variable
    // The `withdraw_attacker_key` handler has canonical seeds but a
    // different vulnerability (no signer check on `attacker`), so it
    // is correctly skipped by this rule.
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cpi-vulnerable");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let seed_findings: Vec<_> = arr
        .iter()
        .filter(|f| f["rule"] == "cpi_signer_seed_validation")
        .collect();
    assert_eq!(
        seed_findings.len(),
        3,
        "expected 3 cpi_signer_seed_validation findings, got {}: {}",
        seed_findings.len(),
        serde_json::to_string_pretty(&seed_findings).unwrap()
    );
    for f in &seed_findings {
        assert_eq!(
            f["severity"], "critical",
            "expected critical severity, got: {f}"
        );
    }
}

#[test]
fn cpi_clean_has_no_cpi_signer_seed_validation() {
    // The cpi-clean fixture uses canonical seed forms across all three
    // handlers: byte literals, `ctx.accounts.user.key().as_ref()`, and
    // `ctx.bumps.<field>`. None should trigger the rule.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cpi-clean");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let has = arr
        .iter()
        .any(|f| f["rule"] == "cpi_signer_seed_validation");
    assert!(
        !has,
        "expected no cpi_signer_seed_validation findings on cpi-clean, got:\n{stdout}"
    );
}

#[test]
fn missing_idl_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    sentinel()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no IDL files found").or(predicate::str::contains("IDL")));
}

#[test]
fn public_pda_insecure_triggers_pda_misconfig() {
    // The in-tree `public/pda-insecure` fixture models the Sealevel-Attacks
    // pattern: a `bump = bump` argument trap and a no-bump seeds constraint.
    // Both should be flagged by pda_misconfig, and the unchecked `-` should
    // be flagged by unsafe_arithmetic.
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public/pda-insecure");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(
        output.status.success(),
        "scan should not error on the fixture"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let rules: Vec<&str> = arr.iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert!(
        rules.contains(&"pda_misconfig"),
        "expected pda_misconfig, got: {rules:?}"
    );
    assert!(
        rules.contains(&"unsafe_arithmetic"),
        "expected unsafe_arithmetic, got: {rules:?}"
    );
}

#[test]
fn public_pda_secure_has_no_findings() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public/pda-secure");
    sentinel()
        .args(["scan", fixture.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no findings"));
}

#[test]
fn balance_drain_vulnerable_triggers_balance_rules() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/balance-drain-vulnerable");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let rules: Vec<&str> = arr.iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert!(
        rules.contains(&"missing_balance_check"),
        "expected missing_balance_check, got: {rules:?}"
    );
    assert!(
        rules.contains(&"lamports_drain"),
        "expected lamports_drain, got: {rules:?}"
    );
}

#[test]
fn clean_vault_no_balance_findings() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-clean");
    let output = sentinel()
        .args(["scan", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(output.status.success(), "scan should succeed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v["findings"].as_array().unwrap();
    let balance_rules = arr
        .iter()
        .filter(|f| {
            matches!(
                f["rule"].as_str(),
                Some(
                    "missing_balance_check"
                        | "lamports_drain"
                        | "unchecked_balance_flow"
                        | "missing_bump_seed_canonicalization"
                        | "duplicate_mutable_accounts"
                )
            )
        })
        .count();
    assert_eq!(
        balance_rules, 0,
        "expected no balance/duplicate findings on clean vault, got {balance_rules}"
    );
}
