//! JSON snapshot tests for the report shape. Each rule's output is locked
//! in `.snap` files; updates to the schema will cause a test failure that
//! the developer can either accept (via `cargo insta review`) or fix.

use assert_cmd::cargo::cargo_bin;
use assert_cmd::Command;
use std::path::Path;

fn sentinel() -> Command {
    let path = cargo_bin("sentinel");
    Command::new(path)
}

fn fixture(rel: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
        .display()
        .to_string()
}

fn run_scan_json(path: &str) -> serde_json::Value {
    let output = sentinel()
        .args(["scan", path, "--format", "json"])
        .output()
        .expect("scan ran");
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    serde_json::from_str(&stdout).expect("valid JSON")
}

#[test]
fn snapshot_vulnerable_vault_findings() {
    let v = run_scan_json(&fixture("vault-vulnerable"));
    // Strip out `file` paths which are absolute and machine-specific so
    // snapshots are portable across hosts.
    let stripped = strip_absolute_paths(v);
    insta::assert_json_snapshot!("vulnerable_vault", stripped);
}

#[test]
fn snapshot_pda_insecure_findings() {
    let v = run_scan_json(&fixture("public/pda-insecure"));
    let stripped = strip_absolute_paths(v);
    insta::assert_json_snapshot!("pda_insecure", stripped);
}

#[test]
fn snapshot_clean_vault_no_findings() {
    let v = run_scan_json(&fixture("vault-clean"));
    insta::assert_json_snapshot!("clean_vault", v);
}

#[test]
fn snapshot_clean_pda_no_findings() {
    let v = run_scan_json(&fixture("public/pda-secure"));
    insta::assert_json_snapshot!("clean_pda", v);
}

#[test]
fn snapshot_balance_drain_vulnerable() {
    let v = run_scan_json(&fixture("balance-drain-vulnerable"));
    let stripped = strip_absolute_paths(v);
    insta::assert_json_snapshot!("balance_drain_vulnerable", stripped);
}

fn run_scan_sarif(path: &str) -> serde_json::Value {
    let output = sentinel()
        .args(["scan", path, "--format", "sarif"])
        .output()
        .expect("scan ran");
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    serde_json::from_str(&stdout).expect("valid SARIF JSON")
}

#[test]
fn snapshot_sarif_vulnerable_vault() {
    let v = run_scan_sarif(&fixture("vault-vulnerable"));
    let stripped = strip_sarif_paths(v);
    insta::assert_json_snapshot!("sarif_vulnerable_vault", stripped);
}

#[test]
fn sarif_output_has_required_fields() {
    // Quick structural test: SARIF must have schema, version, runs, driver, results.
    let v = run_scan_sarif(&fixture("vault-vulnerable"));
    assert_eq!(v["version"], "2.1.0");
    assert!(v.get("runs").is_some(), "expected `runs` field");
    let run = v["runs"].as_array().unwrap().first().unwrap();
    let driver = &run["tool"]["driver"];
    assert_eq!(driver["name"], "anchor-sentinel");
    assert!(driver["rules"].as_array().is_some());
    assert!(driver["rules"].as_array().unwrap().len() >= 10);
    let results = run["results"].as_array().unwrap();
    assert!(!results.is_empty());
    // Check a result has the required fields.
    let first = &results[0];
    assert!(first.get("ruleId").is_some());
    assert!(first.get("level").is_some());
    assert!(first.get("message").is_some());
    assert!(first.get("locations").is_some());
}

#[test]
fn sarif_severity_mapping() {
    let v = run_scan_sarif(&fixture("vault-vulnerable"));
    let run = v["runs"].as_array().unwrap().first().unwrap();
    let results = run["results"].as_array().unwrap();
    for r in results {
        let level = r["level"].as_str().unwrap();
        // SARIF only allows: error, warning, note, none.
        assert!(
            matches!(level, "error" | "warning" | "note"),
            "unexpected SARIF level: {level}"
        );
    }
}

fn strip_sarif_paths(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(runs) = v.get_mut("runs").and_then(|r| r.as_array_mut()) {
        for run in runs {
            if let Some(results) = run.get_mut("results").and_then(|r| r.as_array_mut()) {
                for result in results {
                    if let Some(locations) =
                        result.get_mut("locations").and_then(|l| l.as_array_mut())
                    {
                        for loc in locations {
                            if let Some(uri) = loc
                                .get_mut("physicalLocation")
                                .and_then(|pl| pl.get_mut("artifactLocation"))
                                .and_then(|al| al.get_mut("uri"))
                            {
                                if let Some(s) = uri.as_str() {
                                    if let Some(idx) = s.find("programs/") {
                                        *uri = serde_json::Value::String(s[idx..].to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    v
}

fn strip_absolute_paths(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(arr) = v.get_mut("findings").and_then(|f| f.as_array_mut()) {
        for finding in arr {
            if let Some(obj) = finding.as_object_mut() {
                if let Some(file) = obj.get("file").and_then(|f| f.as_str()) {
                    // Collapse `/Users/.../programs/.../lib.rs` → `programs/.../lib.rs`.
                    if let Some(idx) = file.find("programs/") {
                        obj.insert(
                            "file".to_string(),
                            serde_json::Value::String(file[idx..].to_string()),
                        );
                    }
                }
            }
        }
    }
    v
}
