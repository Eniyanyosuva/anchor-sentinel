//! SARIF (Static Analysis Results Interchange Format) output.
//!
//! SARIF 2.1.0 is the standard consumed by GitHub Code Scanning, VS Code
//! Problems panel, and security dashboards. This module maps our internal
//! `Finding` struct to the SARIF schema so that Sentinel can be plugged
//! directly into CI pipelines.

use serde::Serialize;

use crate::engine::{Finding, Severity};
use crate::rules;

/// Top-level SARIF log.
#[derive(Debug, Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    results: Vec<Result>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_description: Option<Message>,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    properties: RuleProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleProperties {
    #[serde(rename = "security-severity")]
    security_severity: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Result {
    rule_id: String,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
    start_column: usize,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

impl Message {
    fn new(s: impl Into<String>) -> Self {
        Self { text: s.into() }
    }
}

/// Map severity to SARIF level + numeric security-severity.
fn severity_map(sev: Severity) -> (&'static str, f64) {
    match sev {
        Severity::Critical => ("error", 9.5),
        Severity::High => ("error", 8.0),
        Severity::Medium => ("warning", 5.5),
        Severity::Low => ("note", 3.0),
        Severity::Info => ("note", 1.0),
    }
}

/// Build the list of rule definitions from the registry.
fn driver_rules() -> Vec<SarifRule> {
    let mut rules = rules::registered_rules();
    rules.sort_by_key(|&(id, _, _)| id);
    rules
        .into_iter()
        .map(|(id, sev, desc)| {
            let (_level, security_severity) = severity_map(sev);
            SarifRule {
                id: id.to_string(),
                name: id.to_string(),
                short_description: Some(Message::new(desc)),
                help_uri: None,
                properties: RuleProperties { security_severity },
            }
        })
        .collect()
}

/// Render a `Finding` to a SARIF `Result`.
fn finding_to_result(f: &Finding) -> Result {
    let (level, _) = severity_map(f.severity);
    let uri = f.file.clone().unwrap_or_default();
    let start_line = f.line.unwrap_or(1);
    let start_column = f.column.unwrap_or(1);

    Result {
        rule_id: f.rule.clone(),
        level,
        message: Message::new(&f.message),
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri },
                region: Region {
                    start_line,
                    start_column,
                },
            },
        }],
    }
}

/// Build a full SARIF log from a list of findings.
pub fn render(findings: &[Finding]) -> String {
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        (&a.rule, &a.instruction, &a.account, a.line, a.column).cmp(&(
            &b.rule,
            &b.instruction,
            &b.account,
            b.line,
            b.column,
        ))
    });
    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "anchor-sentinel",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/eniyanyosuva/anchor-sentinel",
                    rules: driver_rules(),
                },
            },
            results: sorted.iter().map(finding_to_result).collect(),
        }],
    };
    serde_json::to_string_pretty(&log).expect("SARIF JSON always serializes")
}
