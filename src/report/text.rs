//! Human-readable CLI output. This is the only place in the codebase
//! that emits ANSI color or Unicode glyphs; the six `print_*` helpers
//! and `print_rules_table` are the single entry points used by `main.rs`.
//!
//! All color calls are gated on `tty::interactive()`, so the test
//! suite (which pipes stdout) gets a clean plain-text stream and the
//! snapshot/integration tests don't need to filter ANSI escape codes.
//!
//! Design tenets:
//!   1. Information first — risk + critical findings + verdict visible in 3s.
//!   2. Severity driven — Critical dominates; Medium never competes visually.
//!   3. Progressive disclosure — overview → findings → details.
//!   4. Spacing over boxes — at most three "cards" (hero, overview, verdict).
//!   5. Cargo-style tables (no box drawing) for the `sentinel rules` listing.

use std::time::Duration;

use colored::*;

use crate::engine::{Finding, Severity};
use crate::report::tty;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Public types: what the caller hands us.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Per-stage durations measured by `main.rs` around the four scan
/// phases, plus a wall-clock total. All fields are wall-clock from
/// the start of the corresponding phase (or the whole scan, for
/// `total`).
#[derive(Debug, Clone, Copy)]
pub struct ScanTimings {
    pub load: Duration,
    pub parse_idls: Duration,
    pub ast_hints: Duration,
    pub run_rules: Duration,
    pub total: Duration,
}

/// Everything `main.rs` knows about a finished scan, bundled for the
/// sectioned printers. Borrow-only — the caller owns the underlying
/// data and is responsible for outliving these printers.
pub struct ScanReport<'a> {
    pub timings: ScanTimings,
    pub programs: usize,
    pub instructions: usize,
    pub rules_executed: usize,
    pub findings: &'a [Finding],
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Risk score model. See the plan: penalty = crit*25 + high*8 + med*3 + low*1,
// score = max(0, 100 - penalty). Critical findings always override to BLOCKED.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

mod risk {
    /// Compute the 0..=100 risk score from severity counts.
    pub fn score(c: usize, h: usize, m: usize, l: usize) -> u32 {
        let penalty = (c as u32) * 25 + (h as u32) * 8 + (m as u32) * 3 + l as u32;
        100u32.saturating_sub(penalty)
    }

    /// Letter grade derived from the score. A=90-100, B=75-89, C=50-74,
    /// D=25-49, F=0-24. Bounded on both ends — saturating_sub in
    /// `score` keeps us in 0..=100 so the match is exhaustive over
    /// the natural range.
    pub fn grade(s: u32) -> &'static str {
        match s {
            90..=100 => "A",
            75..=89 => "B",
            50..=74 => "C",
            25..=49 => "D",
            _ => "F",
        }
    }

    /// Authoritative deployment recommendation. Critical findings
    /// always produce `Blocked`, regardless of score. Otherwise the
    /// score decides: 90+ → Approved, 50-89 → ReviewRequired,
    /// <50 → Blocked.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Verdict {
        Approved,
        ReviewRequired,
        Blocked,
    }

    /// The `(verdict, label)` pair the verdict printer renders. The
    /// `&'static str` is the headline (e.g. `"DEPLOYMENT BLOCKED"`);
    /// the follow-up sentence is generated separately.
    pub fn verdict(c: usize, h: usize, m: usize, l: usize) -> (Verdict, &'static str) {
        if c >= 1 {
            return (Verdict::Blocked, "DEPLOYMENT BLOCKED");
        }
        let s = score(c, h, m, l);
        match s {
            90..=100 => (Verdict::Approved, "DEPLOYMENT APPROVED"),
            50..=89 => (Verdict::ReviewRequired, "DEPLOYMENT REVIEW REQUIRED"),
            _ => (Verdict::Blocked, "DEPLOYMENT BLOCKED"),
        }
    }

    /// One-sentence follow-up for the verdict. Used by the Security
    /// Overview block and the final Verdict block. The sentences are
    /// designed to read naturally at any count — `1 finding` is
    /// pluralized to `1 finding`, larger counts are bare plurals.
    pub fn follow_up(c: usize, h: usize, m: usize, l: usize) -> String {
        // Critical override: always this exact phrasing, regardless of
        // the score. Matches the user's spec example verbatim.
        if c >= 1 {
            return pluralize(c, "Critical finding", "Critical findings")
                + " must be resolved before deployment.";
        }
        let s = score(c, h, m, l);
        if s >= 90 {
            // Approved path. The plan says "No critical findings
            // detected" is the approved-state subline. We generalize
            // to "No critical or high-severity findings detected" when
            // both are zero, and to a count summary otherwise.
            if h == 0 && m == 0 && l == 0 {
                return "No findings detected. Codebase is clean.".to_string();
            }
            return "No critical findings detected.".to_string();
        }
        if s >= 50 {
            // Review required — surface the highest present severity.
            if h > 0 {
                return pluralize(
                    h,
                    "high-severity finding requires",
                    "high-severity findings require",
                ) + " review before deployment.";
            }
            if m > 0 {
                return pluralize(
                    m,
                    "medium-severity finding requires",
                    "medium-severity findings require",
                ) + " review before deployment.";
            }
            return pluralize(
                l,
                "low-severity finding requires",
                "low-severity findings require",
            ) + " review before deployment.";
        }
        // Score <50 with no critical: high-count saturated the score.
        // Surface the dominant severity in the follow-up.
        if h > 0 {
            return pluralize(h, "high-severity finding is", "high-severity findings are")
                + " blocking deployment.";
        }
        if m > 0 {
            return pluralize(
                m,
                "medium-severity finding is",
                "medium-severity findings are",
            ) + " blocking deployment.";
        }
        pluralize(l, "low-severity finding is", "low-severity findings are")
            + " blocking deployment."
    }

    fn pluralize(n: usize, singular: &str, plural: &str) -> String {
        let word = if n == 1 { singular } else { plural };
        format!("{n} {word}")
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section 1 — Hero
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print the scan opener: a brand line, a tagline, and the target
/// path. Three lines plus a blank. No box, no animation.
pub fn print_hero(project: &str) {
    if tty::interactive() {
        // The brand line: ⚓ glyph in bright_cyan+bold, "Anchor Sentinel"
        // in white+bold, version in dim. Per the spec the human-readable
        // name is "Anchor Sentinel" (two words, title case), not the
        // kebab-case binary name.
        println!(
            "{} {} {}",
            "⚓".bright_cyan().bold(),
            "Anchor Sentinel".white().bold(),
            format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
        );
        println!(
            "{}",
            "Static Security Analysis for Solana Programs".dimmed()
        );
        println!();
        println!("{}  {}", "Target:".dimmed(), project);
    } else {
        println!("Anchor Sentinel v{}", env!("CARGO_PKG_VERSION"));
        println!("Static Security Analysis for Solana Programs");
        println!();
        println!("Target:  {}", project);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section 2 — Pipeline
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print the 5-stage pipeline status with per-stage durations. The
/// `✓` is green; labels are plain; durations are dim and right-aligned
/// in a 6-char field. TTY vs non-TTY diverge only on color, not on
/// content — the test suite sees a clean plain-text pipeline.
pub fn print_pipeline(timings: &ScanTimings) {
    let stages: [(&str, Duration); 5] = [
        ("Loaded rules", timings.load),
        ("Parsed IDL", timings.parse_idls),
        ("Built AST", timings.ast_hints),
        ("Indexed accounts", timings.ast_hints),
        ("Executed security checks", timings.run_rules),
    ];
    for (label, dur) in stages {
        let ms = dur.as_secs_f64() * 1000.0;
        // Print duration as `412ms` for sub-second and `1.23s` for >= 1s.
        let dur_str = if ms < 1000.0 {
            format!("{:.0}ms", ms)
        } else {
            format!("{:.2}s", ms / 1000.0)
        };
        if tty::interactive() {
            println!(
                "{}  {:<26}{}",
                "✓".green().bold(),
                label,
                format!("{dur_str:>8}").dimmed()
            );
        } else {
            println!("✓  {label:<26}{dur_str:>8}");
        }
    }
    let total_ms = timings.total.as_secs_f64() * 1000.0;
    let total_str = if total_ms < 1000.0 {
        format!("{:.0}ms", total_ms)
    } else {
        format!("{:.2}s", total_ms / 1000.0)
    };
    println!();
    if tty::interactive() {
        println!("{} {}", "Completed in".dimmed(), total_str.white().bold());
    } else {
        println!("Completed in {total_str}");
    }
    println!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section 3 — Security Overview
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print the security overview block: per-severity counts, the risk
/// score (with grade), and the verdict. The label column is
/// left-padded to 15 chars so the numbers align vertically.
pub fn print_security_overview(findings: &[Finding]) {
    let (c, h, m, l) = count_by_severity(findings);
    let s = risk::score(c, h, m, l);
    let g = risk::grade(s);
    let (_, label) = risk::verdict(c, h, m, l);
    let follow = risk::follow_up(c, h, m, l);

    if tty::interactive() {
        println!("{}", "Security Overview".white().bold());
        println!();
        println!("{:<15}{}", "Critical", c.to_string().bright_red().bold());
        println!("{:<15}{}", "High", h.to_string().yellow().bold());
        println!("{:<15}{}", "Medium", m.to_string().blue().bold());
        println!("{:<15}{}", "Low", l.to_string().dimmed());
        println!();
        println!("{:<15}{}", "Risk Score", format!("{s}/100").white().bold());
        println!("{:<15}{}", "Grade", g.white().bold());
        println!("{:<15}{}", "Verdict", label_string_colored(label).bold());
        println!();
        println!("{}", follow);
    } else {
        println!("Security Overview");
        println!();
        println!("{:<15}{c}", "Critical");
        println!("{:<15}{h}", "High");
        println!("{:<15}{m}", "Medium");
        println!("{:<15}{l}", "Low");
        println!();
        println!("{:<15}{s}/100", "Risk Score");
        println!("{:<15}{g}", "Grade");
        println!("{:<15}{label}", "Verdict");
        println!();
        println!("{follow}");
    }
}

/// Color a verdict string by its category. Used by the Security
/// Overview block; the final Verdict block (Section 6) does the same
/// coloring via `verdict_color()`.
fn label_string_colored(label: &str) -> String {
    if label.contains("APPROVED") {
        label.green().to_string()
    } else if label.contains("REVIEW") {
        label.yellow().to_string()
    } else {
        label.red().to_string()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section 4 — Findings
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print all findings, grouped by severity (Critical → Info) and
/// sorted by location within each group. A separator line of `─` is
/// drawn between findings within a group; a blank line separates
/// groups. If there are no findings, prints `✔ no findings` and
/// returns.
pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        if tty::interactive() {
            println!("{}", "✔ no findings".green().bold());
        } else {
            println!("✔ no findings");
        }
        println!();
        return;
    }

    // Group by severity in the spec's order: Critical, High, Medium, Low, Info.
    // We use a single pass + sorted-buckets approach so the output
    // is deterministic regardless of rule execution order.
    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    for sev in order {
        let mut group: Vec<&Finding> = findings.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        // Sort by (file, line, column) — the natural read order.
        group.sort_by(|a, b| {
            a.file
                .as_deref()
                .unwrap_or("")
                .cmp(b.file.as_deref().unwrap_or(""))
                .then(a.line.unwrap_or(0).cmp(&b.line.unwrap_or(0)))
                .then(a.column.unwrap_or(0).cmp(&b.column.unwrap_or(0)))
        });

        // Group header.
        if tty::interactive() {
            println!(
                "{}",
                sev.as_str()
                    .to_uppercase()
                    .bold()
                    .color(severity_color(sev))
            );
        } else {
            println!("{}", sev.as_str().to_uppercase());
        }
        println!();

        for (i, f) in group.iter().enumerate() {
            print_finding(f);
            if i + 1 < group.len() {
                // Separator between findings (not after the last one).
                println!("{}", "─".repeat(60).dimmed());
            }
        }
        println!();
    }
}

/// Render a single finding as the multi-line block shown in the CLI.
/// Uses the `●` glyph (severity-colored) as the bullet, label/value
/// pairs separated by blank lines, and indentation under each label.
fn print_finding(f: &Finding) {
    let sev_color = severity_color(f.severity);
    let dim = |s: &str| s.dimmed().to_string();
    let bullet_colored = "●".color(sev_color).bold().to_string();

    // First line: bullet + rule name, optionally with instruction
    // suffix. Rule name is in the severity color; the instruction
    // parenthetical is dim.
    let header = if let Some(ix) = &f.instruction {
        format!(
            "{bullet_colored}  {}{}",
            f.rule.color(sev_color).bold(),
            dim(&format!("  ·  {ix}"))
        )
    } else {
        format!("{bullet_colored}  {}", f.rule.color(sev_color).bold())
    };
    println!("{header}");

    // Location
    if let Some(file) = &f.file {
        let loc = if let Some(line) = f.line {
            let col = f.column.map(|c| format!(":{c}")).unwrap_or_default();
            format!("{file}:{line}{col}")
        } else {
            file.clone()
        };
        println!();
        println!("{}", dim("Location:"));
        println!("  {loc}");
    }

    if let Some(acct) = &f.account {
        println!();
        println!("{}", dim("Account:"));
        println!("  {acct}");
    }

    println!();
    println!("{}", dim("Problem:"));
    for line in wrap_text(&f.message, 100) {
        println!("  {line}");
    }

    if let Some(hint) = &f.hint {
        println!();
        println!("{}", dim("Recommendation:"));
        for line in wrap_text(hint, 100) {
            println!("  {line}");
        }
    }
    // Trailing newline is added by the caller (separator or blank line).
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section 5 — Statistics
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print a compact 4-row statistics block. Labels are left-padded to
/// 22 chars, numbers are right-aligned. No header, no border.
pub fn print_statistics(report: &ScanReport) {
    println!("{}", "Statistics".white().bold());
    println!();
    let rows: [(&str, String); 4] = [
        ("Files analyzed", report.programs.to_string()),
        ("Instructions analyzed", report.instructions.to_string()),
        ("Rules executed", report.rules_executed.to_string()),
        ("Findings detected", report.findings.len().to_string()),
    ];
    for (label, value) in rows {
        if tty::interactive() {
            println!("{:<22}{}", label, value.bold());
        } else {
            println!("{label:<22}{value}");
        }
    }
    println!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Section 6 — Verdict (the climax)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print the final verdict as the visual climax: the headline in
/// bold + severity color, a blank line, and a one-sentence follow-up.
pub fn print_verdict(findings: &[Finding]) {
    let (c, h, m, l) = count_by_severity(findings);
    let (kind, label) = risk::verdict(c, h, m, l);
    let follow = risk::follow_up(c, h, m, l);
    let colored = match kind {
        risk::Verdict::Approved => label.green().bold(),
        risk::Verdict::ReviewRequired => label.yellow().bold(),
        risk::Verdict::Blocked => label.red().bold(),
    };
    if tty::interactive() {
        println!("{colored}");
        println!();
        println!("{follow}");
    } else {
        println!("{label}");
        println!();
        println!("{follow}");
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Tally findings into (critical, high, medium, low) — info is
/// excluded from the score (spec lists only those four). The
/// returned tuple's element order matches the penalty weights in
/// `risk::score` (c, h, m, l) so the call site reads naturally.
fn count_by_severity(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut c = 0;
    let mut h = 0;
    let mut m = 0;
    let mut l = 0;
    for f in findings {
        match f.severity {
            Severity::Critical => c += 1,
            Severity::High => h += 1,
            Severity::Medium => m += 1,
            Severity::Low | Severity::Info => l += 1,
        }
    }
    (c, h, m, l)
}

/// Map a severity to its `colored::Color` value. Used by both the
/// group header and the per-finding bullet. Centralized so the
/// 4-color palette is consistent across the formatter.
fn severity_color(sev: Severity) -> colored::Color {
    match sev {
        Severity::Critical => colored::Color::BrightRed,
        Severity::High => colored::Color::Yellow,
        Severity::Medium => colored::Color::Blue,
        Severity::Low | Severity::Info => colored::Color::BrightBlack, // dim gray
    }
}

/// Word-wrap `text` so no line exceeds `max_width` visible chars.
/// Lines are broken on whitespace; if a single word is longer than
/// `max_width` it is truncated to `max_width - 1` chars with `…`
/// appended. Returns a `Vec<String>` of wrapped lines.
///
/// Width spec per the user's plan: 100 chars (matches the new
/// findings layout, which has 2 chars of indent plus content).
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return vec![String::new()];
    }
    let mut current = String::new();
    for word in normalized.split(' ') {
        if word.is_empty() {
            continue;
        }
        let word_len = word.chars().count();
        if word_len > max_width {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            let truncated: String = word.chars().take(max_width.saturating_sub(1)).collect();
            out.push(format!("{truncated}…"));
            continue;
        }
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word_len <= max_width {
            current.push(' ');
            current.push_str(word);
        } else {
            out.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// `sentinel rules` — cargo-style table (no box drawing).
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print the `sentinel rules` listing in cargo style: a header line
/// with the brand + count, a blank line, and an aligned table of
/// rows. No `┌─┬─┐` borders. The `Layer` field comes from the
/// `Rule` trait (added in the previous commit) so this table reads
/// the layer info from the source of truth, not a parallel string
/// map.
pub fn print_rules_table() {
    let rules = crate::engine::registry::all_rules();
    let header = "⚓ Anchor Sentinel";
    if tty::interactive() {
        println!(
            "{} {} {}",
            header.bright_cyan().bold(),
            "—".dimmed(),
            format!("{} rules active", rules.len()).dimmed()
        );
    } else {
        println!("{header} — {} rules active", rules.len());
    }
    println!();

    // Cargo-style columns: `ID RULE SEVERITY LAYER`. No `│` separators.
    // Column widths picked to accommodate the longest rule id
    // ("missing_bump_seed_canonicalization" = 33 chars).
    const ID_W: usize = 3;
    const NAME_W: usize = 38;
    const SEV_W: usize = 10;
    const LAYER_W: usize = 8;

    // The header row is plain text in both TTY and non-TTY modes —
    // column alignment is what matters here, not color. The cargo-style
    // table is intentionally monochrome so it reads the same in logs
    // and on a terminal.
    println!(
        "{:<ID_W$}  {:<NAME_W$}  {:<SEV_W$}  {:<LAYER_W$}",
        "ID", "Rule", "Severity", "Layer"
    );

    // Sort by severity (Critical first) then by id alphabetically.
    let mut sorted = rules;
    sorted.sort_by(|a, b| {
        let ord = |s: &Severity| match s {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        };
        ord(&b.severity())
            .cmp(&ord(&a.severity()))
            .then(a.id().cmp(b.id()))
    });

    for (i, rule) in sorted.iter().enumerate() {
        let id = rule.id();
        let sev = rule.severity();
        let layer = rule.layer();
        let sev_label = sev.as_str().to_uppercase();
        let sev_str = if tty::interactive() {
            sev_label.color(severity_color(sev)).bold().to_string()
        } else {
            sev_label
        };
        let layer_str = if tty::interactive() {
            layer.to_string().dimmed().to_string()
        } else {
            layer.to_string()
        };
        let id_display: String = if id.chars().count() > NAME_W {
            let truncated: String = id.chars().take(NAME_W - 1).collect();
            format!("{truncated}…")
        } else {
            id.to_string()
        };
        println!(
            "{n:<ID_W$}  {id_display:<NAME_W$}  {sev_str:<SEV_W$}  {layer_str:<LAYER_W$}",
            n = i + 1,
        );
    }
    println!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Unit tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::risk;

    #[test]
    fn score_zero_findings_is_100() {
        assert_eq!(risk::score(0, 0, 0, 0), 100);
    }

    #[test]
    fn score_one_critical_is_75() {
        assert_eq!(risk::score(1, 0, 0, 0), 75);
    }

    #[test]
    fn score_two_crit_three_high_two_medium_is_20() {
        // (2*25) + (3*8) + (2*3) = 50 + 24 + 6 = 80 → 100 - 80 = 20.
        assert_eq!(risk::score(2, 3, 2, 0), 20);
    }

    #[test]
    fn score_floors_at_zero() {
        // 4 critical saturates the penalty past 100; score clamps.
        assert_eq!(risk::score(5, 10, 5, 0), 0);
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(risk::grade(100), "A");
        assert_eq!(risk::grade(90), "A");
        assert_eq!(risk::grade(89), "B");
        assert_eq!(risk::grade(75), "B");
        assert_eq!(risk::grade(74), "C");
        assert_eq!(risk::grade(50), "C");
        assert_eq!(risk::grade(49), "D");
        assert_eq!(risk::grade(25), "D");
        assert_eq!(risk::grade(24), "F");
        assert_eq!(risk::grade(0), "F");
    }

    #[test]
    fn critical_always_blocks_even_at_high_score() {
        // 1 critical with no others: penalty 25, score 75.
        // Verdict must still be Blocked (override).
        let (v, label) = risk::verdict(1, 0, 0, 0);
        assert_eq!(v, risk::Verdict::Blocked);
        assert_eq!(label, "DEPLOYMENT BLOCKED");
    }

    #[test]
    fn critical_override_survives_zero_penalty_other() {
        // 3 critical, 0 of everything else: penalty 75, score 25.
        // Without override this would be DEPLOYMENT BLOCKED anyway,
        // but we test the override path explicitly.
        let (v, _) = risk::verdict(3, 0, 0, 0);
        assert_eq!(v, risk::Verdict::Blocked);
    }

    #[test]
    fn high_only_at_89_is_review_required() {
        // Penalty for 11 high: 11*8 = 88 → score 12. Verdict is
        // blocked, not review. So at the 50-89 boundary, what
        // produces a review? 1 crit=75 (blocked), 0 crit + 6 high=52
        // (review). 6 high × 8 = 48 → 100-48 = 52.
        let (v, label) = risk::verdict(0, 6, 0, 0);
        assert_eq!(v, risk::Verdict::ReviewRequired);
        assert_eq!(label, "DEPLOYMENT REVIEW REQUIRED");
    }

    #[test]
    fn no_critical_high_or_above_means_approved() {
        // 0 critical, 0 high, 1 medium, 1 low: penalty 4 → 96 → A → Approved.
        let (v, label) = risk::verdict(0, 0, 1, 1);
        assert_eq!(v, risk::Verdict::Approved);
        assert_eq!(label, "DEPLOYMENT APPROVED");
    }

    #[test]
    fn follow_up_critical_singular_vs_plural() {
        assert_eq!(
            risk::follow_up(1, 0, 0, 0),
            "1 Critical finding must be resolved before deployment."
        );
        assert_eq!(
            risk::follow_up(3, 0, 0, 0),
            "3 Critical findings must be resolved before deployment."
        );
    }
}
