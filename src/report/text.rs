//! Human-readable CLI output. This is the only place in the codebase
//! that emits ANSI color, Unicode box-drawing, or animated output;
//! `format_findings` returns plain text and is the single entry point
//! used by `main.rs`.
//!
//! All color/animation calls are gated on `tty::interactive()`, so
//! the test suite (which pipes stdout) gets a clean plain-text
//! stream and the snapshot/integration tests don't need to filter
//! ANSI escape codes.

use std::io::Write;
use std::time::Duration;

use colored::*;

use crate::engine::{Finding, Severity};
use crate::report::tty;

const BOX_WIDTH: usize = 76;

/// Print the scan header (anchor logo, project path, rule summary).
/// Returns nothing; writes to stdout. Plain text when not a TTY.
pub fn print_header(project: &str, rule_count: usize) {
    let cyan = |s: &str| s.cyan().bold().to_string();
    let dim = |s: &str| s.dimmed().to_string();
    let white = |s: &str| s.white().bold().to_string();

    if tty::interactive() {
        println!("{}", cyan(&format!("┌{}┐", "─".repeat(BOX_WIDTH - 2))));
        println!(
            "{}",
            cyan(&format!(
                "│ {} {:<60} │",
                white("⚓ anchor-sentinel"),
                dim(&format!("v{}", env!("CARGO_PKG_VERSION")))
            ))
        );
        println!(
            "{}",
            cyan(&format!(
                "│ {:<74} │",
                "Solana smart contract security analyzer"
            ))
        );
        println!("{}", cyan(&format!("└{}┘", "─".repeat(BOX_WIDTH - 2))));
    } else {
        // Plain text: still include the info, just without the box.
        println!("anchor-sentinel v{}", env!("CARGO_PKG_VERSION"));
        println!("Solana smart contract security analyzer");
    }
    println!("Scanning  {}", project);

    // Per-severity counts among the registered rules. Shown as a single
    // dense line — gives the user an at-a-glance feel for "how noisy is
    // this codebase likely to be" before any findings print.
    let rules = crate::engine::registry::list_rule_ids();
    let mut counts = [0usize; 5];
    for (_, sev, _) in &rules {
        match sev {
            Severity::Critical => counts[4] += 1,
            Severity::High => counts[3] += 1,
            Severity::Medium => counts[2] += 1,
            Severity::Low => counts[1] += 1,
            Severity::Info => counts[0] += 1,
        }
    }
    let rules_line = format!(
        "Rules     {} active  ·  {} critical  ·  {} high  ·  {} medium",
        rule_count, counts[4], counts[3], counts[2]
    );
    println!("{}", rules_line);
}

/// Format a single finding as the multi-line block shown in the CLI.
/// The returned String is plain text with ANSI codes when interactive,
/// or no codes when piped.
pub fn format_finding(f: &Finding) -> String {
    format_finding_inner(f, None)
}

fn format_finding_inner(f: &Finding, width_override: Option<usize>) -> String {
    let width = width_override.unwrap_or(BOX_WIDTH);
    // Top border: `┌──…── <SEVERITY> ──┐` with the severity badge
    // hugging the right edge.
    let sev_label = format!(" {} ", f.severity.as_str().to_uppercase());
    let pad = width.saturating_sub(2 + sev_label.chars().count() + 1);
    let top = format!(
        "┌{}{}{}┐",
        "─".repeat(pad),
        severity_color(f.severity, &sev_label),
        "─"
    );
    let bottom = format!("└{}┘", "─".repeat(width - 2));

    // Body rows: pad the label column to 7 so the values line up.
    let label_w = 7usize;
    let dim_label = |s: &str| s.dimmed().to_string();
    let mut body: Vec<String> = Vec::new();

    if let Some(ix) = &f.instruction {
        body.push(format!(
            "│ {}  {}",
            dim_label(&format!("{:<w$}", "rule", w = label_w)),
            rule_name_color(&f.rule)
        ));
        body.push(format!(
            "│ {}  {}",
            dim_label(&format!("{:<w$}", "instr", w = label_w)),
            ix
        ));
    } else {
        body.push(format!(
            "│ {}  {}",
            dim_label(&format!("{:<w$}", "rule", w = label_w)),
            rule_name_color(&f.rule)
        ));
    }

    if let Some(acct) = &f.account {
        body.push(format!(
            "│ {}  {}",
            dim_label(&format!("{:<w$}", "acct", w = label_w)),
            acct
        ));
    }
    if let (Some(file), Some(line)) = (&f.file, f.line) {
        let col = f.column.map(|c| format!(":{c}")).unwrap_or_default();
        body.push(format!(
            "│ {}  {}:{line}{col}",
            dim_label(&format!("{:<w$}", "file", w = label_w)),
            file
        ));
    }

    body.push(String::from("│"));
    body.push(format!("│  {}", f.message));
    body.push(String::from("│"));
    if let Some(hint) = &f.hint {
        body.push(format!("│  {} {}", "▶".dimmed(), hint.dimmed()));
    }
    body.push(bottom.clone());

    let mut out = String::new();
    out.push_str(&top);
    out.push('\n');
    for (i, line) in body.iter().enumerate() {
        out.push_str(line);
        if i + 1 < body.len() {
            out.push('\n');
        }
    }
    out
}

/// Color the rule name cyan-ish so it stands out from the dim labels
/// but doesn't fight the severity color on the top border.
fn rule_name_color(rule: &str) -> String {
    rule.cyan().to_string()
}

fn severity_color(sev: Severity, s: &str) -> String {
    if !tty::interactive() {
        return s.to_string();
    }
    match sev {
        Severity::Critical => s.bright_red().bold().to_string(),
        Severity::High => s.red().bold().to_string(),
        Severity::Medium => s.yellow().bold().to_string(),
        Severity::Low => s.cyan().bold().to_string(),
        Severity::Info => s.white().dimmed().to_string(),
    }
}

fn severity_summary_color(sev: Severity, s: &str) -> String {
    if !tty::interactive() {
        return s.to_string();
    }
    match sev {
        Severity::Critical => s.bright_red().bold().to_string(),
        Severity::High => s.red().bold().to_string(),
        Severity::Medium => s.yellow().bold().to_string(),
        Severity::Low => s.cyan().bold().to_string(),
        Severity::Info => s.white().dimmed().to_string(),
    }
}

/// Print all findings, with a brief per-finding delay between them
/// when interactive. Returns the formatted text for callers that want
/// to capture it (e.g. tests).
pub fn format_findings(findings: &[Finding]) -> String {
    if findings.is_empty() {
        let text = "✔ no findings".to_string();
        if tty::interactive() {
            println!("{}", text.green());
        } else {
            println!("{text}");
        }
        return text;
    }
    let mut out = Vec::new();
    for (i, f) in findings.iter().enumerate() {
        let block = format_finding(f);
        if tty::interactive()
            && findings.len() <= 20
            && std::env::var("CI").ok().as_deref() != Some("true")
        {
            // Reveal animation: print the block, then pause briefly so
            // the user can read each one. 35ms is short enough to feel
            // snappy on 5–10 findings and long enough to register
            // visually on a fast screen.
            print!("{block}");
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_millis(35));
            if i + 1 < findings.len() {
                println!();
            }
        } else {
            // Piped / CI / too many findings: print the whole batch
            // up front. We push into `out` and let the caller print
            // once at the end so the test snapshot stays byte-stable.
            out.push(block);
        }
    }
    if !out.is_empty() {
        let joined = out.join("\n\n");
        println!("{joined}");
    }
    // Always return a plain version for tests / programmatic callers.
    let plain: Vec<String> = findings.iter().map(format_finding).collect();
    plain.join("\n")
}

/// Print the summary footer with the animated progress bars.
/// Honors `tty::interactive()` and `CI` to skip animation.
pub fn print_summary_footer(findings: &[Finding], elapsed: Duration) {
    let total = findings.len();
    let rule_count = crate::engine::registry::list_rule_ids().len();

    if total == 0 {
        let line = format!(
            " ✓  No issues found  ·  scanned in {:.2}s  ·  {} rules  ·  clean",
            elapsed.as_secs_f64(),
            rule_count
        );
        let line = if tty::interactive() {
            line.bright_green().bold().to_string()
        } else {
            line
        };
        print_rule(80, &line);
        return;
    }

    // Per-severity counts (Critical → Info).
    let mut counts = [0usize; 5];
    for f in findings {
        match f.severity {
            Severity::Info => counts[0] += 1,
            Severity::Low => counts[1] += 1,
            Severity::Medium => counts[2] += 1,
            Severity::High => counts[3] += 1,
            Severity::Critical => counts[4] += 1,
        }
    }
    // Render order: CRITICAL first, then HIGH, MEDIUM, LOW. The
    // array below is the source of truth for both iteration and
    // label rendering.
    let order = [
        (Severity::Critical, counts[4], "CRITICAL"),
        (Severity::High, counts[3], "HIGH"),
        (Severity::Medium, counts[2], "MEDIUM"),
        (Severity::Low, counts[1], "LOW"),
    ];

    let warning = format!(
        " ⚠  {} issues found  ·  scanned in {:.2}s",
        total,
        elapsed.as_secs_f64()
    );
    print_rule(80, &warning);

    for (sev, n, label) in order {
        if n == 0 {
            // Show zero-count rows dimmed, so the user sees the full
            // severity spread even when no findings of a given level.
            let row = format!(" {:<8} 0  {}", label, render_bar(0, total, false));
            let row = if tty::interactive() {
                severity_summary_color(sev, &row).dimmed().to_string()
            } else {
                row
            };
            println!("{}", row);
            continue;
        }
        let pct = n.checked_mul(100).and_then(|x| x.checked_div(total)).unwrap_or(0);
        let row_label = format!(" {:<8} {:>2}  ", label, n);
        let bar = render_bar(n, total, true);
        let row = format!("{}{}  ({}%)", row_label, bar, pct);
        let colored: String = if tty::interactive() {
            severity_summary_color(sev, &row)
        } else {
            row.clone()
        };
        // Animated fill when interactive and not in CI.
        if tty::interactive() && std::env::var("CI").ok().as_deref() != Some("true") && total > 0 {
            // We pass a `ColoredString` so the helper can render the
            // final line with the severity color. The animated
            // frames themselves render in dim white (see helper).
            let cs = severity_color_to_colored(sev, &row);
            print_animated_bar(&row_label, &bar, total, n, &cs);
        } else {
            println!("{}", colored);
        }
    }
    println!();
    let tip1 = "→ Run with --format sarif to upload to GitHub Code Scanning.";
    let tip2 = "→ Run with --ignore <rule> to suppress a specific rule.";
    if tty::interactive() {
        println!("{}", tip1.dimmed());
        println!("{}", tip2.dimmed());
    } else {
        println!("{tip1}");
        println!("{tip2}");
    }
    print_rule(80, "");
}

fn render_bar(n: usize, total: usize, _interactive: bool) -> String {
    // 30-char bar. Filled portion uses block elements for a more
    // visually solid look than ASCII `-`/`=`. The unfilled portion
    // uses light shades so it still shows structure.
    const WIDTH: usize = 30;
    if total == 0 {
        return "░".repeat(WIDTH);
    }
    let filled = (n * WIDTH) / total;
    let empty = WIDTH - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn print_animated_bar(
    label: &str,
    _bar_unused: &str,
    total: usize,
    n: usize,
    final_colored: &ColoredString,
) {
    // We re-render the bar progressively rather than parsing the
    // prebuilt one. The label and percentage stay constant; only the
    // bar's filled/empty split changes. We sleep 25ms per char of
    // the bar for a smooth fill animation.
    const WIDTH: usize = 30;
    let mut line = String::new();
    line.push_str(label);
    let pct = n.checked_mul(100).and_then(|x| x.checked_div(total)).unwrap_or(0);
    for i in 0..=WIDTH {
        let filled = (n * i) / WIDTH.max(1);
        let empty = WIDTH - filled;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
        // Re-print the line in place using ANSI clear-line + CR.
        let row = format!("{}{}  ({}%)", label, bar, pct);
        eprint!("\r\x1b[2K{row}");
        let _ = std::io::stderr().flush();
        std::thread::sleep(Duration::from_millis(25));
    }
    // Final clean line, with the severity color applied.
    println!();
    eprint!("\r\x1b[2K");
    println!("{}", final_colored);
    // Note: the bar uses a yellow/cyan/etc. color applied per severity;
    // the animated frames above intentionally render in the default
    // (dim white) so the animation is visible against any background,
    // then the final line switches to the severity color.
    let _ = line; // suppress unused warning
}

/// Helper that returns a `ColoredString` for a given severity, used by
/// the animated bar where the helper's signature wants `ColoredString`
/// rather than `String`.
fn severity_color_to_colored(sev: Severity, s: &str) -> ColoredString {
    if !tty::interactive() {
        return ColoredString::from(s);
    }
    match sev {
        Severity::Critical => s.bright_red().bold(),
        Severity::High => s.red().bold(),
        Severity::Medium => s.yellow().bold(),
        Severity::Low => s.cyan().bold(),
        Severity::Info => s.white().dimmed(),
    }
}

fn print_rule(width: usize, line: &str) {
    if line.is_empty() {
        let bar = "━".repeat(width);
        let bar = if tty::interactive() {
            bar.dimmed().to_string()
        } else {
            bar
        };
        println!("{bar}");
    } else {
        let bar = "━".repeat(width);
        let bar = if tty::interactive() {
            bar.dimmed().to_string()
        } else {
            bar
        };
        let line = if tty::interactive() {
            line.yellow().to_string()
        } else {
            line.to_string()
        };
        println!("{bar}");
        println!("{line}");
        println!("{bar}");
    }
}

/// Print the `sentinel rules` table. Renders a polished table with
/// the rule id, severity (colored), and source layer (IDL, AST, or
/// IDL+AST) derived from the rule description.
pub fn print_rules_table() {
    let rules = crate::engine::registry::list_rule_ids();
    let header = "⚓ anchor-sentinel";
    if tty::interactive() {
        println!(
            "{} {} {}",
            header.bright_white().bold(),
            "—".dimmed(),
            format!("{} rules active", rules.len()).dimmed()
        );
    } else {
        println!("{header} — {} rules active", rules.len());
    }
    println!();

    // Pad columns to the longest rule name + a few spaces.
    let name_w = rules.iter().map(|(id, _, _)| id.len()).max().unwrap_or(20);
    let sev_w = "SEVERITY".len();
    let layer_w = "LAYER".len();

    let rule_num_w = 3; // "  1" .. " 99"

    let line_top = format!(
        "┌{}┬{}┬{}┬{}┐",
        "─".repeat(rule_num_w + 2),
        "─".repeat(name_w + 2),
        "─".repeat(sev_w + 2),
        "─".repeat(layer_w + 2),
    );
    let line_mid = format!(
        "├{}┼{}┼{}┼{}┤",
        "─".repeat(rule_num_w + 2),
        "─".repeat(name_w + 2),
        "─".repeat(sev_w + 2),
        "─".repeat(layer_w + 2),
    );
    let line_bot = format!(
        "└{}┴{}┴{}┴{}┘",
        "─".repeat(rule_num_w + 2),
        "─".repeat(name_w + 2),
        "─".repeat(sev_w + 2),
        "─".repeat(layer_w + 2),
    );

    let border = if tty::interactive() {
        line_top.cyan().bold().to_string()
    } else {
        line_top
    };
    let mid = if tty::interactive() {
        line_mid.cyan().dimmed().to_string()
    } else {
        line_mid
    };
    let bot = if tty::interactive() {
        line_bot.cyan().bold().to_string()
    } else {
        line_bot
    };

    println!("{border}");
    println!(
        "│ {:>w1$} │ {:<w2$} │ {:<w3$} │ {:<w4$} │",
        "#",
        "Rule",
        "Severity",
        "Layer",
        w1 = rule_num_w,
        w2 = name_w,
        w3 = sev_w,
        w4 = layer_w,
    );
    println!("{mid}");

    // Sort by severity (Critical first) then by id alphabetically.
    let mut sorted: Vec<_> = rules.into_iter().collect();
    sorted.sort_by(|(a_id, a_sev, _), (b_id, b_sev, _)| {
        // Critical=4, High=3, ... Info=0. Reverse: higher severity first.
        let ord = |s: &Severity| match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        };
        ord(b_sev).cmp(&ord(a_sev)).then(a_id.cmp(b_id))
    });

    for (i, (id, sev, _desc)) in sorted.iter().enumerate() {
        let row_color = if i % 2 == 1 && tty::interactive() {
            // Alternating dim row for readability on wide tables.
            // We can't easily dim the row's own components, so we
            // wrap them in a no-op ASCII string. Future: use owo-colors
            // for row-level styling. For now this is a no-op marker.
            "".to_string()
        } else {
            "".to_string()
        };
        let _ = row_color;
        let sev_label = sev.as_str().to_uppercase();
        let sev_str = if tty::interactive() {
            severity_summary_color(*sev, &sev_label)
        } else {
            sev_label
        };
        // Derive layer from the rule id (cheap heuristic; rules are
        // documented in the README and the desc). Layer is a
        // user-facing simplification: "AST" for AST-only rules,
        // "IDL" for IDL-only, "IDL+AST" for both.
        let layer = layer_for_rule(id);
        let layer_str: String = if tty::interactive() {
            layer.dimmed().to_string()
        } else {
            layer.to_string()
        };
        println!(
            "│ {:>w1$} │ {:<w2$} │ {:<w3$} │ {:<w4$} │",
            format!("{}", i + 1),
            id,
            sev_str,
            layer_str,
            w1 = rule_num_w,
            w2 = name_w,
            w3 = sev_w,
            w4 = layer_w,
        );
    }
    println!("{bot}");
}

/// Hard-coded layer mapping. Kept here rather than in each rule so the
/// table doesn't have to know about the `Rule` trait.
fn layer_for_rule(id: &str) -> &'static str {
    match id {
        "missing_signer"
        | "missing_ownership"
        | "missing_mut"
        | "pda_misconfig"
        | "duplicate_mutable_accounts"
        | "lamports_drain"
        | "unchecked_balance_flow" => "IDL+AST",
        "missing_balance_check"
        | "missing_bump_seed_canonicalization"
        | "unsafe_arithmetic"
        | "missing_close_authority"
        | "cpi_signer_seed_validation"
        | "integer_cast_truncation" => "AST",
        _ => "—",
    }
}
