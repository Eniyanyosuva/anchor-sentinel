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
    let dim = |s: &str| s.dimmed().to_string();
    let white = |s: &str| s.white().bold().to_string();
    let bright = |s: &str| s.bright_cyan().bold().to_string();

    if tty::interactive() {
        // Rounded box: ╭──…──╮ / │ / ╰──…──╯ gives a softer, more
        // modern look than the squarer ┌/└ variants. The top border
        // gets a small ⚓ glyph centered as a "logo mark" — subtle
        // but immediately recognizable.
        let inner = BOX_WIDTH - 2;
        let top = format!("╭{}╮", "─".repeat(inner));
        let bot = format!("╰{}╯", "─".repeat(inner));
        println!("{}", bright(&top));
        println!(
            "{}",
            bright(&format!(
                "│ {} {:<60} │",
                bright("⚓"),
                format!(
                    "{} {}",
                    white("anchor-sentinel"),
                    dim(&format!("v{}", env!("CARGO_PKG_VERSION")))
                )
            ))
        );
        println!(
            "{}",
            bright(&format!(
                "│ {:<width$} │",
                "Solana smart contract security analyzer",
                width = inner - 2
            ))
        );
        println!("{}", bright(&bot));
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
    // Top border: `╭──…── <SEVERITY> ──╮` with the severity badge
    // hugging the right edge. Rounded corners give a softer feel.
    // The border chars (─, ╭, ╮, ╰, ╯, │) are all colored per
    // severity so the box's outline communicates the finding's
    // urgency at a glance.
    let sev_label = format!(" {} ", f.severity.as_str().to_uppercase());
    let pad = width.saturating_sub(2 + sev_label.chars().count() + 1);
    let (top, bottom, side) = severity_border(f.severity, width, pad, &sev_label);
    // Body rows: pad the label column to 7 so the values line up.

    // Body rows: pad the label column to 7 so the values line up.
    let label_w = 7usize;
    let dim_label = |s: &str| s.dimmed().to_string();
    let mut body: Vec<String> = Vec::new();

    // First body row: bold rule name with a small ▸ prefix and
    // (instruction) parenthetical. This is the headline of the box.
    if let Some(ix) = &f.instruction {
        body.push(format!(
            "{side} {}  {} {}",
            "▸".dimmed(),
            rule_name_color(&f.rule),
            dim_label(&format!("({ix})"))
        ));
    } else {
        body.push(format!(
            "{side} {}  {}",
            "▸".dimmed(),
            rule_name_color(&f.rule)
        ));
    }
    body.push(side.clone());

    if let Some(acct) = &f.account {
        body.push(format!(
            "{side} {}  {}",
            dim_label(&format!("{:<w$}", "acct", w = label_w)),
            acct
        ));
    }
    if let (Some(file), Some(line)) = (&f.file, f.line) {
        let col = f.column.map(|c| format!(":{c}")).unwrap_or_default();
        body.push(format!(
            "{side} {}  {}:{line}{col}",
            dim_label(&format!("{:<w$}", "file", w = label_w)),
            file
        ));
    }

    body.push(side.clone());
    body.push(format!("{side}  {}", f.message));
    body.push(side.clone());
    if let Some(hint) = &f.hint {
        body.push(format!("{side}  {} {}", "▶".dimmed(), hint.dimmed()));
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

/// Build the top/bottom borders and the side character for a
/// finding box, all colored per severity. The side is reused for
/// every body row, so we pre-compute it once and pass it down.
fn severity_border(
    sev: Severity,
    width: usize,
    pad: usize,
    sev_label: &str,
) -> (String, String, String) {
    // Pick a single color for the entire border. CRITICAL/HIGH
    // share red (the convention: red = urgent, yellow = caution,
    // cyan = info).
    let border_colored = |s: &str| -> String {
        if !tty::interactive() {
            return s.to_string();
        }
        match sev {
            Severity::Critical => s.bright_red(),
            Severity::High => s.red(),
            Severity::Medium => s.yellow(),
            Severity::Low => s.cyan(),
            Severity::Info => s.cyan(),
        }
        .to_string()
    };
    let h = border_colored("─");
    let h_dash_count = h.chars().count();
    // `pad` is the *display* width of the leading dashes (in
    // characters). Because the colored crate wraps each `─` in
    // ANSI codes, the underlying string is longer than `pad`
    // chars. We need exactly `pad` rendered `─`s on the left.
    let top = format!(
        "╭{}{}{}╮",
        (0..pad).map(|_| h.clone()).collect::<String>(),
        severity_color(sev, sev_label),
        (0..1).map(|_| h.clone()).collect::<String>()
    );
    let bottom = format!(
        "╰{}╯",
        (0..(width - 2)).map(|_| h.clone()).collect::<String>()
    );
    let side = border_colored("│");
    // (We don't actually use h_dash_count, but the variable
    // documents what the colored "─" string actually represents.)
    let _ = h_dash_count;
    (top, bottom, side)
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
            let (filled, empty) = render_bar(0, total, sev);
            let row = format!(" {:<8}    0  {}{}", label, filled, empty);
            let row = if tty::interactive() {
                // Severity-color the label, bold the count (here
                // always 0), dim the rest of the row.
                format!(
                    " {}{}  0  {}{}",
                    severity_summary_color(sev, label).bold(),
                    "    ".dimmed(),
                    filled,
                    empty,
                )
            } else {
                row
            };
            println!("{}", row);
            continue;
        }
        let pct = n
            .checked_mul(100)
            .and_then(|x| x.checked_div(total))
            .unwrap_or(0);
        // Build the row in two halves: the labeled side (severity
        // + count) and the bar (per-severity filled + dimmed empty).
        // The bar segments are already pre-colored by render_bar,
        // so we just concatenate.
        let (filled, empty) = render_bar(n, total, sev);
        // `row_label` is the static prefix that the animation
        // re-prints before each bar frame. The full row is built
        // below in the per-TTY path; the static path mirrors the
        // plain text format so piped output is byte-stable.
        let row_label = if tty::interactive() {
            format!(
                " {}{} {}{}  ",
                severity_summary_color(sev, label).bold(),
                " ".dimmed(),
                format!("{}", n).bold(),
                " ".dimmed(),
            )
        } else {
            format!(" {:<8} {:>2}  ", label, n)
        };
        let row = format!("{}{}{}  ({}%)", row_label, filled, empty, pct);
        // Animated fill when interactive and not in CI.
        if tty::interactive() && std::env::var("CI").ok().as_deref() != Some("true") && total > 0 {
            // The animated frames re-render the bar with the
            // severity-colored filled portion and dimmed `·` empty
            // portion. The final clean line is the row we just
            // built, with the label re-colored via the severity
            // color so the helper can print it as a `ColoredString`.
            let final_colored: ColoredString = severity_color_to_colored(sev, &row);
            print_animated_bar(&row_label, &filled, total, n, sev, &final_colored);
        } else {
            println!("{row}");
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

/// Returns the `(filled, unfilled)` segments of a 30-char bar with
/// per-severity coloring on the filled portion and a dimmed
/// (always-gray) unfilled portion. The two segments are returned
/// as a tuple so the caller can `format!` them into the row
/// without losing the per-segment ANSI sequences.
///
/// `n` is the count, `total` is the total finding count.
/// `sev` is the row's severity; we use it only for the filled color.
/// `interactive` gates the colored crate — when piped or CI, the
/// segments come back as plain strings.
fn render_bar(n: usize, total: usize, sev: Severity) -> (String, String) {
    // 30-char bar. Filled portion uses block elements (█) for a
    // visually solid look. The unfilled portion uses middle dots
    // (·, U+00B7) — they render cleanly in every monospace font
    // including the default macOS Terminal font, unlike the light
    // shade (░) which can look pixelated on some setups.
    const WIDTH: usize = 30;
    let filled = n
        .checked_mul(WIDTH)
        .and_then(|x| x.checked_div(total))
        .unwrap_or(0);

    // Build the two raw segments first.
    let raw_filled = "█".repeat(filled);
    let raw_empty = "·".repeat(WIDTH - filled);

    if tty::interactive() {
        // Per-severity color for the filled portion. The unfilled
        // portion is always dimmed so it reads as "background"
        // against the severity-colored fill.
        let colored_filled = match sev {
            Severity::Critical => raw_filled.bright_red(),
            Severity::High => raw_filled.red(),
            Severity::Medium => raw_filled.yellow(),
            Severity::Low => raw_filled.cyan(),
            Severity::Info => raw_filled.white(),
        };
        (colored_filled.to_string(), raw_empty.dimmed().to_string())
    } else {
        (raw_filled, raw_empty)
    }
}

fn print_animated_bar(
    label: &str,
    _bar_unused: &str,
    total: usize,
    n: usize,
    sev: Severity,
    final_colored: &ColoredString,
) {
    // The bar fills left-to-right at 25ms/char. The filled portion
    // is rendered in the row's severity color (red for CRITICAL,
    // yellow for MEDIUM, etc.), the unfilled portion is always
    // dimmed. A bright `▓` shimmer head races 1 cell ahead of
    // the fill to give the animation a sense of motion.
    const WIDTH: usize = 30;
    let pct = n
        .checked_mul(100)
        .and_then(|x| x.checked_div(total))
        .unwrap_or(0);
    // Per-severity color function, applied to the filled segment
    // of every frame.
    let color_for = |s: &str| -> String {
        if !tty::interactive() {
            return s.to_string();
        }
        match sev {
            Severity::Critical => s.bright_red(),
            Severity::High => s.red(),
            Severity::Medium => s.yellow(),
            Severity::Low => s.cyan(),
            Severity::Info => s.white(),
        }
        .to_string()
    };
    for i in 0..=WIDTH {
        let filled = n
            .checked_mul(i)
            .and_then(|x| x.checked_div(WIDTH.max(1)))
            .unwrap_or(0);
        // The leading edge of the bar: a brighter "shimmer" block.
        // Renders 1 char ahead of the filled portion (clamped at
        // the bar's right edge) so the head visibly leads the fill.
        let shimmer = if filled < WIDTH { filled } else { WIDTH - 1 };
        let mut bar = String::with_capacity(WIDTH * 3);
        for j in 0..WIDTH {
            let cell = if j < filled {
                color_for("█")
            } else if j == shimmer && tty::interactive() {
                // Bright white shimmer head — overrides the severity
                // color so it stands out as a moving highlight.
                "▓".bright_white().to_string()
            } else {
                "·".dimmed().to_string()
            };
            bar.push_str(&cell);
        }
        let row = format!("{}{}  ({}%)", label, bar, pct);
        eprint!("\r\x1b[2K{row}");
        let _ = std::io::stderr().flush();
        std::thread::sleep(Duration::from_millis(25));
    }
    // Final clean line, with the severity color applied.
    println!();
    eprint!("\r\x1b[2K");
    println!("{}", final_colored);
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
