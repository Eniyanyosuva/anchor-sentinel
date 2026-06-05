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

// Box width is the total visible width of every box the formatter
// draws — header, finding, summary separator, summary row. 110 chars
// gives enough horizontal breathing room for long file paths and
// `require!(...)` hints without forcing a wrap on typical messages.
const BOX_WIDTH: usize = 110;
const CONTENT_INDENT: usize = 2;
const CONTENT_WIDTH: usize = BOX_WIDTH - 2; // 108 — chars between the two `│`s
const WRAP_WIDTH: usize = CONTENT_WIDTH - CONTENT_INDENT; // 106 — chars after the indent

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
        // Build the brand line at the actual content width, with
        // a single space of padding on either side of the box's `│`.
        // The previous version hardcoded `:<60}` which over-padded
        // for short versions and under-padded (overflowed the right
        // border) for long ones.
        let brand = format!(
            "{} {} {}",
            bright("⚓"),
            white("anchor-sentinel"),
            dim(&format!("v{}", env!("CARGO_PKG_VERSION")))
        );
        let brand_pad = inner.saturating_sub(brand.chars().count() + 2);
        let brand_line = if brand_pad > 0 {
            format!("│ {brand}{} │", " ".repeat(brand_pad))
        } else {
            // Brand string is too long for the box — fall back to a
            // hard wrap on the right border (still pretty).
            format!("│ {brand} │")
        };
        println!("{}", bright(&brand_line));
        let tagline = "Solana smart contract security analyzer";
        let tagline_pad = inner.saturating_sub(tagline.chars().count() + 2);
        let tagline_line = if tagline_pad > 0 {
            format!("│ {tagline}{} │", " ".repeat(tagline_pad))
        } else {
            format!("│ {tagline} │")
        };
        println!("{}", bright(&tagline_line));
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

    // Helper: build a single body line `│  {content}│` padded to
    // exactly `width` chars. Both pipes are colored per severity so
    // the box outline stays consistent. We compute the visible
    // width of `content` (ignoring ANSI escapes) and pad with
    // spaces to the inner width.
    let make_line = |content: String| -> String {
        let visible = visible_width(&content);
        let pad = CONTENT_WIDTH.saturating_sub(visible);
        format!("{side}  {content}{}{side}", " ".repeat(pad))
    };
    // Blank separator line: `│{spaces}│` (no indent).
    let blank = || -> String { format!("{side}{}{side}", " ".repeat(CONTENT_WIDTH)) };

    // First body row: bold rule name with a small ▸ prefix and
    // (instruction) parenthetical. This is the headline of the box.
    if let Some(ix) = &f.instruction {
        let content = format!(
            "{}  {}{}",
            "▸".dimmed(),
            rule_name_color(&f.rule),
            dim_label(&format!(" ({ix})"))
        );
        body.push(make_line(content));
    } else {
        let content = format!("{}  {}", "▸".dimmed(), rule_name_color(&f.rule));
        body.push(make_line(content));
    }
    body.push(blank());

    if let Some(acct) = &f.account {
        let content = format!(
            "{}  {}",
            dim_label(&format!("{:<w$}", "acct", w = label_w)),
            acct
        );
        body.push(make_line(content));
    }
    if let (Some(file), Some(line)) = (&f.file, f.line) {
        let col = f.column.map(|c| format!(":{c}")).unwrap_or_default();
        let content = format!(
            "{}  {}:{line}{col}",
            dim_label(&format!("{:<w$}", "file", w = label_w)),
            file
        );
        body.push(make_line(content));
    }

    body.push(blank());

    // Message: wrap on word boundaries at WRAP_WIDTH (76 chars).
    for (i, seg) in wrap_text(&f.message, WRAP_WIDTH).into_iter().enumerate() {
        // First line gets the standard 2-space indent; continuations
        // also use 2 spaces so they line up with the message text.
        let content = seg;
        body.push(make_line(content));
        let _ = i;
    }

    body.push(blank());
    if let Some(hint) = &f.hint {
        // First hint line has a `▶ ` prefix (2 chars). Continuation
        // lines get the same 2-space indent — they line up with the
        // start of the message, not with the hint text. This is a
        // small alignment compromise but keeps the box visually
        // consistent with messages.
        let wrapped = wrap_text(hint, WRAP_WIDTH.saturating_sub(2));
        for (i, seg) in wrapped.into_iter().enumerate() {
            let content = if i == 0 {
                format!("{} {}", "▶".dimmed(), seg.dimmed())
            } else {
                format!("  {}", seg.dimmed())
            };
            body.push(make_line(content));
        }
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

/// Visible (display) width of a string, counting Unicode chars but
/// ignoring ANSI escape sequences. We need this when padding box
/// lines — the underlying `String` includes the `colored` crate's
/// ANSI codes, so `s.len()` would over-count.
fn visible_width(s: &str) -> usize {
    // Walk through the string char by char, skipping CSI sequences
    // (`\x1b[...m`).
    let mut count = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until we hit a letter (the final byte of a CSI
            // sequence is in `[A-Za-z]`).
            for nc in chars.by_ref() {
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        count += 1;
    }
    count
}

/// Word-wrap `text` so that no line exceeds `max_width` visible chars.
/// Lines are broken on whitespace; if a single word is longer than
/// `max_width` it is truncated to `max_width - 1` chars and `…` is
/// appended. Returns a `Vec<String>` of the wrapped lines (without
/// any leading/trailing padding).
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    // First, normalize whitespace: collapse runs of spaces/tabs to a
    // single space. We want clean word boundaries, not the exact
    // original layout.
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
            // Flush whatever we have so far.
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            // Truncate the long word, appending `…`.
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
        print_rule(BOX_WIDTH, &line);
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
    print_rule(BOX_WIDTH, &warning);

    for (sev, n, label) in order {
        if n == 0 {
            // Show zero-count rows dimmed, so the user sees the full
            // severity spread even when no findings of a given level.
            let (filled, empty) = render_bar(0, total, sev);
            let pct = 0;
            // Fixed 110-char row: ` {label:<11} {n:>4}  {bar}  ({pct:>3}%)`.
            // Visible math: 1 + 11 + 1 + 4 + 2 + 70 + 2 + 6 = 97. Pad
            // with trailing spaces to hit 110.
            let plain = format!(
                " {:<11} {:>4}  {}{}  ({:>3}%)",
                label, n, filled, empty, pct
            );
            let row = if tty::interactive() {
                // Severity-color the label, bold the count (here
                // always 0), dim the rest of the row. The bar
                // segments are already pre-colored by `render_bar`.
                let head = format!(
                    " {}{} {:>4}  ",
                    severity_summary_color(sev, label).bold(),
                    " ".dimmed(),
                    n,
                );
                format!("{head}{}{}  ({:>3}%)", filled, empty, pct)
            } else {
                plain
            };
            println!("{row}");
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
                " {}{} {:>4}  ",
                severity_summary_color(sev, label).bold(),
                " ".dimmed(),
                n,
            )
        } else {
            format!(" {:<11} {:>4}  ", label, n)
        };
        let row = format!("{row_label}{}{}  ({:>3}%)", filled, empty, pct);
        // Animated fill when interactive and not in CI.
        if tty::interactive() && std::env::var("CI").ok().as_deref() != Some("true") && total > 0 {
            // The animated frames re-render the bar with the
            // severity-colored filled portion and dimmed `·` empty
            // portion in place via `\r\x1b[2K`. The helper's
            // final frame is the clean filled bar — no extra
            // re-print, no double render.
            print_animated_bar(&row_label, &filled, total, n, sev, &ColoredString::from(""));
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
    print_rule(BOX_WIDTH, "");
}

/// Returns the `(filled, unfilled)` segments of a 70-char bar with
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
    // 70-char bar — sized to fill the same horizontal space as the
    // finding boxes (110 chars minus a 11-char label, 4-char count, and
    // separators). Filled portion uses block elements (█) for a
    // visually solid look. The unfilled portion uses middle dots
    // (·, U+00B7) — they render cleanly in every monospace font
    // including the default macOS Terminal font, unlike the light
    // shade (░) which can look pixelated on some setups.
    const WIDTH: usize = 70;
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
    _final_colored_unused: &ColoredString,
) {
    // The bar fills left-to-right at 25ms/char. The filled portion
    // is rendered in the row's severity color (red for CRITICAL,
    // yellow for MEDIUM, etc.), the unfilled portion is always
    // dimmed. A bright `▓` shimmer head races 1 cell ahead of
    // the fill to give the animation a sense of motion.
    //
    // Every frame is written in place via `\r\x1b[2K` (carriage
    // return + clear-line) so the user sees a single line that
    // fills up smoothly, not a stack of growing rows. The last
    // iteration is the clean final state (no shimmer) so we
    // never print the bar twice.
    const WIDTH: usize = 70;
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
        // the bar's right edge) so the head visibly leads the
        // fill. On the final iteration (`i == WIDTH`) we suppress
        // the shimmer so the last frame is the clean filled bar.
        let show_shimmer = i < WIDTH;
        let shimmer = if filled < WIDTH { filled } else { WIDTH - 1 };
        let mut bar = String::with_capacity(WIDTH * 3);
        for j in 0..WIDTH {
            let cell = if j < filled {
                color_for("█")
            } else if show_shimmer && j == shimmer && tty::interactive() {
                // Bright white shimmer head — overrides the severity
                // color so it stands out as a moving highlight.
                "▓".bright_white().to_string()
            } else {
                "·".dimmed().to_string()
            };
            bar.push_str(&cell);
        }
        let row = format!("{}{}  ({}%)", label, bar, pct);
        // Write to STDOUT (not stderr) so the bar lives on the
        // same stream as the rest of the summary footer — that
        // way the test snapshots and CI logs see one row, not
        // an interleaved pair. `\r` returns the cursor to col 0
        // of the same line; `\x1b[2K` clears the rest of the
        // line so leftover chars from the previous frame are
        // wiped (e.g. when a frame is shorter than the
        // previous one — the `…` count drops as `i` increases).
        // Per-frame sleep is 8ms — small enough that the full
        // 71-frame sweep over the 70-char bar finishes in well
        // under 600ms total, but long enough to read as motion.
        print!("\r\x1b[2K{row}");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(8));
    }
    // Advance past the bar line so the next severity (or the
    // trailing tips) starts on a fresh row. ONE newline — the
    // last loop frame is already the clean final state, so we
    // never re-print the row.
    println!();
}

/// Helper that returns a `ColoredString` for a given severity.
/// Reserved for future use — the animated bar no longer needs it
/// because the last loop frame is now the clean final state.
#[allow(dead_code)]
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
/// IDL+AST) read from each rule's `layer()` method.
pub fn print_rules_table() {
    // Use the rule instances so we can call `r.layer()` directly —
    // the table reads layer info from the source of truth (the rule
    // file) rather than from a parallel string map.
    let rules = crate::engine::registry::all_rules();
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

    // Fixed column widths so the right border lines up regardless
    // of rule id length. Each cell gets +2 chars of inner padding
    // (one space on each side of the content) via the `┌─┬─┐` etc.
    // table characters.
    //   1 (outer │) + (5+2) (#) + 1 (│) + (45+2) (Rule) + 1 (│)
    //   + (12+2) (Sev) + 1 (│) + (10+2) (Layer) + 1 (outer │) = 85 chars.
    const NUM_W: usize = 5;
    const NAME_W: usize = 45;
    const SEV_W: usize = 12;
    const LAYER_W: usize = 10;

    let line_top = format!(
        "┌{}┬{}┬{}┬{}┐",
        "─".repeat(NUM_W + 2),
        "─".repeat(NAME_W + 2),
        "─".repeat(SEV_W + 2),
        "─".repeat(LAYER_W + 2),
    );
    let line_mid = format!(
        "├{}┼{}┼{}┼{}┤",
        "─".repeat(NUM_W + 2),
        "─".repeat(NAME_W + 2),
        "─".repeat(SEV_W + 2),
        "─".repeat(LAYER_W + 2),
    );
    let line_bot = format!(
        "└{}┴{}┴{}┴{}┘",
        "─".repeat(NUM_W + 2),
        "─".repeat(NAME_W + 2),
        "─".repeat(SEV_W + 2),
        "─".repeat(LAYER_W + 2),
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
        w1 = NUM_W,
        w2 = NAME_W,
        w3 = SEV_W,
        w4 = LAYER_W,
    );
    println!("{mid}");

    // Sort by severity (Critical first) then by id alphabetically.
    let mut sorted = rules;
    sorted.sort_by(|a, b| {
        // Critical=4, High=3, ... Info=0. Reverse: higher severity first.
        let ord = |s: &Severity| match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
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
            severity_summary_color(sev, &sev_label)
        } else {
            sev_label
        };
        // Layer comes from the rule itself, not a string map.
        let layer_str: String = if tty::interactive() {
            layer.to_string().dimmed().to_string()
        } else {
            layer.to_string()
        };
        // Truncate id if it somehow exceeds NAME_W (longest current
        // id is "missing_bump_seed_canonicalization" at 33 chars,
        // well under 45 — defensive only).
        let id_display: String = if id.chars().count() > NAME_W {
            let truncated: String = id.chars().take(NAME_W - 1).collect();
            format!("{truncated}…")
        } else {
            id.to_string()
        };
        println!(
            "│ {:>w1$} │ {:<w2$} │ {:<w3$} │ {:<w4$} │",
            format!("{}", i + 1),
            id_display,
            sev_str,
            layer_str,
            w1 = NUM_W,
            w2 = NAME_W,
            w3 = SEV_W,
            w4 = LAYER_W,
        );
    }
    println!("{bot}");
}
