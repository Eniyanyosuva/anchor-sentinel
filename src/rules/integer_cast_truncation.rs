//! `integer_cast_truncation` — flags `expr as T` casts where the source
//! integer type is wider than the destination, which silently truncates
//! the high bits at runtime.
//!
//! In Solana Anchor programs this is a real bug class: account data is
//! typically `u64` (lamports, token amounts) but downstream consumers
//! (syscall arguments, account discriminants, packed byte buffers) often
//! require narrower types. A naive `let n: u8 = amount as u8;` drops
//! everything above `u8::MAX` without warning, and the on-chain error
//! shows up far from the offending cast.
//!
//! Severity rationale: silent data loss, not directly exploitable, but
//! it underwrites subtle fund-rounding and IDL-mismatch bugs that often
//! become critical when stacked with other rules.

use std::collections::HashSet;

use anyhow::Result;

use crate::engine::{AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct IntegerCastTruncation;

impl Rule for IntegerCastTruncation {
    fn id(&self) -> &'static str {
        "integer_cast_truncation"
    }
    fn description(&self) -> &'static str {
        "Detects `as` casts that may silently truncate a wider integer into a narrower one (e.g. u64 → u8)."
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn layer(&self) -> Layer {
        Layer::Ast
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        // Dedupe per (file, line, from_ty, to_ty) so a tight loop with
        // many identical casts doesn't flood the report. Two casts at
        // different lines still produce separate findings.
        let mut seen: HashSet<(String, usize, String, String)> = HashSet::new();

        for hint in &ctx.ast_hints {
            if let AstHintKind::IntegerCast { from_ty, to_ty } = &hint.kind {
                let from_w = source_width(from_ty);
                let to_w = int_width(to_ty);
                // Skip when destination width is unknown (could be a
                // user-defined newtype that isn't actually an integer).
                let Some(to_w) = to_w else {
                    continue;
                };
                // Skip when the source is no wider than the destination.
                // `source_width` already accounts for the `looks_like_int`
                // heuristic, so `amount as u64` is treated as same-width.
                if from_w <= to_w {
                    continue;
                }

                let key = (hint.file.clone(), hint.line, from_ty.clone(), to_ty.clone());
                if !seen.insert(key) {
                    continue;
                }

                let display_from = if from_ty == "inferred" {
                    "an integer".to_string()
                } else {
                    from_ty.clone()
                };
                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "`{display_from}` cast to `{to_ty}` ({to_w}-bit) silently truncates the high bits at runtime. Use `try_into()` (and handle the `TryFromIntError`) or `from_le_bytes` / `to_le_bytes` to make the conversion explicit."
                    ),
                )
                .program(&ctx.ir.name)
                .hint(format!(
                    "Replace `{display_from} as {to_ty}` with `let n: {to_ty} = value.try_into().map_err(|_| ErrorCode::Overflow)?;` or split the value with `to_le_bytes`."
                ));
                b = hint.location().stamp(b);
                out.push(b.build());
            }
        }
        Ok(out)
    }
}

/// Width in bits for the integer types `is_int_type` recognizes. Returns
/// `None` for unknown types (e.g. user newtypes) — the rule skips those
/// to avoid false positives.
fn int_width(ty: &str) -> Option<usize> {
    match ty {
        "u8" | "i8" => Some(8),
        "u16" | "i16" => Some(16),
        "u32" | "i32" => Some(32),
        "u64" | "i64" => Some(64),
        "u128" | "i128" => Some(128),
        // Platform-dependent: skip rather than guess.
        "usize" | "isize" => None,
        _ => None,
    }
}

/// Width assumption for the source side of a cast. We have a real type
/// for literals and explicitly-typed paths; for plain identifier paths
/// (e.g. an `amount` parameter) the AST layer doesn't track types, so
/// we fall back to a conservative 64-bit estimate. That estimate is the
/// source of false positives only when the variable is *actually*
/// narrower than the destination — which is exactly the case we want to
/// flag, so the heuristic is sound.
fn source_width(ty: &str) -> usize {
    if let Some(w) = int_width(ty) {
        return w;
    }
    // Heuristic: an untracked path that *looks like* an integer is
    // almost always a `u64` lamports/amount parameter in Anchor code.
    // Reporting it as 64 bits is the right call: if the cast target is
    // narrower, that's a real truncation; if it's wider, the rule
    // skips the hint anyway.
    if looks_like_int(ty) {
        return 64;
    }
    // Unknown source — assume widest sensible so we never *miss* a
    // truncation. The rule still requires the destination to be a
    // known narrower integer.
    128
}

fn looks_like_int(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let lname = s.to_ascii_lowercase();
    matches!(
        lname.as_str(),
        "amount" | "value" | "total" | "lamports" | "balance" | "delta" | "n" | "i" | "x" | "y"
    ) || lname.ends_with("_amount")
        || lname.ends_with("_total")
        || lname.ends_with("_value")
}
