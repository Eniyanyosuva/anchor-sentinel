//! `missing_bump_seed_canonicalization` — flags PDA accounts whose `bump`
//! constraint is set to a non-canonical value.
//!
//! In Anchor, the secure way to pin a PDA bump is one of:
//!   1. `#[account(seeds = [...], bump)]` — implicit canonical bump
//!   2. `#[account(seeds = [...], bump = ctx.bumps.field)]` — explicit canonical
//!   3. `bump = <field>` where `<field>` is a `u8` argument — ANCHOR DERIVES
//!      the canonical bump from seeds at runtime and stores it in the field.
//!
//! The dangerous pattern is:
//!   - `bump = some_variable` where the variable is NOT a bumps-field AND
//!     NOT derived from the seeds. This binds the bump to a user-controlled
//!     value, enabling the classic PDA canonicalization bypass.
//!
//! Unlike `pda_misconfig` which focuses on missing `bump` constraints and
//! the specific `bump = bump` (plain-ident) trap, this rule catches the
//! broader class: any non-canonical bump expression.

use anyhow::Result;
use std::collections::HashSet;

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct MissingBumpSeedCanonicalization;

impl Rule for MissingBumpSeedCanonicalization {
    fn id(&self) -> &'static str {
        "missing_bump_seed_canonicalization"
    }
    fn description(&self) -> &'static str {
        "PDA bump constraint uses a non-canonical value instead of `ctx.bumps`"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn layer(&self) -> Layer {
        Layer::Ast
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let hint_index = field_hint_index(ctx);
        let mut seen: HashSet<String> = HashSet::new();

        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField {
                field_name,
                constraints,
                ..
            } = &hint.kind
            {
                for constraint in constraints {
                    // Find all `bump = <expr>` patterns (not bare `bump` or `bumps`).
                    if let Some(bump_expr) = extract_bump_expression(constraint) {
                        if is_non_canonical_bump(bump_expr) && !seen.contains(field_name) {
                            seen.insert(field_name.clone());
                            let mut b = Finding::builder(
                                self.id(),
                                self.severity(),
                                format!(
                                    "Account `{field_name}` pins `bump = {bump_expr}` — this \
                                     binds the PDA derivation to a non-canonical value. An attacker \
                                     can pass a different bump and access a separate PDA account."
                                ),
                            )
                            .program(&ctx.ir.name)
                            .account(field_name)
                            .hint(
                                "Use the bare `bump` identifier (which derives the canonical bump \
                                 from seeds), or `bump = ctx.bumps.{field_name}` to use the \
                                 framework-managed canonical bump.",
                            );
                            if let Some(h) = hint_index.get(field_name) {
                                b = h.location().stamp(b);
                            }
                            out.push(b.build());
                        }
                    }
                }
            }
        }

        Ok(out)
    }
}

/// Extract the RHS expression from a `bump = <expr>` constraint.
/// Returns `None` for bare `bump` or `bumps` (canonical forms).
fn extract_bump_expression(constraint: &str) -> Option<&str> {
    let idx = constraint.find("bump")?;
    let after = &constraint[idx + "bump".len()..];
    // `bumps` (plural — `bumps = ...` or `bump_seed`) is not a bump constraint.
    if after.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
        return None;
    }
    // Bare `bump` (followed by `,` or end) is canonical — skip.
    if after.starts_with(',') || after.trim().is_empty() {
        return None;
    }
    // `bump = <expr>` — extract the expression.
    let eq_idx = after.find('=')?;
    let expr = after[eq_idx + 1..]
        .trim_start()
        .trim_end_matches(',')
        .trim();
    if expr.is_empty() {
        return None;
    }
    Some(expr)
}

/// Returns `true` if the bump expression is non-canonical (user-controlled
/// or derived from an untrusted source).
fn is_non_canonical_bump(expr: &str) -> bool {
    // Canonical forms — do NOT flag:
    //   `bump = ctx.bumps.foo` — framework-managed canonical bump
    //   `bump = bumps.foo`    — shorthand for ctx.bumps
    if expr.starts_with("ctx.bumps") || expr.starts_with("bumps.") {
        return false;
    }
    // Anything else is non-canonical:
    //   `bump` (bare ident from a function arg),
    //   `args.bump`, `user_bump`, `seed_bump`, `params.bump`, etc.
    true
}
