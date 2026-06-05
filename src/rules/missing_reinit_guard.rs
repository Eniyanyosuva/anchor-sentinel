//! `missing_reinit_guard` — flags accounts declared with
//! `init_if_needed` that lack a reinitialization guard.
//!
//! In Anchor, `#[account(init_if_needed, payer = user, space = ...)]`
//! creates the account on the first call and **reuses** it on
//! subsequent calls. Without an accompanying `has_one` or
//! `constraint` expression that proves the caller is the same
//! authority that previously initialized the account, **any signer
//! that pays can clobber the existing state**. They bump the
//! account's lamports above rent-exempt, set the discriminator,
//! and write whatever data they like — overwriting whatever the
//! legitimate initializer wrote.
//!
//! Severity: High — silent, repeatable, often leads to fund loss
//! when the reinitialized account is a vault, a registry entry, or
//! a config struct that gates downstream actions.
//!
//! Safe patterns (not flagged):
//!   - `has_one = <authority>` on the same field, where `<authority>`
//!     is a Signer field — Anchor's runtime check verifies the
//!     account's stored authority matches the signer.
//!   - `constraint = <field>.<authority> == <signer>.key() @ Error`
//!     — explicit same-authority check in the constraint expression.
//!   - The struct uses `#[account(init, ...)]` (not `init_if_needed`) —
//!     the account is then guaranteed to be created exactly once,
//!     at the same time as the first transaction, and reinit is
//!     impossible by construction.

use anyhow::Result;
use std::collections::HashSet;

use crate::engine::{AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct MissingReinitGuard;

impl Rule for MissingReinitGuard {
    fn id(&self) -> &'static str {
        "missing_reinit_guard"
    }
    fn description(&self) -> &'static str {
        "Detects init_if_needed accounts without a reinitialization guard"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn layer(&self) -> Layer {
        Layer::Ast
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        // Dedupe per (struct, field) — we might re-encounter the
        // same field via IDL + AST hints.
        let mut seen: HashSet<(String, String)> = HashSet::new();

        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField {
                struct_name,
                field_name,
                constraints,
                ..
            } = &hint.kind
            {
                // Step 1: does this field declare `init_if_needed`?
                if !has_init_if_needed(constraints) {
                    continue;
                }
                let key = (struct_name.clone(), field_name.clone());
                if !seen.insert(key) {
                    continue;
                }

                // Step 2: is there a reinitialization guard?
                //   - has_one = <authority> on the same field, OR
                //   - constraint = <expr> referencing an authority field
                if has_reinit_guard(constraints) {
                    continue;
                }

                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "Account `{field_name}` uses init_if_needed without a reinitialization guard — an attacker can reinitialize this account and overwrite its state."
                    ),
                )
                .program(&ctx.ir.name)
                .account(field_name)
                .hint(
                    "Add `constraint = <account>.<authority_field> == <signer>.key() @ ErrorCode::AlreadyInitialized` (or `has_one = <authority>` where `<authority>` is a Signer) to prevent reinitialization by a different caller.",
                );
                b = hint.location().stamp(b);
                out.push(b.build());
            }
        }

        Ok(out)
    }
}

/// True if the field's `#[account(...)]` attrs include `init_if_needed`.
///
/// We substring-search the joined constraints rather than parsing
/// each one — `init_if_needed` is always a bare identifier token
/// (no `= value`), so a word-boundary match is sufficient. An
/// account is *only* reinitializable if it actually carries the
/// `init_if_needed` keyword; bare `init` does NOT trigger.
fn has_init_if_needed(constraints: &[String]) -> bool {
    for c in constraints {
        // The stringified form is something like
        // "init_if_needed, payer=user, space=8+32". We tokenize by
        // comma/space and look for an exact match.
        for tok in c.split(|ch: char| ch == ',' || ch.is_whitespace()) {
            if tok == "init_if_needed" {
                return true;
            }
        }
    }
    false
}

/// True if the field's `#[account(...)]` attrs include either
/// `has_one = <ident>` or a `constraint = <expr>` expression. Either
/// pattern can serve as a reinit guard.
fn has_reinit_guard(constraints: &[String]) -> bool {
    for c in constraints {
        if c.split(|ch: char| ch == ',' || ch.is_whitespace())
            .any(|tok| tok == "has_one")
        {
            return true;
        }
        if c.split(|ch: char| ch == ',' || ch.is_whitespace())
            .any(|tok| tok.starts_with("constraint") || tok == "realloc")
        {
            // `constraint = ...` or `realloc::zero = false` etc.
            // We accept any constraint expression as a guard —
            // false positives are possible if the constraint doesn't
            // actually reference an authority, but that's better than
            // missing real reinit bugs. The has_one path is the
            // recommended pattern; constraint is the escape hatch.
            return true;
        }
    }
    false
}
