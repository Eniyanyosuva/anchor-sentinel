//! `missing_mut` — flags instruction accounts whose name suggests a write
//! target (`destination`, `to`, `recipient`, `out`) but whose IDL `isMut`
//! is false AND whose AST field is NOT annotated `#[account(mut)]`.
//!
//! With AST hints absent, falls back to the name-based heuristic.

use std::collections::HashSet;

use anyhow::Result;

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

const DEST_NAMES: &[&str] = &[
    "destination",
    "recipient",
    "target",
    "to",
    "output",
    "out_vault",
    "out",
];

pub struct MissingMut;

impl Rule for MissingMut {
    fn id(&self) -> &'static str {
        "missing_mut"
    }
    fn description(&self) -> &'static str {
        "Account appears to be a write target but is not marked mutable"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn layer(&self) -> Layer {
        Layer::IdlAst
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Build a set of (field_name) where the AST has `#[account(mut)]`.
        let mut ast_mut: HashSet<String> = HashSet::new();
        let hint_index = field_hint_index(ctx);
        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField {
                field_name,
                constraints,
                ..
            } = &hint.kind
            {
                if constraints.iter().any(|c| c.contains("mut")) {
                    ast_mut.insert(field_name.clone());
                }
            }
        }

        let mut out = Vec::new();
        for ix in &ctx.ir.instructions {
            for acct in &ix.accounts {
                if acct.is_mut {
                    continue;
                }
                if ast_mut.contains(&acct.name) {
                    // IDL is stale relative to the source — that's a
                    // separate `id_drift` rule we'd add later. For now we
                    // trust the source.
                    continue;
                }
                let lname = acct.name.to_ascii_lowercase();
                if !DEST_NAMES.iter().any(|n| lname == *n) {
                    continue;
                }
                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "Account `{}` on instruction `{}` is not declared mutable but its name implies a write target.",
                        acct.name, ix.name
                    ),
                )
                .program(&ctx.ir.name)
                .instruction(&ix.name)
                .account(&acct.name)
                .hint("Add `#[account(mut)]` to the field and set `writable: true` in the IDL.");
                if let Some(h) = hint_index.get(&acct.name) {
                    b = h.location().stamp(b);
                }
                out.push(b.build());
            }
        }
        Ok(out)
    }
}
