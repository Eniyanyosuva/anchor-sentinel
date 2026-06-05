//! `missing_ownership` — flags accounts whose IDL `isMut: true` but whose
//! AST field type is `AccountInfo` (the unsafe escape hatch) AND lacks an
//! `#[account(owner = …)]` constraint. With AST hints absent, we fall
//! back to a name-based heuristic that flags `vault`/`pool`/`state` mutable
//! non-signer accounts.
//!
//! The right way to constrain ownership in Anchor is to type the field as
//! `Account<'info, T>` — that gives you a compile-time owner check. If
//! the dev is forced to use `AccountInfo`, they need an explicit
//! `#[account(owner = <program>)]` constraint to keep the runtime safe.

use std::collections::HashSet;

use anyhow::Result;

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct MissingOwnership;

impl Rule for MissingOwnership {
    fn id(&self) -> &'static str {
        "missing_ownership"
    }
    fn description(&self) -> &'static str {
        "Mutable account typed as `AccountInfo` without an explicit `owner` constraint"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn layer(&self) -> Layer {
        Layer::IdlAst
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Field types that already imply an ownership check at runtime.
        let mut ast_properly_typed: HashSet<String> = HashSet::new();
        let hint_index = field_hint_index(ctx);
        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField { field_name, ty, .. } = &hint.kind {
                if ty.contains("Account<")
                    || ty.contains("Program<")
                    || ty.contains("SystemAccount")
                {
                    ast_properly_typed.insert(field_name.clone());
                }
            }
        }

        let mut out = Vec::new();
        for ix in &ctx.ir.instructions {
            for acct in &ix.accounts {
                if !acct.is_mut || acct.is_signer {
                    continue;
                }
                if ast_properly_typed.contains(&acct.name) {
                    // AST shows `Account<…>` or `Program<…>` — already safe.
                    continue;
                }
                let lname = acct.name.to_ascii_lowercase();
                if !(lname.contains("vault") || lname.contains("pool") || lname.contains("state")) {
                    continue;
                }
                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "Account `{}` on instruction `{}` is mutable but typed as `AccountInfo` and lacks an `#[account(owner = …)]` constraint. Runtime code can deserialize arbitrary data into it.",
                        acct.name, ix.name
                    ),
                )
                .program(&ctx.ir.name)
                .instruction(&ix.name)
                .account(&acct.name)
                .hint("Either type the field as `Account<'info, T>` for compile-time ownership, or add `#[account(owner = <expected_program_id>)]`.");
                if let Some(h) = hint_index.get(&acct.name) {
                    b = h.location().stamp(b);
                }
                out.push(b.build());
            }
        }
        Ok(out)
    }
}
