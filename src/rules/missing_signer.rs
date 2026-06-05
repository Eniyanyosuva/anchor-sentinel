//! `missing_signer` — flags instruction accounts that are not signed-for
//! in the IDL but whose role strongly implies they should be authorized.
//!
//! When AST hints are present, the rule is upgraded:
//!   - The field IS typed `Signer` (or `SystemAccount` / `Program` with a
//!     `signer` constraint) → no finding.
//!   - The field is typed `AccountInfo` (the unsafe escape hatch) → we raise
//!     a high-confidence finding regardless of the account name.
//!   - The struct doesn't have an `#[account(signer)]` constraint → flag.
//!
//! When AST hints are absent (no `programs/**/src/lib.rs` shipped, or the
//! file failed to parse), we fall back to the original name-based heuristic.

use std::collections::HashSet;

use anyhow::Result;

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

const SUSPECT_NAMES: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "payer",
    "user",
    "signer",
    "creator",
    "operator",
];

pub struct MissingSigner;

impl Rule for MissingSigner {
    fn id(&self) -> &'static str {
        "missing_signer"
    }
    fn description(&self) -> &'static str {
        "Account appears to require authorization but lacks a signer check"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn layer(&self) -> Layer {
        Layer::IdlAst
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Build a set of (field_name) that AST has confirmed as `Signer`
        // or with an explicit `signer` constraint.
        let mut ast_signed: HashSet<String> = HashSet::new();
        let mut ast_account_info: HashSet<String> = HashSet::new();
        let hint_index = field_hint_index(ctx);
        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField {
                field_name,
                ty,
                constraints,
                ..
            } = &hint.kind
            {
                if ty.contains("Signer") || constraints.iter().any(|c| c.contains("signer")) {
                    ast_signed.insert(field_name.clone());
                } else if ty.contains("AccountInfo") {
                    ast_account_info.insert(field_name.clone());
                }
            }
        }

        let mut out = Vec::new();
        for ix in &ctx.ir.instructions {
            for acct in &ix.accounts {
                if acct.is_signer {
                    continue;
                }
                // AST says it's signed for.
                if ast_signed.contains(&acct.name) {
                    continue;
                }

                let (reason, hint) = if ast_account_info.contains(&acct.name) {
                    (
                        format!(
                            "Account `{}` on instruction `{}` is declared as `AccountInfo` in the handler but is not marked as a signer in the IDL. `AccountInfo` is the unsafe escape hatch — there is no runtime signer check.",
                            acct.name, ix.name
                        ),
                        "Type the field as `Signer` instead of `AccountInfo`.".to_string(),
                    )
                } else {
                    let lname = acct.name.to_ascii_lowercase();
                    if !SUSPECT_NAMES.iter().any(|n| lname.contains(n)) {
                        continue;
                    }
                    (
                        format!(
                            "Account `{}` on instruction `{}` is not marked as a signer but its name implies authority.",
                            acct.name, ix.name
                        ),
                        "Type the field as `Signer` or add `#[account(signer)]`.".to_string(),
                    )
                };

                let mut b = Finding::builder(self.id(), self.severity(), reason)
                    .program(&ctx.ir.name)
                    .instruction(&ix.name)
                    .account(&acct.name)
                    .hint(hint);
                if let Some(h) = hint_index.get(&acct.name) {
                    b = h.location().stamp(b);
                }
                out.push(b.build());
            }
        }
        Ok(out)
    }
}
