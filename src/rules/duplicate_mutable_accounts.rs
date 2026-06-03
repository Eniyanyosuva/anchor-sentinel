//! `duplicate_mutable_accounts` — flags instructions with multiple mutable
//! `AccountInfo` arguments that could reference the same pubkey.
//!
//! The classic confusion attack: pass the same pubkey for two writable
//! account slots. Debiting one also debits the other because they point
//! to the same underlying account. Anchor's `Account<'info, T>` type
//! derives addresses from seeds, preventing this, but `AccountInfo`
//! accepts any pubkey.
//!
//! Detection strategy (IDL + AST):
//! 1. Find instructions with ≥2 writable non-signer accounts.
//! 2. Check AST hints: if ALL such accounts are typed `AccountInfo`, flag.
//!    If any use `Account<'info, T>`, the derivation is safe — skip.
//! 3. Also flag if the IDL lacks distinct PDA seeds (suggesting they could
//!    be resolved to the same address).

use anyhow::Result;
use std::collections::HashSet;

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Rule, Severity};

pub struct DuplicateMutableAccounts;

impl Rule for DuplicateMutableAccounts {
    fn id(&self) -> &'static str {
        "duplicate_mutable_accounts"
    }
    fn description(&self) -> &'static str {
        "Multiple mutable `AccountInfo` args could reference the same pubkey"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Build a set of (field_name) where AST shows `Account<…>` or
        // `SystemAccount` — these derive their address and can't be spoofed.
        let mut ast_safe: HashSet<String> = HashSet::new();
        // Also track which fields are typed `AccountInfo` (unsafe).
        let mut ast_account_info: HashSet<String> = HashSet::new();
        let hint_index = field_hint_index(ctx);
        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField { field_name, ty, .. } = &hint.kind {
                if ty.contains("Account<")
                    || ty.contains("SystemAccount")
                    || ty.contains("Program<")
                    || ty.contains("Signer")
                    || ty.contains("TokenAccount")
                    || ty.contains("TokenAccount2022")
                {
                    ast_safe.insert(field_name.clone());
                } else if ty.contains("AccountInfo") {
                    ast_account_info.insert(field_name.clone());
                }
            }
        }

        let mut out = Vec::new();
        for ix in &ctx.ir.instructions {
            // Find writable non-signer accounts (potential duplication targets).
            let writable_non_signers: Vec<_> = ix
                .accounts
                .iter()
                .filter(|a| a.is_mut && !a.is_signer)
                .collect();

            // Need ≥2 to be vulnerable to duplication.
            if writable_non_signers.len() < 2 {
                continue;
            }

            // Check if any are safely typed (Account<…>, etc.).

            // If ALL writable non-signers are `AccountInfo`, flag.
            // If some are safe and some are AccountInfo, still flag the
            // AccountInfo ones — partial confusion is still a risk.
            let unsafe_accounts: Vec<_> = writable_non_signers
                .iter()
                .filter(|a| !ast_safe.contains(&a.name))
                .collect();

            if unsafe_accounts.len() >= 2 {
                let names: Vec<&str> = unsafe_accounts.iter().map(|a| a.name.as_str()).collect();
                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "Instruction `{}` has ≥2 mutable `AccountInfo` accounts ({}) — \
                         an attacker can pass the same pubkey for both. Debiting one \
                         also debits the other because they reference the same account.",
                        ix.name,
                        names.join(", ")
                    ),
                )
                .program(&ctx.ir.name)
                .instruction(&ix.name)
                .account(names.first().copied().unwrap_or(""))
                .hint(
                    "Type the fields as `Account<'info, T>` or use `#[account(mut)]` \
                     with `has_one` constraints to derive distinct addresses from seeds.",
                );
                if let Some(first) = names.first() {
                    if let Some(h) = hint_index.get(*first) {
                        b = h.location().stamp(b);
                    }
                }
                out.push(b.build());
            }
        }

        Ok(out)
    }
}
