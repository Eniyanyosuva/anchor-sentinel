//! `missing_balance_check` — flags instructions that debit lamports from an
//! account without a preceding balance check or guard.
//!
//! Classic drain: subtracting lamports from a vault without first verifying
//! the vault has enough. An attacker can trigger underflow panics or, worse,
//! bypass insufficient guards.
//!
//! Detection strategy (AST-based):
//! 1. Find `LamportsDebit` hints (from `-=`, `try_borrow_mut_lamports` mutations).
//! 2. Find `BalanceCheck` hints (from `>=`, `require!`, `checked_sub` guards).
//! 3. Group by nearest `InstructionHandler` using `seq` ordering.
//! 4. Flag any debit where no `BalanceCheck` for the same account has `seq < debit_seq`.

use anyhow::Result;
use std::collections::HashMap;

use crate::engine::{AnalysisContext, AstHint, AstHintKind, Finding, Layer, Rule, Severity};

/// `(file, fn_name)` key for grouping hints per handler function.
type FnKey = (String, String);

pub struct MissingBalanceCheck;

impl Rule for MissingBalanceCheck {
    fn id(&self) -> &'static str {
        "missing_balance_check"
    }
    fn description(&self) -> &'static str {
        "Lamports debited without a preceding balance check"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn layer(&self) -> Layer {
        Layer::Ast
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Collect debits and checks grouped by (file, fn_name).
        // `(account, amount_expr, seq, hint_ref)` — a lamports-debit operation.
        type DebitEntry<'a> = (String, String, usize, &'a AstHint);
        let mut debits: HashMap<FnKey, Vec<DebitEntry<'_>>> = HashMap::new();
        let mut checks: HashMap<FnKey, Vec<(String, usize)>> = HashMap::new();

        let mut current_fn: Option<FnKey> = None; // (file, fn_name)
        for hint in &ctx.ast_hints {
            if let AstHintKind::InstructionHandler { fn_name, .. } = &hint.kind {
                current_fn = Some((hint.file.clone(), fn_name.clone()));
                continue;
            }
            let Some((ref file, ref fn_name)) = current_fn else {
                continue;
            };
            let key = (file.clone(), fn_name.clone());

            match &hint.kind {
                AstHintKind::LamportsDebit {
                    account,
                    amount_expr,
                    seq,
                } => {
                    debits.entry(key).or_default().push((
                        account.clone(),
                        amount_expr.clone(),
                        *seq,
                        hint,
                    ));
                }
                AstHintKind::BalanceCheck {
                    account,
                    check_type: _,
                    seq,
                } => {
                    checks.entry(key).or_default().push((account.clone(), *seq));
                }
                _ => {}
            }
        }

        let mut out = Vec::new();
        for ((file, fn_name), entries) in &debits {
            let fn_checks = checks
                .get(&(file.clone(), fn_name.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);

            for (account, amount, debit_seq, debit_hint) in entries {
                // Check if any balance check precedes this debit for the same
                // account, or a generic check (empty account name) exists before it.
                let has_guard = fn_checks.iter().any(|(check_acct, check_seq)| {
                    *check_seq < *debit_seq && (check_acct == account || check_acct.is_empty())
                });

                if !has_guard {
                    let mut b = Finding::builder(
                        self.id(),
                        self.severity(),
                        format!(
                            "Account `{account}` has lamports debited by `{amount}` in `{fn_name}` \
                             without a preceding balance check. An attacker can drain the account \
                             by calling with `amount > account.lamports()`."
                        ),
                    )
                    .program(&ctx.ir.name)
                    .instruction(fn_name)
                    .account(account)
                    .hint(format!(
                        "Add a guard before the debit: \
                         `require!({account}.lamports() >= {amount}, ErrorCode::InsufficientFunds)` \
                         or use `checked_sub`."
                    ));
                    b = debit_hint.location().stamp(b);
                    out.push(b.build());
                }
            }
        }

        // Sort deterministically so snapshots are stable (HashMap iteration
        // is non-deterministic).
        out.sort_by(|a, b| {
            (&a.instruction, &a.account, a.line).cmp(&(&b.instruction, &b.account, b.line))
        });

        Ok(out)
    }
}
