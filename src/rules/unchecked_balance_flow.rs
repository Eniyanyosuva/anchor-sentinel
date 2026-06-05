//! `unchecked_balance_flow` — detects potential lamports conservation
//! violations at the IDL level.
//!
//! In Solana, lamports are conserved: the total across all accounts before
//! and after an instruction must be equal. If an instruction debits lamports
//! from an account without a corresponding credit or CPI, lamports may have
//! leaked or been created.
//!
//! Detection strategy (IDL + AST):
//! 1. For each instruction, find writable non-signer accounts (potential lamports sources).
//! 2. Check AST hints: are there `LamportsCredit` operations? `CpiTransfer` operations?
//! 3. If there are debit operations but no credits and no CPI, flag as a potential conservation issue.
//! 4. Also check for rent-exempt minimum violations.

use anyhow::Result;
use std::collections::HashMap;

use crate::engine::{AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct UncheckedBalanceFlow;

impl Rule for UncheckedBalanceFlow {
    fn id(&self) -> &'static str {
        "unchecked_balance_flow"
    }
    fn description(&self) -> &'static str {
        "Potential lamports conservation violation — debits without matching credits"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn layer(&self) -> Layer {
        Layer::IdlAst
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Collect AST-level credits, debits, and CPI targets per instruction handler.
        // We store `(account, amount_expr, seq)` for credits so we can verify
        // ordering: credits should generally follow debits in the same handler.
        let mut credits: HashMap<String, Vec<(String, String, usize)>> = HashMap::new();
        let mut debits: HashMap<String, Vec<(String, usize)>> = HashMap::new();
        let mut cpi_ops: HashMap<String, Vec<String>> = HashMap::new(); // target names

        let mut current_fn: Option<String> = None;
        for hint in &ctx.ast_hints {
            if let AstHintKind::InstructionHandler { fn_name, .. } = &hint.kind {
                current_fn = Some(fn_name.clone());
                continue;
            }
            let Some(ref fn_name) = current_fn else {
                continue;
            };

            match &hint.kind {
                AstHintKind::LamportsCredit {
                    account,
                    amount_expr,
                    seq,
                } => {
                    credits.entry(fn_name.clone()).or_default().push((
                        account.clone(),
                        amount_expr.clone(),
                        *seq,
                    ));
                }
                AstHintKind::LamportsDebit { account, seq, .. } => {
                    debits
                        .entry(fn_name.clone())
                        .or_default()
                        .push((account.clone(), *seq));
                }
                AstHintKind::CpiTransfer { target, seq } => {
                    cpi_ops
                        .entry(fn_name.clone())
                        .or_default()
                        .push(format!("{target}@{seq}"));
                }
                _ => {}
            }
        }

        let mut out = Vec::new();
        for ix in &ctx.ir.instructions {
            // IDL heuristic: find writable non-signer accounts (potential lamports sources).
            let writable_non_signers: Vec<_> = ix
                .accounts
                .iter()
                .filter(|a| a.is_mut && !a.is_signer && !is_system_account(&a.name))
                .collect();

            if writable_non_signers.is_empty() {
                continue;
            }

            let ix_credits = credits.get(&ix.name).map(|v| v.len()).unwrap_or(0);
            let ix_debits = debits.get(&ix.name).map(|v| v.len()).unwrap_or(0);
            let ix_cpi = cpi_ops.get(&ix.name).map(|v| v.len()).unwrap_or(0);

            // If there are lamports debits but no matching credits and no CPI,
            // lamports may have leaked.
            if ix_debits > 0 && ix_credits == 0 && ix_cpi == 0 {
                // Check if there's any rent-exempt check for this instruction.
                let has_rent_check = ctx.ast_hints.iter().any(|h| {
                    if let AstHintKind::BalanceCheck {
                        check_type,
                        account,
                        ..
                    } = &h.kind
                    {
                        (check_type.contains("rent") || check_type.contains("min"))
                            || writable_non_signers.iter().any(|a| a.name == *account)
                    } else {
                        false
                    }
                });

                if !has_rent_check {
                    let account_names: Vec<&str> = writable_non_signers
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect();
                    out.push(
                        Finding::builder(
                            self.id(),
                            self.severity(),
                            format!(
                                "Instruction `{}` debits lamports from {} but shows no corresponding \
                                 credit or CPI. This may violate lamports conservation or drop accounts below \
                                 the rent-exempt minimum.",
                                ix.name,
                                account_names.join(", ")
                            ),
                        )
                        .program(&ctx.ir.name)
                        .instruction(&ix.name)
                        .hint(
                            "Verify that debited lamports are credited elsewhere, or add a \
                             rent-exempt minimum check: `require!(account.lamports() >= rent_exempt_min, ErrorCode::RentViolation)`.",
                        )
                        .build(),
                    );
                }
            } else if ix_debits > 0 && ix_credits == 0 && ix_cpi > 0 {
                // Debits present with CPI but no explicit credit — flag for manual review.
                let targets = cpi_ops.get(&ix.name).unwrap();
                let account_names: Vec<&str> = writable_non_signers
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect();
                out.push(
                    Finding::builder(
                        self.id(),
                        Severity::Info,
                        format!(
                            "Instruction `{}` debits from {} but relies on CPI to {} for \
                             lamports reconciliation. Verify the CPI recipient is correct.",
                            ix.name,
                            account_names.join(", "),
                            targets.join(", ")
                        ),
                    )
                    .program(&ctx.ir.name)
                    .instruction(&ix.name)
                    .build(),
                );
            } else if ix_debits > 0 && ix_credits > 0 {
                // Debits and credits exist — check for rent-exempt minimum.
                let has_rent_check = ctx.ast_hints.iter().any(|h| {
                    if let AstHintKind::BalanceCheck { check_type, .. } = &h.kind {
                        check_type.contains("rent") || check_type.contains("min")
                    } else {
                        false
                    }
                });
                if !has_rent_check {
                    let credit_list = credits
                        .get(&ix.name)
                        .map(|v| {
                            v.iter()
                                .map(|(a, expr, _seq)| format!("{a} (+{expr})"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    let account_names: Vec<&str> = writable_non_signers
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect();
                    out.push(
                        Finding::builder(
                            self.id(),
                            Severity::Info,
                            format!(
                                "Instruction `{}` debits from {} and credits {}. \
                                 No rent-exempt minimum guard detected.",
                                ix.name,
                                account_names.join(", "),
                                credit_list
                            ),
                        )
                        .program(&ctx.ir.name)
                        .instruction(&ix.name)
                        .hint(
                            "Consider adding a rent-exempt check to prevent accidental \
                             account destruction: `require!(account.lamports() >= rent_exempt, ...)`. ",
                        )
                        .build(),
                    );
                }
            }
        }

        Ok(out)
    }
}

fn is_system_account(name: &str) -> bool {
    matches!(
        name,
        "system_program" | "system" | "rent" | "clock" | "token_program"
    )
}
