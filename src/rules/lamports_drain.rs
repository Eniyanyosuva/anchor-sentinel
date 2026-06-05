//! `lamports_drain` — flags instructions that zero lamports on an account
//! without proper authorization.
//!
//! Setting lamports to 0 (account closure) without a signer/authority check
//! allows anyone to destroy accounts and potentially steal rent-exempt deposits.
//!
//! Detection strategy:
//! 1. Find `LamportsZero` hints (from `lamports = 0`, `set_lamports(0)`).
//! 2. Find `BalanceCheck` / auth checks (`require_keys_eq`, `require`, signer checks).
//! 3. Group by nearest `InstructionHandler`.
//! 4. Flag zeroing when no auth check precedes it AND the IDL has no signer.

use anyhow::Result;
use std::collections::HashMap;

use crate::engine::{AnalysisContext, AstHint, AstHintKind, Finding, Layer, Rule, Severity};

/// `(file, fn_name)` key for grouping hints per handler function.
type FnKey = (String, String);

pub struct LamportsDrain;

impl Rule for LamportsDrain {
    fn id(&self) -> &'static str {
        "lamports_drain"
    }
    fn description(&self) -> &'static str {
        "Lamports explicitly zeroed without proper authorization"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn layer(&self) -> Layer {
        Layer::IdlAst
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Collect zeros and auth checks grouped by (file, fn_name).
        // `(account, seq, hint_ref)` — a lamports-zero operation.
        type ZeroEntry<'a> = (String, usize, &'a AstHint);
        let mut zeros: HashMap<FnKey, Vec<ZeroEntry<'_>>> = HashMap::new();
        let mut auth_checks: HashMap<FnKey, Vec<usize>> = HashMap::new();

        let mut current_fn: Option<FnKey> = None;
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
                AstHintKind::LamportsZero { account, seq } => {
                    zeros
                        .entry(key)
                        .or_default()
                        .push((account.clone(), *seq, hint));
                }
                AstHintKind::BalanceCheck {
                    check_type, seq, ..
                } if is_auth_check(check_type) => {
                    auth_checks.entry(key).or_default().push(*seq);
                }
                _ => {}
            }
        }

        let mut out = Vec::new();
        for ((file, fn_name), entries) in &zeros {
            let auth_seqs = auth_checks
                .get(&(file.clone(), fn_name.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);

            // Also check IDL: does this instruction have any signer?
            let has_idl_signer = ctx
                .ir
                .instructions
                .iter()
                .any(|ix| ix.name == *fn_name && ix.accounts.iter().any(|a| a.is_signer));

            for (account, zero_seq, zero_hint) in entries {
                let has_auth = auth_seqs.iter().any(|s| *s < *zero_seq);

                if !has_auth && !has_idl_signer {
                    let mut b = Finding::builder(
                        self.id(),
                        self.severity(),
                        format!(
                            "Account `{account}` is zeroed in `{fn_name}` without any authorization \
                             check. Any caller can destroy this account and its rent-exempt deposit."
                        ),
                    )
                    .program(&ctx.ir.name)
                    .instruction(fn_name)
                    .account(account)
                    .hint(format!(
                        "Add a signer/authority check before zeroing lamports: \
                         `require_keys_eq!({account}.key(), expected_authority, ErrorCode::Unauthorized)`."
                    ));
                    b = zero_hint.location().stamp(b);
                    out.push(b.build());
                }
            }
        }

        // Sort findings deterministically by (instruction, account, line) so
        // snapshots are stable across runs (HashMap iteration is non-deterministic).
        out.sort_by(|a, b| {
            (&a.instruction, &a.account, a.line).cmp(&(&b.instruction, &b.account, b.line))
        });

        Ok(out)
    }
}

fn is_auth_check(check_type: &str) -> bool {
    matches!(
        check_type,
        "require_keys_eq"
            | "require_keys_neq"
            | "require"
            | "require_gte"
            | "require_eq"
            | "require_gt"
    )
}
