//! `cpi_signer_seed_validation` — flags `invoke_signed` calls whose signer
//! seeds cannot be verified at analysis time.
//!
//! In Solana, `invoke_signed` lets a program sign on behalf of a PDA it
//! owns. The runtime derives the PDA from the seeds the program passes
//! in, so the seeds themselves are the only thing standing between
//! legitimate and forged signing. If the seeds come from user input
//! (function args, account fields without `.key().as_ref()`, or any
//! unresolvable expression) the attacker can compute their own valid
//! PDA and have the program sign for it. The Sealevel-Attacks "fake
//! PDA" and "withdraw without signing" patterns both rely on this.
//!
//! Severity: Critical — direct fund drain, often paired with a downstream
//! `lamports -= amount` that the user-facing report doesn't see.
//!
//! Safe seed forms:
//!   - `b"..."` byte string literal
//!   - `ctx.bumps.<ident>` — Anchor-managed canonical bump
//!   - `<expr>.key().as_ref()` on a known account field
//!
//! Anything else (function args, locally-bound variables, unresolvable
//! expressions) is treated as Dynamic and produces a Critical finding.

use anyhow::Result;

use crate::engine::{AnalysisContext, AstHintKind, Finding, Rule, Severity, SignerSeedClass};

pub struct CpiSignerSeedValidation;

impl Rule for CpiSignerSeedValidation {
    fn id(&self) -> &'static str {
        "cpi_signer_seed_validation"
    }
    fn description(&self) -> &'static str {
        "invoke_signed uses dynamic signer seeds that cannot be verified at analysis time"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();

        for hint in &ctx.ast_hints {
            if let AstHintKind::CpiInvokeSigned {
                seeds,
                seed_summary,
                ..
            } = &hint.kind
            {
                // The Absent case covers empty seeds (equivalent to a
                // plain `invoke`) and macro-token parse failures. Both
                // are programmer mistakes rather than security
                // vulnerabilities, so we don't fire on them.
                if matches!(seeds, SignerSeedClass::Safe | SignerSeedClass::Absent) {
                    continue;
                }

                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "invoke_signed uses dynamic signer seeds that cannot be verified at analysis time — ensure seeds are derived from canonical PDAs (ctx.bumps.<name>) not user input. Detected seeds: `{seed_summary}`."
                    ),
                )
                .program(&ctx.ir.name)
                .hint(
                    "Replace dynamic seeds with: a `b\"literal\"` byte string, `ctx.bumps.<field>` for the canonical bump, or `ctx.accounts.<account>.key().as_ref()` for a known account's pubkey. Never pass function arguments or user-controlled data as signer seeds.",
                );
                b = hint.location().stamp(b);
                out.push(b.build());
            }
        }

        Ok(out)
    }
}
