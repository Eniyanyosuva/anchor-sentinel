//! `pda_misconfig` — flags PDA accounts whose `seeds`/`bump` constraint is
//! weak or missing in the Anchor source.
//!
//! The 0.30+ IDL already carries PDA derivation hints (`pda.seeds`), but the
//! *canonicalization* of the bump only lives in the source. So:
//!
//! 1. If the AST shows a `seeds = [...]` constraint with **no** `bump` →
//!    flag (canonicalization left to runtime guesswork).
//! 2. If `bump = <expr>` is used and the expression is anything other than
//!    the bare identifier `bump` (i.e., `bump = bump` is OK; `bump = user_bump`
//!    or `bump = bump_arg` is NOT) → flag (user-supplied bypass).
//! 3. If 0.30+ IDL lists a `pda` with empty `seeds` → flag.
//!
//! When AST hints are absent, only rule (3) fires.

use anyhow::Result;

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct PdaMisconfig;

impl Rule for PdaMisconfig {
    fn id(&self) -> &'static str {
        "pda_misconfig"
    }
    fn description(&self) -> &'static str {
        "PDA seeds without an explicit, canonical bump"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn layer(&self) -> Layer {
        Layer::IdlAst
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let mut seen_fields = std::collections::HashSet::new();
        let hint_index = field_hint_index(ctx);

        for hint in &ctx.ast_hints {
            if let AstHintKind::AccountsField {
                field_name,
                constraints,
                ..
            } = &hint.kind
            {
                // Combine all `#[account(...)]` attrs for this field.
                let joined: String = constraints.join(", ");

                // Rule 1: seeds present, no bump.
                if joined.contains("seeds") && !joined.contains("bump") {
                    seen_fields.insert(field_name.clone());
                    let mut b = Finding::builder(
                        self.id(),
                        self.severity(),
                        format!(
                            "Account `{}` declares `seeds = [...]` but does not pin the bump. Bump canonicalization is left to runtime guesswork, which can be exploited by passing non-canonical bumps.",
                            field_name
                        ),
                    )
                    .program(&ctx.ir.name)
                    .account(field_name)
                    .hint("Add `bump` to the constraint (e.g. `bump` or `bump = ctx.bumps.<field>`).");
                    if let Some(h) = hint_index.get(field_name) {
                        b = h.location().stamp(b);
                    }
                    out.push(b.build());
                    continue;
                }

                // Rule 2: bump set to a non-canonical expression.
                if let Some(idx) = joined.find("bump") {
                    let after = &joined[idx + "bump".len()..];
                    // Skip "bumps" (plural — `bump = ctx.bumps.foo` is OK).
                    if after.starts_with('s') {
                        continue;
                    }
                    // The valid bare-bump forms are:
                    //   `bump,`          — standalone canonical bump
                    //   `bump = `        — implicit canonical bump
                    // Anything else is `bump = <expr>` where expr is the trap.
                    if let Some(eq_idx) = after.find('=') {
                        let expr = after[eq_idx + 1..]
                            .trim_start()
                            .trim_end_matches(',')
                            .trim();
                        if !expr.is_empty() && expr != "ctx.bumps" && !expr.starts_with("ctx.bumps")
                        {
                            // Look for the case where the RHS is a *plain
                            // identifier* matching a struct field. That's the
                            // user-supplied bump (`bump = bump` where `bump`
                            // is a function argument).
                            if is_plain_ident(expr) {
                                seen_fields.insert(field_name.clone());
                                let mut b = Finding::builder(
                                    self.id(),
                                    self.severity(),
                                    format!(
                                        "Account `{}` pins `bump = {}` — this binds the bump to a user-supplied value instead of the canonical bump. The classic Sealevel-Attacks bypass.",
                                        field_name, expr
                                    ),
                                )
                                .program(&ctx.ir.name)
                                .account(field_name)
                                .hint("Replace with the bare `bump` identifier or `bump = ctx.bumps.<field>` to use the canonical bump.");
                                if let Some(h) = hint_index.get(field_name) {
                                    b = h.location().stamp(b);
                                }
                                out.push(b.build());
                            }
                        }
                    }
                }
            }
        }

        // Rule 3: IDL-level empty PDA seeds.
        for ix in &ctx.ir.instructions {
            for acct in &ix.accounts {
                if let Some(pda) = &acct.pda {
                    if pda.seeds.is_empty() && !seen_fields.contains(&acct.name) {
                        let mut b = Finding::builder(
                            self.id(),
                            self.severity(),
                            format!(
                                "Account `{}` on instruction `{}` is declared as a PDA but has no seeds in the IDL.",
                                acct.name, ix.name
                            ),
                        )
                        .program(&ctx.ir.name)
                        .instruction(&ix.name)
                        .account(&acct.name)
                        .hint("Provide explicit `seeds = [...]` in the constraint.");
                        if let Some(h) = hint_index.get(&acct.name) {
                            b = h.location().stamp(b);
                        }
                        out.push(b.build());
                    }
                }
            }
        }

        Ok(out)
    }
}

fn is_plain_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
