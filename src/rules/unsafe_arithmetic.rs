//! `unsafe_arithmetic` — flags raw `+ - * / %` on integer types found by the
//! AST visitors in `src/ast/instruction_fn.rs`.
//!
//! Whitelisted: `checked_*`, `saturating_*`, `overflowing_*`, `wrapping_*`.
//! Those don't show up here because they're `ExprMethodCall`, not
//! `ExprBinary`, so the inner visitor only emits raw ops.

use std::collections::HashSet;

use anyhow::Result;

use crate::engine::{AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct UnsafeArithmetic;

impl Rule for UnsafeArithmetic {
    fn id(&self) -> &'static str {
        "unsafe_arithmetic"
    }
    fn description(&self) -> &'static str {
        "Detects unchecked +, -, *, /, % on u64/u128/i64"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn layer(&self) -> Layer {
        Layer::Ast
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let mut seen: HashSet<(String, String, String, String)> = HashSet::new();

        for hint in &ctx.ast_hints {
            if let AstHintKind::UnsafeArithmetic { op, lhs_ty, rhs_ty } = &hint.kind {
                // Dedupe per (file, op, lhs_ty, rhs_ty) so a tight loop with
                // 50 additions doesn't flood the report.
                let key = (
                    hint.file.clone(),
                    op.clone(),
                    lhs_ty.clone(),
                    rhs_ty.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "Unchecked `{op}` between `{lhs_ty}` and `{rhs_ty}` — wrap in `checked_{op}`, `saturating_{op}`, or `overflowing_{op}` to avoid panics on overflow."
                    ),
                )
                .program(&ctx.ir.name)
                .hint(format!(
                    "Replace `a {op} b` with `a.checked_{op}(b).unwrap()` or use a checked-math helper."
                ));
                b = hint.location().stamp(b);
                out.push(b.build());
            }
        }
        Ok(out)
    }
}
