//! `missing_close_authority` — flags `close = <ident>` constraints where the
//! close target is not enforced as a signer or authority.
//!
//! When an Anchor account is closed via `#[account(mut, close = target)]`,
//! Anchor transfers the account's rent-exempt lamports to `target` and
//! zeros the account data. If `target` is just a plain `AccountInfo`,
//! *anyone* can be that account — the attacker passes their own pubkey
//! as `target` and walks away with the rent. The original "owner" gets
//! nothing.
//!
//! Severity: High — silent, repeatable fund drain. The close target must
//! be one of:
//!   1. `Signer<'info>` (transaction-level authorization), or
//!   2. Bound by `has_one = <target>` somewhere on the same struct
//!      (data-level authority check), or
//!   3. Mentioned in a `constraint = …<target>…` expression on the same
//!      struct (manual authorization).
//!
//! When none of those hold, emit a finding pointing at the field that
//! uses `close = <ident>`. We don't flag the target field itself — the
//! `close = …` line is the actionable site.

use anyhow::Result;
use std::collections::{HashMap, HashSet};

use crate::engine::{field_hint_index, AnalysisContext, AstHintKind, Finding, Layer, Rule, Severity};

pub struct MissingCloseAuthority;

impl Rule for MissingCloseAuthority {
    fn id(&self) -> &'static str {
        "missing_close_authority"
    }
    fn description(&self) -> &'static str {
        "Detects `close = <target>` constraints where the target is not enforced as a signer or authority"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn layer(&self) -> Layer {
        Layer::Ast
    }

    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();

        // Group AST hints by struct so the rule can answer
        // "is field `X` a Signer? does any other field in the same struct
        // have has_one = X or constraint = … X …?"
        let by_struct = group_by_struct(&ctx.ast_hints);
        let hint_index = field_hint_index(ctx);
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        for (struct_name, fields) in &by_struct {
            // First pass: collect the set of close targets referenced in
            // this struct, so we can search the rest of the struct for
            // their authority bindings.
            let close_pairs: Vec<(String, String)> = fields
                .iter()
                .filter_map(|f| {
                    let close_target = extract_close_target(&f.constraints);
                    close_target.map(|t| (f.field_name.clone(), t))
                })
                .collect();

            if close_pairs.is_empty() {
                continue;
            }

            for (field_name, target) in &close_pairs {
                // 1. Is the close target itself a `Signer<'info>` on this struct?
                let target_is_signer = fields
                    .iter()
                    .any(|f| f.field_name == *target && is_signer_type(&f.ty));

                // 2. Does any field in the struct have `has_one = <target>`?
                let target_has_one = fields.iter().any(|f| {
                    f.constraints
                        .iter()
                        .any(|c| extract_named_ident(c, "has_one") == Some(target.as_str()))
                });

                // 3. Does any field have a `constraint = …<target>…` that
                //    names the target? We use a word-boundary match so
                //    e.g. `target` doesn't match a field called `targetx`.
                let target_in_constraint = fields.iter().any(|f| {
                    f.constraints.iter().any(|c| {
                        if let Some(expr) = extract_constraint_expr(c) {
                            contains_ident(expr, target)
                        } else {
                            false
                        }
                    })
                });

                if target_is_signer || target_has_one || target_in_constraint {
                    continue;
                }

                let key = (struct_name.clone(), field_name.clone(), target.clone());
                if !seen.insert(key) {
                    continue;
                }

                let mut b = Finding::builder(
                    self.id(),
                    self.severity(),
                    format!(
                        "close target `{target}` is not enforced as a signer or authority — anyone can close this account and claim rent. Type the field as `Signer<'info>`, add a `has_one = {target}` constraint, or use a `constraint = …{target}…` expression."
                    ),
                )
                .program(&ctx.ir.name)
                .instruction(struct_name)
                .account(field_name)
                .hint(format!(
                    "Bind `{target}` to a `Signer<'info>` (e.g. `pub {target}: Signer<'info>`) or add a constraint like `has_one = {target}` / `constraint = vault.authority == {target}.key()`."
                ));
                if let Some(h) = hint_index.get(field_name) {
                    b = h.location().stamp(b);
                }
                out.push(b.build());
            }
        }

        Ok(out)
    }
}

/// A flattened view of an `AccountsField` hint, kept local to this rule.
struct FieldView {
    field_name: String,
    ty: String,
    constraints: Vec<String>,
}

fn group_by_struct(hints: &[crate::engine::AstHint]) -> HashMap<String, Vec<FieldView>> {
    let mut out: HashMap<String, Vec<FieldView>> = HashMap::new();
    for hint in hints {
        if let AstHintKind::AccountsField {
            struct_name,
            field_name,
            ty,
            constraints,
        } = &hint.kind
        {
            out.entry(struct_name.clone()).or_default().push(FieldView {
                field_name: field_name.clone(),
                ty: ty.clone(),
                constraints: constraints.clone(),
            });
        }
    }
    out
}

/// Extract the RHS identifier from a `close = <ident>` constraint.
/// Returns `None` for `mut`, `realloc`, `bump`, etc.
fn extract_close_target(constraints: &[String]) -> Option<String> {
    for c in constraints {
        if let Some(target) = extract_named_ident(c, "close") {
            return Some(target.to_string());
        }
    }
    None
}

/// Extract the RHS identifier from a constraint like `<name> = <ident>`.
/// Whitespace around `=` is tolerated. Returns `None` if the constraint
/// doesn't match that pattern or the RHS isn't a plain identifier.
fn extract_named_ident<'a>(constraint: &'a str, name: &str) -> Option<&'a str> {
    // Locate `name` followed by `=` (skipping `name =` over `name.` /
    // `name(`). We do this by searching for `name` and then checking the
    // character after.
    let idx = constraint.find(name)?;
    let after = &constraint[idx + name.len()..];
    // `has_one` shouldn't match `has_one_xyz`; same for `close`.
    if after.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let after = after.trim_start();
    let after = after.strip_prefix('=')?.trim_start();
    let ident: &str = after
        .split(|c: char| c == ',' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim();
    if is_plain_ident(ident) {
        Some(ident)
    } else {
        None
    }
}

/// Extract the expression text from a `constraint = <expr>` form.
fn extract_constraint_expr(constraint: &str) -> Option<&str> {
    let idx = constraint.find("constraint")?;
    let after = &constraint[idx + "constraint".len()..];
    if after.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let after = after.trim_start();
    let after = after.strip_prefix('=')?.trim_start();
    // Strip a trailing comma if present.
    let expr = after.trim_end().trim_end_matches(',').trim();
    if expr.is_empty() {
        None
    } else {
        Some(expr)
    }
}

/// Returns true if `s` is a plain Rust identifier.
fn is_plain_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Word-boundary check: does `haystack` contain `needle` as an identifier?
/// Used to spot `target.key()`, `target == X`, `vault.target == …`, etc.
fn contains_ident(haystack: &str, needle: &str) -> bool {
    if !is_plain_ident(needle) {
        return false;
    }
    let mut start = 0;
    while let Some(idx) = haystack[start..].find(needle) {
        let abs = start + idx;
        let before_ok = abs == 0
            || !haystack
                .as_bytes()
                .get(abs - 1)
                .copied()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
        let after = abs + needle.len();
        let after_ok = after >= haystack.len()
            || !haystack
                .as_bytes()
                .get(after)
                .copied()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// True if the type string (already whitespace-stripped) starts with
/// `Signer`. We match the prefix because `Signer<'info>` keeps the
/// lifetime tokens in the string.
fn is_signer_type(ty: &str) -> bool {
    ty.starts_with("Signer")
}
