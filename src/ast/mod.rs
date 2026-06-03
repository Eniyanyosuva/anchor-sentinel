//! AST layer. Walks every `*.rs` file the loader discovered, runs the two
//! visitors, and returns a flat list of hints for the engine.
//!
//! Spans are resolved at parse time: each visitor emits a `RawHint` with a
//! `proc_macro2::LineColumn`; we convert those to 1-based (line, column)
//! pairs in the final `AstHint` so rules can stamp findings without any
//! further work.

use anyhow::Result;
use std::path::Path;
use syn::visit::Visit;

use crate::engine::AstHint;

mod accounts_struct;
mod instruction_fn;

/// Parse each path the loader gave us and collect AST hints.
pub fn collect_hints(paths: &[std::path::PathBuf]) -> Result<Vec<AstHint>> {
    let mut out = Vec::new();
    for p in paths {
        if let Some(hints) = parse_file(p) {
            out.extend(hints);
        }
    }
    Ok(out)
}

/// Parse a single Rust source string and return the AST hints it
/// produces. The `file` label is stamped onto each hint so the report
/// can show `file:line:column`. Used by the WASM entrypoint, which has
/// no filesystem to walk.
///
/// The `#[allow(dead_code)]` is for the native build: the function is
/// only called from the `wasm32` target, but the symbol is part of
/// the rlib so we don't want clippy to fail CI on it.
#[allow(dead_code)]
pub fn collect_hints_from_source(file: &str, src: &str) -> Result<Vec<AstHint>> {
    let ast = syn::parse_file(src).map_err(|e| anyhow::anyhow!("parsing Rust source: {e}"))?;

    let mut accounts = accounts_struct::FileAccounts::default();
    let mut fns = instruction_fn::FileFns::default();
    let mut av = accounts_struct::AccountsStructVisitor::new(file, &mut accounts);
    let mut fv = instruction_fn::InstructionFnVisitor::new(file, &mut fns);

    av.visit_file(&ast);
    fv.visit_file(&ast);

    let mut hints: Vec<AstHint> = Vec::new();
    for raw in accounts.hints {
        hints.push(AstHint {
            kind: raw.kind,
            file: file.to_string(),
            line: raw.start.line,
            column: raw.start.column,
        });
    }
    for raw in fns.hints {
        hints.push(AstHint {
            kind: raw.kind,
            file: file.to_string(),
            line: raw.start.line,
            column: raw.start.column,
        });
    }
    Ok(hints)
}

fn parse_file(path: &Path) -> Option<Vec<AstHint>> {
    let _src = std::fs::read_to_string(path).ok()?;
    let ast = syn::parse_file(&_src).ok()?;
    let file = path.display().to_string();

    let mut accounts = accounts_struct::FileAccounts::default();
    let mut fns = instruction_fn::FileFns::default();
    let mut av = accounts_struct::AccountsStructVisitor::new(&file, &mut accounts);
    let mut fv = instruction_fn::InstructionFnVisitor::new(&file, &mut fns);

    av.visit_file(&ast);
    fv.visit_file(&ast);

    // Each visitor stores its own private `RawHint` type, so we resolve
    // spans to engine-level `AstHint` values per-visitor and then chain
    // those. The `file` is the same for both, and `start.line`/`column`
    // are 1-based because `proc_macro2` reports them that way.
    let mut hints: Vec<AstHint> = Vec::new();
    for raw in accounts.hints {
        hints.push(AstHint {
            kind: raw.kind,
            file: file.clone(),
            line: raw.start.line,
            column: raw.start.column,
        });
    }
    for raw in fns.hints {
        hints.push(AstHint {
            kind: raw.kind,
            file: file.clone(),
            line: raw.start.line,
            column: raw.start.column,
        });
    }
    Some(hints)
}
