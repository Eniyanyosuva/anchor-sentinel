//! WebAssembly entrypoint for the Anchor Sentinel playground.
//!
//! Built only when the target is `wasm32-unknown-unknown`. The CLI
//! binary and `cargo test` use `src/main.rs` and the `lib` rlib target;
//! this file is gated by `#[cfg(target_arch = "wasm32")]` in `lib.rs`.
//!
//! The browser calls `scan(idl_json, rust_src)` from JavaScript. We:
//!   1. Parse the IDL via the same `idl::from_value` path the CLI uses.
//!   2. Run the AST visitor on the Rust source string.
//!   3. Run every registered rule over the resulting `AnalysisContext`.
//!   4. Return the findings as a JS-serializable value (a plain array
//!      of objects) so the playground can render them without
//!      reaching back into Rust.

use wasm_bindgen::prelude::*;

use crate::ast;
use crate::engine::{run_all_rules, AnalysisContext};
use crate::idl;

/// Install a `console.error` panic hook so a panic inside the WASM
/// module shows up in the browser's devtools rather than as a silent
/// abort. Idempotent; safe to call multiple times.
#[wasm_bindgen(start)]
pub fn _start() {
    console_error_panic_hook::set_once();
}

/// Scan a single IDL + Rust source pair and return findings as a
/// JavaScript value.
///
/// `idl_json` is the raw text of an Anchor IDL file (0.30+ or legacy
/// 0.29; the parser auto-detects). `rust_src` is the raw text of an
/// Anchor `programs/<name>/src/lib.rs`. Either can be empty, in which
/// case the corresponding analysis layer is skipped.
///
/// The return value is a plain JS array of finding objects, each
/// shaped like:
///
/// ```ts
/// {
///   rule: string,
///   severity: "critical" | "high" | "medium" | "low" | "info",
///   program: string,
///   instruction: string | null,
///   account: string | null,
///   file: string | null,
///   line: number | null,
///   column: number | null,
///   message: string,
///   hint: string | null,
/// }
/// ```
///
/// Parse errors are returned as a single error object: `[{ error: "..." }]`.
#[wasm_bindgen]
pub fn scan(idl_json: &str, rust_src: &str) -> JsValue {
    match scan_inner(idl_json, rust_src) {
        Ok(findings) => serde_wasm_bindgen::to_value(&findings).unwrap_or(JsValue::NULL),
        Err(e) => {
            // Surface the error to the UI rather than aborting the page.
            let msg = format!("{e:#}");
            serde_wasm_bindgen::to_value(&[serde_json::json!({ "error": msg })])
                .unwrap_or(JsValue::NULL)
        }
    }
}

fn scan_inner(idl_json: &str, rust_src: &str) -> anyhow::Result<Vec<crate::engine::Finding>> {
    // 1. IDL → ProgramIr.
    let program_ir = if idl_json.trim().is_empty() {
        // Empty IDL: synthesize a stub so rules that only need AST
        // hints (e.g. unsafe_arithmetic) can still run. IDL-only rules
        // produce no findings on a stub.
        crate::idl::ir::ProgramIr {
            version: crate::idl::ir::IdlVersion::V30Plus,
            name: String::new(),
            instructions: Vec::new(),
            accounts: Vec::new(),
            types: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            source_path: "<wasm>".to_string(),
        }
    } else {
        let json: serde_json::Value =
            serde_json::from_str(idl_json).map_err(|e| anyhow::anyhow!("parsing IDL JSON: {e}"))?;
        idl::from_value(json, "<wasm>")?
    };

    // 2. Rust source → AstHints.
    let ast_hints = if rust_src.trim().is_empty() {
        Vec::new()
    } else {
        ast::collect_hints_from_source("<lib.rs>", rust_src)?
    };

    // 3. Run every rule.
    let ctx = AnalysisContext {
        ir: program_ir,
        ast_hints,
    };
    Ok(run_all_rules(&ctx)?)
}
