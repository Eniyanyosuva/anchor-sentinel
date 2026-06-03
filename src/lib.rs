//! Anchor Sentinel core library.
//!
//! This crate exists for two consumers:
//!   - The `sentinel` CLI binary (`src/main.rs`).
//!   - The WASM playground build (`src/wasm.rs`).
//!
//! Both share the same rule engine, IDL parser, AST parser, and report
//! generators. The CLI additionally wires up file walking, output
//! formatting, and exit codes; the WASM build accepts raw strings and
//! returns findings as a JS value.
//!
//! Modules:
//!   - [`ast`]: Rust source visitor that produces `AstHint`s for the engine.
//!   - [`engine`]: the `Rule` trait, `AnalysisContext`, `Finding`, severity.
//!   - [`idl`]: IDL parser producing the unified `ProgramIr`.
//!   - [`report`]: text / JSON / SARIF report generators.
//!   - [`rules`]: the 13 built-in security rules.
//!   - [`wasm`]: `#[wasm_bindgen]` entrypoint (compiled when targeting
//!     `wasm32-unknown-unknown`).

pub mod ast;
pub mod engine;
pub mod idl;
pub mod report;
pub mod rules;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
