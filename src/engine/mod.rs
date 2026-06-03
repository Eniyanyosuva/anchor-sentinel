//! Rule engine core: `Rule` trait, `Finding`, `Severity`, `AnalysisContext`.
//!
//! Rules are simple, stateless, sync functions over an `AnalysisContext`. The
//! registry in `registry.rs` discovers and orders them at startup.

pub mod registry;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::idl::ir::ProgramIr;

/// 5-level severity scale. Ordered low → high so comparisons work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity from a string. Reserved for the upcoming
    /// `--min-severity` config-file form; the current CLI uses `MinSeverity`
    /// directly.
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single finding produced by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub program: String,
    pub instruction: Option<String>,
    pub account: Option<String>,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
    pub hint: Option<String>,
}

impl Finding {
    pub fn builder(rule: &str, severity: Severity, message: impl Into<String>) -> FindingBuilder {
        FindingBuilder {
            rule: rule.to_string(),
            severity,
            message: message.into(),
            program: None,
            instruction: None,
            account: None,
            file: None,
            line: None,
            column: None,
            hint: None,
        }
    }
}

pub struct FindingBuilder {
    rule: String,
    severity: Severity,
    message: String,
    program: Option<String>,
    instruction: Option<String>,
    account: Option<String>,
    file: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    hint: Option<String>,
}

impl FindingBuilder {
    pub fn program(mut self, p: impl Into<String>) -> Self {
        self.program = Some(p.into());
        self
    }
    pub fn instruction(mut self, i: impl Into<String>) -> Self {
        self.instruction = Some(i.into());
        self
    }
    pub fn account(mut self, a: impl Into<String>) -> Self {
        self.account = Some(a.into());
        self
    }
    pub fn file(mut self, f: impl Into<String>) -> Self {
        self.file = Some(f.into());
        self
    }
    pub fn line(mut self, l: usize) -> Self {
        self.line = Some(l);
        self
    }
    pub fn column(mut self, c: usize) -> Self {
        self.column = Some(c);
        self
    }
    pub fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }
    pub fn build(self) -> Finding {
        Finding {
            rule: self.rule,
            severity: self.severity,
            program: self.program.unwrap_or_default(),
            instruction: self.instruction,
            account: self.account,
            file: self.file,
            line: self.line,
            column: self.column,
            message: self.message,
            hint: self.hint,
        }
    }
}

/// What a rule sees at check-time. The AST layer populates `ast_hints` later
/// in the build-out; for now it's an empty `Vec` and rules ignore it.
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    pub ir: ProgramIr,
    /// Optional AST-derived hints. Populated in Week 2.
    pub ast_hints: Vec<AstHint>,
}

impl Default for AnalysisContext {
    fn default() -> Self {
        // Real callers always populate `ir` explicitly; this exists only so
        // the struct can be constructed in tests without a parsed program.
        Self {
            ir: ProgramIr {
                version: crate::idl::ir::IdlVersion::V30Plus,
                name: String::new(),
                instructions: Vec::new(),
                accounts: Vec::new(),
                types: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
                source_path: String::new(),
            },
            ast_hints: Vec::new(),
        }
    }
}

/// A free-form hint derived from the Rust source.
#[derive(Debug, Clone)]
pub struct AstHint {
    pub kind: AstHintKind,
    pub file: String,
    /// Resolved (1-based) line, set by the AST layer using the source text
    /// + `proc_macro2::LineColumn`.
    pub line: usize,
    /// Resolved (1-based) column.
    pub column: usize,
}

impl AstHint {
    /// Borrow the hint's source location as a `SourceLocation`. This is the
    /// form rules want when stamping a `Finding` so that the report can
    /// include `file:line:column` (currently the rule layer leaves these
    /// fields as `null` for non-`unsafe_arithmetic` rules — task #1 fixes
    /// that by routing every `AccountsField` hint through this helper).
    pub fn location(&self) -> SourceLocation {
        SourceLocation {
            file: self.file.clone(),
            line: self.line,
            column: self.column,
        }
    }
}

/// Resolved source location, ready to be stamped onto a `Finding`.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl SourceLocation {
    pub fn stamp(self, b: FindingBuilder) -> FindingBuilder {
        b.file(self.file).line(self.line).column(self.column)
    }
}

/// Safety classification for the signer-seeds argument of an
/// `invoke_signed` call. The `cpi_signer_seed_validation` rule uses this
/// to decide whether to fire a Critical finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerSeedClass {
    /// All seed slices are composed of canonical sources:
    /// `b"..."` literals, `ctx.bumps.<ident>`, or `.key().as_ref()` on
    /// a known account field. The seeds can be trusted to identify a
    /// real PDA.
    Safe,
    /// At least one seed slice contains a function arg, an unresolvable
    /// expression, or anything else the AST layer can't verify. The
    /// seeds may identify an attacker-controlled address.
    Dynamic,
    /// The third argument was present but empty — equivalent to `invoke`
    /// (no signers). Most often a programmer mistake; not strictly
    /// exploitable, so the rule currently does not fire on it.
    Absent,
}

#[derive(Debug, Clone)]
pub enum AstHintKind {
    /// A field of an `#[derive(Accounts)]` struct.
    AccountsField {
        /// Owning struct name. Reserved for cross-struct linking
        /// (a future task will key the field hint index by
        /// `(instruction_name, struct_name, field_name)` instead of
        /// `field_name` alone).
        #[allow(dead_code)]
        struct_name: String,
        field_name: String,
        /// "Signer", "Account<'info, T>", "AccountInfo", "SystemAccount", etc.
        ty: String,
        /// Constraint attributes like `mut`, `seeds`, `bump`, `has_one`.
        constraints: Vec<String>,
    },
    /// A `pub fn` in an `#[program]` impl block.
    InstructionHandler {
        /// Owning struct name. Reserved for the Week-4+ cross-link
        /// between IDL instructions and AST handlers.
        #[allow(dead_code)]
        struct_name: String,
        /// Handler fn name. Reserved for the same cross-link.
        #[allow(dead_code)]
        fn_name: String,
    },
    /// An unchecked arithmetic op (`+`, `-`, `*`, `/`, `%`).
    UnsafeArithmetic {
        op: String,
        lhs_ty: String,
        rhs_ty: String,
    },
    /// A lamports subtraction (debit) on an account.
    LamportsDebit {
        account: String,
        amount_expr: String,
        seq: usize,
    },
    /// A lamports addition (credit) on an account.
    LamportsCredit {
        account: String,
        amount_expr: String,
        seq: usize,
    },
    /// A guard/comparison involving lamports/balance (if, require!, >=, etc.).
    BalanceCheck {
        account: String,
        check_type: String,
        seq: usize,
    },
    /// Lamports explicitly zeroed (`lamports = 0`, `set_lamports(0)`).
    LamportsZero { account: String, seq: usize },
    /// CPI that may transfer lamports (`invoke` / `invoke_signed`).
    CpiTransfer { target: String, seq: usize },
    /// `invoke_signed` call with the signer-seeds safety classification.
    /// The `cpi_signer_seed_validation` rule fires Critical findings for
    /// `Seeds::Dynamic` — i.e. seeds that contain function args or any
    /// expression the AST layer can't verify as canonical. `Seeds::Safe`
    /// means every seed slice was either a `b"..."` literal, a
    /// `ctx.bumps.<ident>` canonical bump, or a `.key().as_ref()` on a
    /// known account. `Seeds::Absent` is the rare case where the third
    /// argument was empty (no signers, equivalent to plain `invoke`).
    CpiInvokeSigned {
        /// The CPI target. Currently unused by the rule but kept for
        /// future cross-referencing and to maintain symmetry with
        /// `CpiTransfer`.
        #[allow(dead_code)]
        target: String,
        /// Monotonic sequence number for ordering. Currently unused.
        #[allow(dead_code)]
        seq: usize,
        seeds: SignerSeedClass,
        /// Short human description of the seeds for the rule's finding
        /// message — e.g. `"b\"vault\", ctx.bumps.vault"` or
        /// `"args.bump (function arg)"`.
        seed_summary: String,
    },
    /// An `as` cast between two integer-typed expressions. The rule
    /// `integer_cast_truncation` only fires when the source is wider than
    /// the destination (e.g. `u64` → `u8`); widening casts are emitted too
    /// so future rules (overflow on downcast, lossy float→int) can reuse
    /// the hint.
    IntegerCast { from_ty: String, to_ty: String },
}

/// The interface every rule implements.
pub trait Rule: Send + Sync {
    /// Stable identifier used in `--ignore` flags and JSON output.
    fn id(&self) -> &'static str;
    /// Short human description, used by `sentinel rules`.
    fn description(&self) -> &'static str;
    /// Default severity for findings from this rule.
    fn severity(&self) -> Severity;
    /// Inspect the context and return any findings.
    fn check(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
}

/// Run every registered rule over `ctx`, returning all findings.
pub fn run_all_rules(ctx: &AnalysisContext) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for rule in registry::all_rules() {
        out.extend(rule.check(ctx)?);
    }
    Ok(out)
}

/// Build a quick lookup from field_name → the AST hint that first declared
/// it. Rules use this to stamp source locations onto findings, since IDL
/// alone carries no `file:line:column` for individual accounts.
///
/// In the rare case where the same field name appears on multiple structs
/// (e.g. `authority` on both `Deposit` and `Withdraw`) the first hint wins.
/// That's acceptable for a static analysis tool — the message says
/// "Account `authority` on instruction `withdraw`" and the line points at
/// one of the declarations; the user can fix the right one from the
/// instruction name alone.
pub fn field_hint_index(ctx: &AnalysisContext) -> std::collections::HashMap<String, AstHint> {
    let mut index = std::collections::HashMap::new();
    for hint in &ctx.ast_hints {
        if let AstHintKind::AccountsField { field_name, .. } = &hint.kind {
            index
                .entry(field_name.clone())
                .or_insert_with(|| hint.clone());
        }
    }
    index
}
