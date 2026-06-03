//! Built-in rules. Each rule lives in its own submodule and self-registers
//! via `inventory::submit!`. To add a rule, drop a new file here and add a
//! `pub mod <name>;` line — no central edit.

use std::sync::Arc;

use crate::engine::Severity;
use crate::engine::{registry::RuleFactory, Rule};

pub mod duplicate_mutable_accounts;
pub mod lamports_drain;
pub mod missing_balance_check;
pub mod missing_bump_seed_canonicalization;
pub mod missing_mut;
pub mod missing_ownership;
pub mod missing_signer;
pub mod pda_misconfig;
pub mod unchecked_balance_flow;
pub mod unsafe_arithmetic;

// `inventory` requires the submission to be reachable from a `static` of the
// crate. Putting them in a `#[distributed_slice]`-style static list keeps the
// linker from dropping them.
inventory::submit! {
    RuleFactory { build: || Arc::new(missing_signer::MissingSigner) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(missing_ownership::MissingOwnership) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(unsafe_arithmetic::UnsafeArithmetic) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(missing_mut::MissingMut) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(pda_misconfig::PdaMisconfig) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(missing_balance_check::MissingBalanceCheck) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(missing_bump_seed_canonicalization::MissingBumpSeedCanonicalization) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(duplicate_mutable_accounts::DuplicateMutableAccounts) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(lamports_drain::LamportsDrain) as Arc<dyn Rule> }
}
inventory::submit! {
    RuleFactory { build: || Arc::new(unchecked_balance_flow::UncheckedBalanceFlow) as Arc<dyn Rule> }
}

/// Rule metadata without instantiation — used by SARIF output and
/// `sentinel rules`. Returns `(rule_id, severity, description)`.
pub fn registered_rules() -> Vec<(&'static str, Severity, &'static str)> {
    crate::engine::registry::list_rule_ids()
}
