// Clean close fixture — used to verify the `missing_close_authority`
// rule does NOT fire when the close target is properly bound. Three
// safe patterns are exercised:
//
//   1. `close_authority_signed` — close target is a `Signer<'info>`.
//   2. `close_authority_has_one` — close target is bound via
//      `has_one = authority` on the account being closed.
//   3. `close_authority_constraint` — close target is referenced in a
//      `constraint = …` expression that gates the call.

use anchor_lang::prelude::*;

declare_id!("CloseC1ean11111111111111111111111111111111111");

#[program]
pub mod close_clean {
    use super::*;

    pub fn close_authority_signed(ctx: Context<CloseAuthoritySigned>) -> Result<()> {
        // SAFE: `authority` is a `Signer<'info>` — Anchor will fail the
        // transaction if the caller didn't sign with that key.
        Ok(())
    }

    pub fn close_authority_has_one(ctx: Context<CloseAuthorityHasOne>) -> Result<()> {
        // SAFE: `has_one = authority` on the vault forces the on-chain
        // account's `authority` field to match the `authority` account
        // passed in. Anyone can be `authority`, but the vault can only
        // have been created with that authority — the original creator
        // gets the rent.
        Ok(())
    }

    pub fn close_authority_constraint(ctx: Context<CloseAuthorityConstraint>) -> Result<()> {
        // SAFE: the `constraint` expression references `authority` and
        // performs an explicit key check before the close happens.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CloseAuthoritySigned<'info> {
    pub authority: Signer<'info>,
    #[account(mut, close = authority)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct CloseAuthorityHasOne<'info> {
    pub authority: AccountInfo<'info>,
    #[account(mut, close = authority, has_one = authority)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct CloseAuthorityConstraint<'info> {
    pub authority: AccountInfo<'info>,
    #[account(
        mut,
        close = authority,
        constraint = vault.authority == authority.key() @ VaultError::Unauthorized,
    )]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("unauthorized close")]
    Unauthorized,
}
