// Vulnerable close fixture — used to drive the `missing_close_authority`
// rule. The `close = receiver` constraint on every handler hands the
// rent-exempt lamports to a `receiver` field that's typed as a plain
// `AccountInfo`, so any pubkey can be passed as `receiver` and walk
// away with the rent. Sentinel should flag all three handlers.

use anchor_lang::prelude::*;

declare_id!("CloseVauLT11111111111111111111111111111111111");

#[program]
pub mod close_vulnerable {
    use super::*;

    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        // VULN: receiver is plain AccountInfo — no signer, no authority check.
        // Anyone can call this with their own pubkey as `receiver` and
        // drain the rent-exempt lamports.
        Ok(())
    }

    pub fn force_close(ctx: Context<ForceClose>) -> Result<()> {
        // VULN: same shape, different struct.
        Ok(())
    }

    pub fn admin_close(ctx: Context<AdminClose>) -> Result<()> {
        // VULN: target is a system account, not a signer.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    /// VULN: not a Signer, no has_one binding to receiver.
    pub receiver: AccountInfo<'info>,
    #[account(mut, close = receiver)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct ForceClose<'info> {
    /// VULN: same — plain AccountInfo.
    pub receiver: AccountInfo<'info>,
    #[account(mut, close = receiver)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct AdminClose<'info> {
    /// VULN: SystemAccount isn't a signer.
    pub receiver: SystemAccount<'info>,
    #[account(mut, close = receiver)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
