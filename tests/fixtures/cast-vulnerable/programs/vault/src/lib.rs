// Vulnerable vault — used to drive the `integer_cast_truncation` rule.
//
// The handlers accept a `u64 amount` and silently narrow it into a `u8`
// before storing it in account data. A user passing 1_000 SOL (which is
// well within `u64`) will see their balance truncated to the low 8 bits,
// and the on-chain error surfaces far from the offending cast.
//
// Sentinel should flag every `as u8` / `as u16` cast on a `u64` source.

use anchor_lang::prelude::*;

declare_id!("CASTvu111111111111111111111111111111111111");

#[program]
pub mod cast_vulnerable {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG: `amount` is `u64`; storing it as `u8` truncates the high 56 bits.
        let truncated: u8 = amount as u8;
        vault.balance = truncated;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG: same shape as deposit, but cast to `u16` — still truncates.
        let truncated: u16 = amount as u16;
        vault.payout = truncated;
        Ok(())
    }

    pub fn audit(ctx: Context<Audit>, amount: u64) -> Result<()> {
        let audit = &mut ctx.accounts.audit;
        // SAFE: widening `u8 → u16` is fine; the rule should NOT flag this.
        let widened: u16 = ctx.accounts.vault.balance as u16;
        audit.last_value = widened;
        // SAFE: same width (`u64 → u64`) is fine.
        audit.last_raw = amount as u64;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, CastVault>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, CastVault>,
}

#[derive(Accounts)]
pub struct Audit<'info> {
    pub auditor: Signer<'info>,
    pub vault: Account<'info, CastVault>,
    #[account(mut)]
    pub audit: Account<'info, CastAudit>,
}

#[account]
pub struct CastVault {
    pub balance: u8,
    pub payout: u16,
}

#[account]
pub struct CastAudit {
    pub last_value: u16,
    pub last_raw: u64,
}
