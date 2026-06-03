// Clean CPI fixture — used to verify the `cpi_signer_seed_validation`
// rule does NOT fire when the signer seeds are composed of canonical
// sources. All three handlers use the safe pattern:
//   - byte string literals
//   - `ctx.accounts.<signer>.key().as_ref()` for the user pubkey
//   - `ctx.bumps.<field>` for the canonical bump

use anchor_lang::prelude::*;
use solana_program::program::invoke_signed;

declare_id!("CpiC1ean111111111111111111111111111111111111");

#[program]
pub mod cpi_clean {
    use super::*;

    // SAFE: literal `b"vault"`, `ctx.accounts.user.key().as_ref()` for
    // the user pubkey, `ctx.bumps.vault` for the canonical bump.
    pub fn withdraw_pda(ctx: Context<WithdrawPda>) -> Result<()> {
        let ix = solana_program::system_instruction::transfer(
            &ctx.accounts.vault.key(),
            &ctx.accounts.destination.key(),
            1_000_000,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.vault.to_account_info()],
            &[&[
                b"vault",
                ctx.accounts.user.key().as_ref(),
                &[ctx.bumps.vault],
            ]],
        )?;
        Ok(())
    }

    // SAFE: same shape, multiple signers — two PDAs in one call.
    pub fn withdraw_dual_pda(ctx: Context<WithdrawDualPda>) -> Result<()> {
        let ix = solana_program::system_instruction::transfer(
            &ctx.accounts.vault_a.key(),
            &ctx.accounts.destination.key(),
            1_000_000,
        );
        invoke_signed(
            &ix,
            &[
                ctx.accounts.vault_a.to_account_info(),
                ctx.accounts.vault_b.to_account_info(),
            ],
            &[
                &[b"vault_a", &[ctx.bumps.vault_a]],
                &[b"vault_b", &[ctx.bumps.vault_b]],
            ],
        )?;
        Ok(())
    }

    // SAFE: pure literal seeds — no user input at all.
    pub fn withdraw_literal(ctx: Context<WithdrawLiteral>) -> Result<()> {
        let ix = solana_program::system_instruction::transfer(
            &ctx.accounts.vault.key(),
            &ctx.accounts.destination.key(),
            1_000_000,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.vault.to_account_info()],
            &[&[b"vault", &[ctx.bumps.vault]]],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawPda<'info> {
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WithdrawDualPda<'info> {
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"vault_a"], bump)]
    pub vault_a: Account<'info, Vault>,
    #[account(mut, seeds = [b"vault_b"], bump)]
    pub vault_b: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WithdrawLiteral<'info> {
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub bump: u8,
}
