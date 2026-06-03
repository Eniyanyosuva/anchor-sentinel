// Vulnerable CPI fixture — used to drive the `cpi_signer_seed_validation`
// rule. All four handlers call `invoke_signed` with seeds the AST layer
// cannot verify: function args, locally-bound variables, or
// user-controlled fields. Each handler should fire a Critical finding.

use anchor_lang::prelude::*;
use solana_program::program::invoke_signed;

declare_id!("CpiVauLT111111111111111111111111111111111111");

#[program]
pub mod cpi_vulnerable {
    use super::*;

    // VULN: `user_bump` is a function arg — the attacker controls it
    // and can compute their own valid PDA from the same seeds.
    pub fn withdraw_arg_bump(
        ctx: Context<WithdrawArgBump>,
        user_bump: u8,
    ) -> Result<()> {
        let ix = solana_program::system_instruction::transfer(
            &ctx.accounts.vault.key(),
            &ctx.accounts.destination.key(),
            1_000_000,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.vault.to_account_info()],
            &[&[b"vault", ctx.accounts.user.key().as_ref(), &[user_bump]]],
        )?;
        Ok(())
    }

    // VULN: seeds contain a `ctx.accounts.attacker` field directly —
    // the user passes any pubkey as `attacker`, and the program signs
    // for that pubkey. The seeds are technically well-formed but the
    // `attacker` field is not enforced as a Signer or authority, so the
    // attacker can pick any pubkey and compute a matching PDA. Sentinel
    // reports this via `missing_signer` on `attacker` rather than via
    // `cpi_signer_seed_validation`, because the seeds themselves ARE
    // canonical — the vulnerability lives in the Accounts struct.
    pub fn withdraw_attacker_key(
        ctx: Context<WithdrawAttackerKey>,
    ) -> Result<()> {
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
                ctx.accounts.attacker.key().as_ref(),
                &[ctx.bumps.vault],
            ]],
        )?;
        Ok(())
    }

    // VULN: seeds use a user-supplied `seed_vec` function arg as the
    // bump byte. The attacker controls the entire seed array.
    pub fn withdraw_arg_bump_byte(
        ctx: Context<WithdrawArgBumpByte>,
        bump: u8,
    ) -> Result<()> {
        let ix = solana_program::system_instruction::transfer(
            &ctx.accounts.vault.key(),
            &ctx.accounts.destination.key(),
            1_000_000,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.vault.to_account_info()],
            &[&[b"vault", ctx.accounts.user.key().as_ref(), &[bump]]],
        )?;
        Ok(())
    }

    // VULN: `bump` is a locally-bound `u8` from an `unwrap()`. Whatever
    // the value, the AST layer can't tie it to a canonical bump.
    pub fn withdraw_local_bump(ctx: Context<WithdrawLocalBump>) -> Result<()> {
        let bump: u8 = ctx.accounts.vault.bump.try_into().unwrap();
        let ix = solana_program::system_instruction::transfer(
            &ctx.accounts.vault.key(),
            &ctx.accounts.destination.key(),
            1_000_000,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.vault.to_account_info()],
            &[&[b"vault", ctx.accounts.user.key().as_ref(), &[bump]]],
        )?;
        Ok(())
    }

    // VULN: seeds are a function arg slice — fully attacker-controlled.
    pub fn withdraw_dynamic(
        ctx: Context<WithdrawDynamic>,
        seeds: Vec<Vec<u8>>,
    ) -> Result<()> {
        let _ = seeds;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawArgBump<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WithdrawArgBumpByte<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WithdrawLocalBump<'info> {
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WithdrawDynamic<'info> {
    pub user: Signer<'info>,
    pub vault: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub bump: u8,
}
