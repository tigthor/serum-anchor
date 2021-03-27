#![feature(proc_macro_hygiene)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_option::COption;
use anchor_spl::token::{self, Mint, TokenAccount};

#[program]
pub mod pool {
    use super::*;

    // Initializes a new pool.
    #[access_control(Init::accounts(&ctx, nonce))]
    pub fn init(ctx: Context<Init>, fee_rate: u32, nonce: u8) -> Result<()> {
        let pool_signer = ctx.accounts.pool_signer.key;
        let pool = &mut ctx.accounts.pool;
        pool.mint = *ctx.accounts.mint.to_account_info().key;
        pool.fee_vault = *ctx.accounts.fee_vault.to_account_info().key;
        pool.fee_rate = fee_rate;
        pool.nonce = nonce;
        pool.asset_vaults = ctx
            .remaining_accounts
            .iter()
            .map(|acc| {
                assert!(acc.owner == &token::ID);
                let vault = *acc.key;
                let mut data: &[u8] = &acc.try_borrow_data()?;
                let vault_account = TokenAccount::try_deserialize(&mut data)?;
                assert!(&vault_account.owner == pool_signer);
                let mint = vault_account.mint;
                Ok(AssetInfo { mint, vault })
            })
            .collect::<Result<Vec<AssetInfo>>>()?;
        Ok(())
    }

    // Creates pool tokens for a user.
    pub fn create(ctx: Context<Execute>, size: u64) -> Result<()> {
        Ok(())
    }

    // Redeems pool tokens for a user.
    pub fn redeem(ctx: Context<Execute>, size: u64) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init)]
    pool: ProgramAccount<'info, Pool>,
    pool_signer: AccountInfo<'info>,
    #[account("mint.mint_authority == COption::Some(*pool_signer.key)")]
    mint: CpiAccount<'info, Mint>,
    #[account("&fee_vault.owner == pool_signer.key")]
    fee_vault: CpiAccount<'info, TokenAccount>,
    rent: Sysvar<'info, Rent>,
}

impl<'info> Init<'info> {
    pub fn accounts(ctx: &Context<Init>, nonce: u8) -> Result<()> {
        let signer = Pubkey::create_program_address(
            &[ctx.accounts.pool.to_account_info().key.as_ref(), &[nonce]],
            ctx.program_id,
        )
        .map_err(|_| ErrorCode::InvalidPoolSigner)?;
        if ctx.accounts.pool_signer.key != &signer {
            return Err(ErrorCode::InvalidPoolSigner.into());
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(mut, has_one = mint, has_one = fee_vault)]
    pool: ProgramAccount<'info, Pool>,
    #[account(mut)]
    mint: CpiAccount<'info, Mint>,
    // todo: vault for each pool asset
    #[account(seeds = [
        pool.to_account_info().key.as_ref(),
        &[pool.nonce],
    ])]
    pool_signer: AccountInfo<'info>,
    #[account(mut)]
    fee_vault: AccountInfo<'info>,

    #[account(mut)]
    user_pool_token: AccountInfo<'info>,
    // todo: accounts for each of the assets
    #[account(signer)]
    user_authority: AccountInfo<'info>,

    token_program: AccountInfo<'info>,
}

#[account]
pub struct Pool {
    /// Pool token mint.
    pub mint: Pubkey,
    /// Assets in the pool.
    pub asset_vaults: Vec<AssetInfo>,
    /// Vault for fees collected by the pool. Mint is the pool token mint.
    pub fee_vault: Pubkey,
    /// Fee on creations and redemptions, per million tokens.
    pub fee_rate: u32,
    /// Bump seed for the pool signer.
    pub nonce: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AssetInfo {
    pub mint: Pubkey,
    pub vault: Pubkey,
}

#[error]
pub enum ErrorCode {
    #[msg("Invalid pool signer given.")]
    InvalidPoolSigner,
}
