# variable-k-AMM
A weird tokenomic for an abandonned casino projet ! &lt;3

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, MintTo, Burn};

declare_id!("7eiX7pdAfzK5nBTR6HpJA2BR6BwaWoZ9HHawc5W8Dj7y");

const PRECISION: u128 = 1_000_000_000; // 10^9 pour les calculs
const BPS_DENOMINATOR: u128 = 10_000;
const MAX_FEE_BPS: u128 = 5_000; // 50% maximum

#[program]
pub mod mgc_token {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        initial_sol_reserve: u64,
        virtual_sol_reserve: u64,
        virtual_token_supply: u64,
        base_fee_in_bps: u16,
        base_fee_out_bps: u16,
        alpha_in: u64,
        alpha_out: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.mint = ctx.accounts.mint.key();
        pool.sol_reserve = initial_sol_reserve;
        pool.token_supply = 0;
        pool.virtual_sol_reserve = virtual_sol_reserve;
        pool.virtual_token_supply = virtual_token_supply;
        pool.base_fee_in_bps = base_fee_in_bps;
        pool.base_fee_out_bps = base_fee_out_bps;
        pool.alpha_in = alpha_in;
        pool.alpha_out = alpha_out;
        
        let effective_sol = (initial_sol_reserve as u128)
            .checked_add(virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        let effective_token = virtual_token_supply as u128;
        
        pool.k_constant = effective_sol
            .checked_mul(effective_token)
            .ok_or(ErrorCode::MathOverflow)?;

        pool.authorized_minters = Vec::new();
        pool.authorized_burners = Vec::new();
        
        Ok(())
    }

    /// Ajouter un contrat autorisé pour le minting
    pub fn add_authorized_minter(
        ctx: Context<ManageAuthorization>,
        minter: Pubkey,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(
            ctx.accounts.authority.key() == pool.authority,
            ErrorCode::Unauthorized
        );
        
        if !pool.authorized_minters.contains(&minter) {
            pool.authorized_minters.push(minter);
        }
        
        Ok(())
    }

    /// Ajouter un contrat autorisé pour le burning
    pub fn add_authorized_burner(
        ctx: Context<ManageAuthorization>,
        burner: Pubkey,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(
            ctx.accounts.authority.key() == pool.authority,
            ErrorCode::Unauthorized
        );
        
        if !pool.authorized_burners.contains(&burner) {
            pool.authorized_burners.push(burner);
        }
        
        Ok(())
    }

    /// Mint de tokens (réservé aux contrats autorisés)
    pub fn authorized_mint(
        ctx: Context<AuthorizedMint>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        require!(
            pool.authorized_minters.contains(&ctx.accounts.caller.key()),
            ErrorCode::UnauthorizedMinter
        );

        let seeds = &[b"pool_v5".as_ref(), &[ctx.bumps.pool]];
        let signer = &[&seeds[..]];
        
        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: pool.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        
        token::mint_to(cpi_ctx, amount)?;
        
        // Mettre à jour token_supply avec checked_add
        pool.token_supply = pool.token_supply
            .checked_add(amount)
            .ok_or(ErrorCode::MathOverflow)?;
        
        // Recalculer k avec réserves virtuelles
        let effective_sol = (pool.sol_reserve as u128)
            .checked_add(pool.virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        let effective_token = (pool.token_supply as u128)
            .checked_add(pool.virtual_token_supply as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        pool.k_constant = effective_sol
            .checked_mul(effective_token)
            .ok_or(ErrorCode::MathOverflow)?;
        
        Ok(())
    }

    /// Burn de tokens (réservé aux contrats autorisés)
    pub fn authorized_burn(
        ctx: Context<AuthorizedBurn>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        require!(
            pool.authorized_burners.contains(&ctx.accounts.caller.key()),
            ErrorCode::UnauthorizedBurner
        );

        let cpi_accounts = Burn {
            mint: ctx.accounts.mint.to_account_info(),
            from: ctx.accounts.source.to_account_info(),
            authority: ctx.accounts.caller.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        
        token::burn(cpi_ctx, amount)?;
        
        // Mettre à jour token_supply avec checked_sub
        pool.token_supply = pool.token_supply
            .checked_sub(amount)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        // Recalculer k avec réserves virtuelles
        let effective_sol = (pool.sol_reserve as u128)
            .checked_add(pool.virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        let effective_token = (pool.token_supply as u128)
            .checked_add(pool.virtual_token_supply as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        pool.k_constant = effective_sol
            .checked_mul(effective_token)
            .ok_or(ErrorCode::MathOverflow)?;
        
        Ok(())
    }

    /// Acheter des MGC avec des SOL (swap SOL → MGC)
    pub fn buy_tokens(
        ctx: Context<BuyTokens>,
        sol_amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        require!(sol_amount > 0, ErrorCode::InvalidAmount);
        
        // Calculer les frais d'entrée dynamiques en u128
        // Note: calculate_entry_fee uses reserve ratio. We should use effective reserve?
        // For fees, maybe real reserve is better? Or effective?
        // Let's use effective reserve for stability.
        let effective_sol_reserve = (pool.sol_reserve as u128)
            .checked_add(pool.virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;

        let fee_bps = calculate_entry_fee(
            sol_amount,
            effective_sol_reserve as u64, // Cast safe if u64
            pool.base_fee_in_bps,
            pool.alpha_in,
        )?;
        
        // Calculer les frais en u128 pour éviter les erreurs de rounding
        let sol_amount_u128 = sol_amount as u128;
        let fee_amount_u128 = sol_amount_u128
            .checked_mul(fee_bps)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(BPS_DENOMINATOR)
            .ok_or(ErrorCode::MathOverflow)?;
        
        let fee_amount = fee_amount_u128 as u64;
        let sol_after_fee = sol_amount
            .checked_sub(fee_amount)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        require!(sol_after_fee > 0, ErrorCode::FeeTooHigh);
        
        // Formule AMM: tokens_out = supply - (k / (reserve + sol_in))
        let new_effective_reserve = effective_sol_reserve
            .checked_add(sol_after_fee as u128)
            .ok_or(ErrorCode::MathOverflow)?;
        
        // new_supply = k / new_reserve
        let new_effective_supply = pool.k_constant
            .checked_div(new_effective_reserve)
            .ok_or(ErrorCode::DivisionByZero)?;
        
        // tokens_to_mint = current_supply - new_supply
        let current_effective_supply = (pool.token_supply as u128)
            .checked_add(pool.virtual_token_supply as u128)
            .ok_or(ErrorCode::MathOverflow)?;
        
        // Protection
        require!(
            current_effective_supply > new_effective_supply,
            ErrorCode::InvalidAMMState
        );
        
        let tokens_to_mint_u128 = current_effective_supply
            .checked_sub(new_effective_supply)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        require!(tokens_to_mint_u128 <= u64::MAX as u128, ErrorCode::MathOverflow);
        let tokens_to_mint = tokens_to_mint_u128 as u64;
        
        require!(tokens_to_mint > 0, ErrorCode::InvalidAmount);

        // Transférer les SOL de l'utilisateur vers le pool
        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.buyer.key(),
            &pool.key(),
            sol_amount,
        );
        anchor_lang::solana_program::program::invoke(
            &transfer_ix,
            &[
                ctx.accounts.buyer.to_account_info(),
                pool.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        // Mint les tokens MGC
        let seeds = &[b"pool_v5".as_ref(), &[ctx.bumps.pool]];
        let signer = &[&seeds[..]];
        
        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.buyer_token_account.to_account_info(),
            authority: pool.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        
        token::mint_to(cpi_ctx, tokens_to_mint)?;

        // Mettre à jour l'état du pool
        pool.sol_reserve = pool.sol_reserve
            .checked_add(sol_after_fee)
            .ok_or(ErrorCode::MathOverflow)?;
        
        pool.token_supply = pool.token_supply
            .checked_add(tokens_to_mint)
            .ok_or(ErrorCode::MathOverflow)?;
        
        // Recalculer k (fees increase liquidity)
        let final_effective_sol = (pool.sol_reserve as u128)
            .checked_add(pool.virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        let final_effective_token = (pool.token_supply as u128)
            .checked_add(pool.virtual_token_supply as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        pool.k_constant = final_effective_sol
            .checked_mul(final_effective_token)
            .ok_or(ErrorCode::MathOverflow)?;

        emit!(TokenPurchased {
            buyer: ctx.accounts.buyer.key(),
            sol_amount,
            fee_amount,
            tokens_received: tokens_to_mint,
            new_price: calculate_price(
                pool.sol_reserve, 
                pool.token_supply,
                pool.virtual_sol_reserve,
                pool.virtual_token_supply
            )?,
        });

        Ok(())
    }

    /// Vendre des MGC contre des SOL (swap MGC → SOL)
    pub fn sell_tokens(
        ctx: Context<SellTokens>,
        token_amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        require!(token_amount > 0, ErrorCode::InvalidAmount);
        require!(pool.token_supply > 0, ErrorCode::InvalidAMMState);
        require!(pool.sol_reserve > 0, ErrorCode::InsufficientReserve);
        require!(pool.k_constant > 0, ErrorCode::InvalidAMMState);
        
        // Calculer le montant de SOL selon la bonding curve
        let effective_token_supply = (pool.token_supply as u128)
            .checked_add(pool.virtual_token_supply as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        let new_effective_supply = effective_token_supply
            .checked_add(token_amount as u128)
            .ok_or(ErrorCode::MathOverflow)?;
        
        require!(new_effective_supply > 0, ErrorCode::InvalidAMMState);
        
        // new_reserve = k / new_supply
        let new_effective_reserve = pool.k_constant
            .checked_div(new_effective_supply)
            .ok_or(ErrorCode::DivisionByZero)?;
        
        let effective_sol_reserve = (pool.sol_reserve as u128)
            .checked_add(pool.virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;
        
        // Protection: new_reserve doit être < current_reserve
        require!(
            new_effective_reserve < effective_sol_reserve,
            ErrorCode::InvalidAMMState
        );
        
        let sol_out_before_fee_u128 = effective_sol_reserve
            .checked_sub(new_effective_reserve)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        require!(
            sol_out_before_fee_u128 <= u64::MAX as u128,
            ErrorCode::MathOverflow
        );
        let sol_out_before_fee = sol_out_before_fee_u128 as u64;
        
        require!(sol_out_before_fee > 0, ErrorCode::InvalidAmount);
        
        // Calculer les frais de sortie dynamiques
        let fee_bps = calculate_exit_fee(
            sol_out_before_fee,
            effective_sol_reserve as u64, // Use effective reserve
            pool.base_fee_out_bps,
            pool.alpha_out,
        )?;
        
        // Calculer les frais en u128
        let fee_amount_u128 = (sol_out_before_fee as u128)
            .checked_mul(fee_bps)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(BPS_DENOMINATOR)
            .ok_or(ErrorCode::MathOverflow)?;
        
        let fee_amount = fee_amount_u128 as u64;
        let sol_to_transfer = sol_out_before_fee
            .checked_sub(fee_amount)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        require!(sol_to_transfer > 0, ErrorCode::FeeTooHigh);
        require!(
            pool.sol_reserve >= sol_out_before_fee, // Must have enough REAL SOL
            ErrorCode::InsufficientReserve
        );

        // Burn les tokens MGC
        let cpi_accounts = Burn {
            mint: ctx.accounts.mint.to_account_info(),
            from: ctx.accounts.seller_token_account.to_account_info(),
            authority: ctx.accounts.seller.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        
        token::burn(cpi_ctx, token_amount)?;

        // Transférer les SOL du pool vers le vendeur
        **pool.to_account_info().try_borrow_mut_lamports()? = pool
            .to_account_info()
            .lamports()
            .checked_sub(sol_to_transfer)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        **ctx.accounts.seller.to_account_info().try_borrow_mut_lamports()? = ctx
            .accounts
            .seller
            .to_account_info()
            .lamports()
            .checked_add(sol_to_transfer)
            .ok_or(ErrorCode::MathOverflow)?;

        // Mettre à jour l'état du pool avec checked operations
        pool.sol_reserve = pool.sol_reserve
            .checked_sub(sol_out_before_fee)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        pool.token_supply = pool.token_supply
            .checked_sub(token_amount)
            .ok_or(ErrorCode::MathUnderflow)?;
        
        // Recalculer k (fees stay in pool, increasing K)
        let final_effective_sol = (pool.sol_reserve as u128)
            .checked_add(pool.virtual_sol_reserve as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        let final_effective_token = (pool.token_supply as u128)
            .checked_add(pool.virtual_token_supply as u128)
            .ok_or(ErrorCode::MathOverflow)?;
            
        pool.k_constant = final_effective_sol
            .checked_mul(final_effective_token)
            .ok_or(ErrorCode::MathOverflow)?;

        emit!(TokenSold {
            seller: ctx.accounts.seller.key(),
            tokens_sold: token_amount,
            sol_received: sol_to_transfer,
            fee_amount,
            new_price: calculate_price(
                pool.sol_reserve, 
                pool.token_supply,
                pool.virtual_sol_reserve,
                pool.virtual_token_supply
            )?,
        });

        Ok(())
    }
}

// Calcul des frais d'entrée dynamiques avec gestion complète des erreurs
fn calculate_entry_fee(
    amount_in: u64,
    reserve: u64,
    base_fee_bps: u16,
    alpha: u64,
) -> Result<u128> {
    require!(reserve > 0, ErrorCode::DivisionByZero);
    
    // f_in = f_base + α · log(1 + ΔMint / R_pool)
    let ratio = (amount_in as u128)
        .checked_mul(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(reserve as u128)
        .ok_or(ErrorCode::DivisionByZero)?;
    
    let log_approx = approximate_log(ratio)?;
    
    let dynamic_component = (alpha as u128)
        .checked_mul(log_approx)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?;
    
    let total_fee = (base_fee_bps as u128)
        .checked_add(dynamic_component)
        .ok_or(ErrorCode::MathOverflow)?;
    
    // Cap à MAX_FEE_BPS (50%)
    Ok(std::cmp::min(total_fee, MAX_FEE_BPS))
}

// Calcul des frais de sortie dynamiques
fn calculate_exit_fee(
    amount_out: u64,
    reserve: u64,
    base_fee_bps: u16,
    alpha: u64,
) -> Result<u128> {
    require!(reserve > 0, ErrorCode::DivisionByZero);
    
    // f_out = f_base + α · log(1 + R_out / R_pool)
    let ratio = (amount_out as u128)
        .checked_mul(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(reserve as u128)
        .ok_or(ErrorCode::DivisionByZero)?;
    
    let log_approx = approximate_log(ratio)?;
    
    let dynamic_component = (alpha as u128)
        .checked_mul(log_approx)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?;
    
    let total_fee = (base_fee_bps as u128)
        .checked_add(dynamic_component)
        .ok_or(ErrorCode::MathOverflow)?;
    
    // Cap à MAX_FEE_BPS (50%)
    Ok(std::cmp::min(total_fee, MAX_FEE_BPS))
}

// Approximation du logarithme naturel avec gestion d'erreurs
fn approximate_log(x: u128) -> Result<u128> {
    // Approximation de ln(1 + x) pour x petit: ln(1+x) ≈ x - x²/2 + x³/3
    if x == 0 {
        return Ok(0);
    }
    
    let x_squared = x
        .checked_mul(x)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?;
    
    let x_cubed = x_squared
        .checked_mul(x)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?;
    
    let term2 = x_squared
        .checked_div(2)
        .ok_or(ErrorCode::MathOverflow)?;
    
    let term3 = x_cubed
        .checked_div(3)
        .ok_or(ErrorCode::MathOverflow)?;
    
    let result = x
        .checked_sub(term2)
        .ok_or(ErrorCode::MathUnderflow)?
        .checked_add(term3)
        .ok_or(ErrorCode::MathOverflow)?;
    
    Ok(result)
}

// Calculer le prix actuel (SOL par MGC, scaled by PRECISION)
fn calculate_price(
    sol_reserve: u64, 
    token_supply: u64,
    virtual_sol: u64,
    virtual_token: u64
) -> Result<u64> {
    let effective_sol = (sol_reserve as u128)
        .checked_add(virtual_sol as u128)
        .ok_or(ErrorCode::MathOverflow)?;
        
    let effective_token = (token_supply as u128)
        .checked_add(virtual_token as u128)
        .ok_or(ErrorCode::MathOverflow)?;

    if effective_token == 0 {
        return Ok(0);
    }
    
    let price_u128 = effective_sol
        .checked_mul(PRECISION)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(effective_token)
        .ok_or(ErrorCode::DivisionByZero)?;
    
    require!(price_u128 <= u64::MAX as u128, ErrorCode::MathOverflow);
    Ok(price_u128 as u64)
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool_v5"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    /// CHECK: token Mint account - will be initialized via CPI
    pub mint: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct ManageAuthorization<'info> {
    #[account(
        mut,
        seeds = [b"pool_v5"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AuthorizedMint<'info> {
    #[account(
        mut,
        seeds = [b"pool_v5"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    /// CHECK: token Mint account
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,
    
    /// CHECK: destination token account owned by Token program
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    
    pub caller: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct AuthorizedBurn<'info> {
    #[account(
        mut,
        seeds = [b"pool_v5"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    /// CHECK: token Mint account
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,
    
    /// CHECK: source token account owned by Token program
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    
    pub caller: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct BuyTokens<'info> {
    #[account(
        mut,
        seeds = [b"pool_v5"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    /// CHECK: token Mint account
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub buyer: Signer<'info>,
    
    /// CHECK: buyer token account owned by Token program
    #[account(mut)]
    pub buyer_token_account: UncheckedAccount<'info>,
    
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SellTokens<'info> {
    #[account(
        mut,
        seeds = [b"pool_v5"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    /// CHECK: token Mint account
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub seller: Signer<'info>,
    
    /// CHECK: seller token account owned by Token program
    #[account(mut)]
    pub seller_token_account: UncheckedAccount<'info>,
    
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub sol_reserve: u64,
    pub token_supply: u64,
    pub k_constant: u128, // En u128 pour éviter overflow
    pub base_fee_in_bps: u16,
    pub base_fee_out_bps: u16,
    pub alpha_in: u64,
    pub alpha_out: u64,
    pub virtual_sol_reserve: u64,
    pub virtual_token_supply: u64,
    #[max_len(10)]
    pub authorized_minters: Vec<Pubkey>,
    #[max_len(10)]
    pub authorized_burners: Vec<Pubkey>,
}

#[event]
pub struct TokenPurchased {
    pub buyer: Pubkey,
    pub sol_amount: u64,
    pub fee_amount: u64,
    pub tokens_received: u64,
    pub new_price: u64,
}

#[event]
pub struct TokenSold {
    pub seller: Pubkey,
    pub tokens_sold: u64,
    pub sol_received: u64,
    pub fee_amount: u64,
    pub new_price: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Non autorisé")]
    Unauthorized,
    #[msg("Minter non autorisé")]
    UnauthorizedMinter,
    #[msg("Burner non autorisé")]
    UnauthorizedBurner,
    #[msg("Réserve de SOL insuffisante")]
    InsufficientReserve,
    #[msg("Overflow mathématique")]
    MathOverflow,
    #[msg("Underflow mathématique")]
    MathUnderflow,
    #[msg("Division par zéro")]
    DivisionByZero,
    #[msg("Montant invalide")]
    InvalidAmount,
    #[msg("État AMM invalide")]
    InvalidAMMState,
    #[msg("Réserve invalide")]
    InvalidReserve,
    #[msg("Frais trop élevés")]
    FeeTooHigh,
}
