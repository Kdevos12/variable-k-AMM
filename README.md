# variable-k-AMM
A weird tokenomic for an abandonned casino projet ! &lt;3

# MGC AMM - Technical Documentation

## Introduction

I started this project somewhat on a whim, driven by pure autism in november 2025?                                   
The initial idea was to create an AMM system for an online casino on Solana. The core concept was fairly straightforward: use a bonding curve with virtual reserves to manage a token (MGC) that would serve as casino chips. The objective was to have a mechanism where the casino's overall losses would be automatically amortized through the progressive increase of the K constant with each swap. Essentially, the more people play and lose, the more the pool's liquidity increases, which stabilizes the system. However, after reflection, I realized this was simply too much work, too much effort to maintain, and above all, far too legally problematic depending on jurisdiction. So I'm abandoning the casino project, but the code remains interesting from a technical standpoint.

From a technical perspective, I implemented a classic "constant" product AMM (x * y = k) but with several specific features. First, virtual reserves to simulate deep liquidity from the start without needing millions of SOL. Second, dynamic fees calculated with a logarithmic approximation that increase based on swap volume to prevent large-scale manipulation. The important aspect is that unlike a standard AMM, K is not constant , k increases with each transaction through fees that remain in the pool. I also added all standard security protections: strict account validation, slippage protection, 24-hour timelock on authorization changes, and complete transparency on real versus virtual reserves. The code is written in Rust with Anchor for Solana.

---

## Mathematical Documentation

### 1. Bonding Curve with Virtual Reserves

**Core principle:**
```
R_eff = R_real + R_virtual
S_eff = S_real + S_virtual

K = R_eff × S_eff
```

Where:
- `R_eff` = Effective SOL reserve
- `R_real` = Real SOL reserve (available for withdrawal)
- `R_virtual` = Virtual SOL reserve (liquidity simulation)
- `S_eff` = Effective token supply
- `S_real` = Real supply
- `S_virtual` = Virtual supply

### 2. SOL → MGC Swap (Token Purchase)

**Steps:**

1. **Entry fee calculation:**
   ```
   ratio = (amount_in × 10^9) / R_eff
   log_approx(x) ≈ x - x²/2 + x³/3
   f_in = f_base + α_in × log(1 + ratio)
   f_in = min(f_in, 50%)  // Capped at 50%
   ```

2. **Amount after fees:**
   ```
   sol_after_fee = sol_amount × (1 - f_in)
   ```

3. **Tokens to mint calculation:**
   ```
   R_new = R_eff + sol_after_fee
   S_new = K / R_new
   tokens_out = S_eff - S_new
   ```

4. **K update (increase via fees):**
   ```
   R_real_new = R_real + sol_after_fee
   S_real_new = S_real + tokens_out
   K_new = (R_real_new + R_virtual) × (S_real_new + S_virtual)
   ```

### 3. MGC → SOL Swap (Token Sale)

**Steps:**

1. **SOL output calculation (before fees):**
   ```
   S_new = S_eff + token_amount
   R_new = K / S_new
   sol_out_before_fee = R_eff - R_new
   ```

2. **Exit fee calculation:**
   ```
   ratio = (sol_out × 10^9) / R_eff
   f_out = f_base + α_out × log(1 + ratio)
   f_out = min(f_out, 50%)
   ```

3. **Final amount:**
   ```
   sol_to_user = sol_out_before_fee × (1 - f_out)
   ```

4. **K update (fees remain in pool):**
   ```
   R_real_new = R_real - sol_out_before_fee
   S_real_new = S_real - token_amount
   K_new = (R_real_new + R_virtual) × (S_real_new + S_virtual)
   ```

### 4. Spot Price

```
price = R_eff / S_eff × 10^9
```

Price in lamports per token, multiplied by 10^9 for precision.

### 5. Key Mathematical Property

**K increases with each swap:**
```
ΔK = fee_amount × S_eff  (for buy)
ΔK = fee_amount × S_eff  (for sell)
```

This accumulation effect enables loss amortization in the casino context.

---

## IT Documentation

### Architecture

**Program:** `mgc_token` (Solana/Anchor)
**Language:** Rust
**Framework:** Anchor 0.29
**Binary size:** 309 KB

### Main Structures

```rust
pub struct Pool {
    authority: Pubkey,           // Pool authority
    mint: Pubkey,                // MGC token mint
    sol_reserve: u64,            // Real SOL reserve
    token_supply: u64,           // Real supply
    k_constant: u128,            // K constant (variable)
    base_fee_in_bps: u16,        // Base entry fee (bps)
    base_fee_out_bps: u16,       // Base exit fee (bps)
    alpha_in: u64,               // Entry dynamic coefficient
    alpha_out: u64,              // Exit dynamic coefficient
    virtual_sol_reserve: u64,    // Virtual SOL reserve
    virtual_token_supply: u64,   // Virtual supply
    authorized_minters: Vec<Pubkey>,        // Max 10
    authorized_burners: Vec<Pubkey>,        // Max 10
    pending_authorizations: Vec<PendingAuthorization>, // Max 5
}

pub struct PendingAuthorization {
    address: Pubkey,
    proposed_at: i64,
    auth_type: AuthorizationType,  // Minter | Burner
}
```

### Instructions

| Instruction | Parameters | Description |
|-------------|------------|-------------|
| `initialize` | `initial_sol_reserve, virtual_sol_reserve, virtual_token_supply, base_fee_in_bps, base_fee_out_bps, alpha_in, alpha_out` | Initialize pool |
| `buy_tokens` | `sol_amount, min_tokens_out` | SOL → MGC swap with slippage protection |
| `sell_tokens` | `token_amount, min_sol_out` | MGC → SOL swap with slippage protection |
| `propose_authorized_minter` | `minter` | Propose minter (24h timelock) |
| `propose_authorized_burner` | `burner` | Propose burner (24h timelock) |
| `execute_pending_authorization` | `pending_address` | Execute after 24h |
| `cancel_pending_authorization` | `pending_address` | Cancel proposal |
| `authorized_mint` | `amount` | Mint reserved for authorized contracts |
| `authorized_burn` | `amount` | Burn reserved for authorized contracts |
| `get_pool_info` | - | Return complete info (view) |

### Implemented Security Features

- ✅ **Account validation:** `Account<Mint>`, `Account<TokenAccount>` with constraints
- ✅ **Slippage protection:** `min_tokens_out` / `min_sol_out` required
- ✅ **Secure transfers:** `system_program::transfer` + `invoke_signed`
- ✅ **24h timelock:** On authorization changes (86400s)
- ✅ **Checked math:** All calculations with `checked_add/sub/mul/div`
- ✅ **Transparency:** Events with real + virtual reserves

### Events

```rust
TokenPurchased {
    buyer, sol_amount, fee_amount, tokens_received, new_price,
    real_sol_reserve, real_token_supply,
    virtual_sol_reserve, virtual_token_supply
}

TokenSold {
    seller, tokens_sold, sol_received, fee_amount, new_price,
    real_sol_reserve, real_token_supply,
    virtual_sol_reserve, virtual_token_supply
}
```

### Constants

```rust
PRECISION: u128 = 1_000_000_000     // 10^9 for calculations
BPS_DENOMINATOR: u128 = 10_000      // Basis points
MAX_FEE_BPS: u128 = 5_000           // 50% max
TIMELOCK_DELAY: i64 = 86400         // 24 hours
```

### PDA

```
Pool: ["pool_v5"]
```

### Error Codes

| Code | Message |
|------|---------|
| `Unauthorized` | Unauthorized |
| `UnauthorizedMinter` | Unauthorized minter |
| `UnauthorizedBurner` | Unauthorized burner |
| `InsufficientReserve` | Insufficient SOL reserve |
| `MathOverflow` | Mathematical overflow |
| `MathUnderflow` | Mathematical underflow |
| `SlippageExceeded` | Slippage exceeded |
| `InvalidMint` | Invalid mint |
| `InvalidTokenAccount` | Invalid token account |
| `AlreadyAuthorized` | Already authorized |
| `AlreadyPending` | Already pending |
| `NoPendingAuthorization` | No pending authorization |
| `TimelockNotExpired` | Timelock not expired |

### Build & Deploy

```bash
# Build
anchor build

# Deploy
anchor deploy --provider.cluster devnet

# Test (requires update for new API)
anchor test
```

### Known Limitations

- Pool size increases with pending_authorizations (max 5)
- Variable K makes returning to initial state impossible
- Virtual reserves not modifiable after initialization
- Fees capped at 50% (no governance to modify)

### Implementation Notes

**Solved Issue - Borrow Checker:**
In `execute_pending_authorization`, values (`address`, `auth_type`, `proposed_at`) are copied before pool modification to avoid simultaneous immutable/mutable borrows.

**Breaking Changes vs Original API:**
- `add_authorized_minter` → `propose_authorized_minter`
- `add_authorized_burner` → `propose_authorized_burner`
- `buy_tokens(amount)` → `buy_tokens(amount, min_out)`
- `sell_tokens(amount)` → `sell_tokens(amount, min_out)`

---

## File Structure

```
programs/mgc_token/
├── src/
│   └── lib.rs          # Main code (938 lines)
├── Cargo.toml
└── target/deploy/
    └── mgc_token.so    # Compiled binary (309 KB)
```

## Status

**Compiled:** ✅
**Tested:** ⚠️ Existing tests require API update
**Deployed:** ❌
**Project:** Abandoned (legal concerns)
