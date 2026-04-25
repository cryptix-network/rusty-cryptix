use cryptix_math::Uint256;

// Allow dust-sized redemptions so the final outstanding liquidity tokens can always exit.
pub const LIQUIDITY_MIN_PAYOUT_SOMPI: u64 = 1;
pub const CURVE_FLOOR_TOKEN: u128 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiquidityMathError {
    Overflow,
    InvalidInput,
    InvalidState,
    ZeroOutput,
}

pub fn calculate_trade_fee(amount: u64, fee_bps: u16) -> Result<u64, LiquidityMathError> {
    let fee = (u128::from(amount)).checked_mul(u128::from(fee_bps)).ok_or(LiquidityMathError::Overflow)? / 10_000u128;
    u64::try_from(fee).map_err(|_| LiquidityMathError::Overflow)
}

pub fn cpmm_buy(
    remaining_pool_supply: u128,
    curve_reserve_sompi: u64,
    cpay_net_in: u64,
) -> Result<(u128, u128, u64), LiquidityMathError> {
    let y_before = remaining_pool_supply.checked_add(CURVE_FLOOR_TOKEN).ok_or(LiquidityMathError::Overflow)?;
    let x_before = curve_reserve_sompi;
    let x_after = x_before.checked_add(cpay_net_in).ok_or(LiquidityMathError::Overflow)?;
    if x_after == 0 {
        return Err(LiquidityMathError::InvalidInput);
    }

    let k = Uint256::from_u64(x_before) * Uint256::from_u128(y_before);
    let y_after_u256 = ceil_div_u256(k, Uint256::from_u64(x_after));
    let y_after = u128::try_from(y_after_u256).map_err(|_| LiquidityMathError::Overflow)?;
    if y_after == 0 || y_after > y_before {
        return Err(LiquidityMathError::InvalidState);
    }

    let token_out = y_before.checked_sub(y_after).ok_or(LiquidityMathError::Overflow)?;
    if token_out == 0 {
        return Err(LiquidityMathError::ZeroOutput);
    }
    let new_remaining_pool_supply = y_after.checked_sub(CURVE_FLOOR_TOKEN).ok_or(LiquidityMathError::Overflow)?;
    Ok((token_out, new_remaining_pool_supply, x_after))
}

pub fn cpmm_sell(
    remaining_pool_supply: u128,
    curve_reserve_sompi: u64,
    token_in: u128,
) -> Result<(u64, u128, u64), LiquidityMathError> {
    let y_before = remaining_pool_supply.checked_add(CURVE_FLOOR_TOKEN).ok_or(LiquidityMathError::Overflow)?;
    let y_after = y_before.checked_add(token_in).ok_or(LiquidityMathError::Overflow)?;
    let x_before = curve_reserve_sompi;
    let k = Uint256::from_u64(x_before) * Uint256::from_u128(y_before);
    let x_after_u256 = k / Uint256::from_u128(y_after);
    let x_after_u128 = u128::try_from(x_after_u256).map_err(|_| LiquidityMathError::Overflow)?;
    let x_after = u64::try_from(x_after_u128).map_err(|_| LiquidityMathError::Overflow)?;
    if x_after > x_before {
        return Err(LiquidityMathError::InvalidState);
    }

    let gross_out = x_before.checked_sub(x_after).ok_or(LiquidityMathError::Overflow)?;
    if gross_out == 0 {
        return Err(LiquidityMathError::ZeroOutput);
    }
    let new_remaining_pool_supply = remaining_pool_supply.checked_add(token_in).ok_or(LiquidityMathError::Overflow)?;
    Ok((gross_out, new_remaining_pool_supply, x_after))
}

pub fn ceil_div_u256(numerator: Uint256, denominator: Uint256) -> Uint256 {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder.is_zero() {
        quotient
    } else {
        quotient + Uint256::from_u64(1)
    }
}
