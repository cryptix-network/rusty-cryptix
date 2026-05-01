use cryptix_consensus_core::constants::SOMPI_PER_CRYPTIX;
use cryptix_math::Uint256;

// Allow dust-sized redemptions so the final outstanding liquidity tokens can always exit.
pub const LIQUIDITY_MIN_PAYOUT_SOMPI: u64 = 1;
pub const LIQUIDITY_TOKEN_DECIMALS: u8 = 0;
pub const MIN_LIQUIDITY_SUPPLY_RAW: u128 = 100_000;
pub const LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 1_000_000;
pub const DEFAULT_LIQUIDITY_SUPPLY_RAW: u128 = LIQUIDITY_TOKEN_SUPPLY_RAW;
pub const MAX_LIQUIDITY_SUPPLY_RAW: u128 = 10_000_000;
pub const MIN_LIQUIDITY_SEED_RESERVE_SOMPI: u64 = SOMPI_PER_CRYPTIX;
pub const INITIAL_REAL_CPAY_RESERVES_SOMPI: u64 = SOMPI_PER_CRYPTIX;
pub const MIN_CPAY_RESERVE_SOMPI: u64 = 1;
pub const MIN_REAL_TOKEN_RESERVE: u128 = 1;
pub const LIQUIDITY_CURVE_MODE_BASIC: u8 = 0;
pub const LIQUIDITY_CURVE_MODE_AGGRESSIVE: u8 = 1;
pub const LIQUIDITY_CURVE_MODE_INDIVIDUAL: u8 = 2;
pub const DEFAULT_LIQUIDITY_CURVE_MODE: u8 = LIQUIDITY_CURVE_MODE_BASIC;
pub const INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 250_000_000_000_000;
pub const INITIAL_VIRTUAL_TOKEN_RESERVES: u128 = LIQUIDITY_TOKEN_SUPPLY_RAW * 6 / 5;
pub const AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 200_000_000_000_000;
pub const AGGRESSIVE_INITIAL_VIRTUAL_TOKEN_RESERVES: u128 = LIQUIDITY_TOKEN_SUPPLY_RAW * 21 / 20;
pub const INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 100_000_000_000_000;
pub const INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 800_000_000_000_000;
pub const INDIVIDUAL_VIRTUAL_CPAY_STEP_SOMPI: u64 = 10_000_000_000_000;
pub const INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS: u16 = 10_100;
pub const INDIVIDUAL_MAX_VIRTUAL_TOKEN_MULTIPLIER_BPS: u16 = 20_000;
pub const INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS: u16 = 100;
pub const VIRTUAL_TOKEN_MULTIPLIER_BPS_DENOMINATOR: u16 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiquidityMathError {
    Overflow,
    InvalidInput,
    InvalidState,
    ZeroOutput,
}

pub fn validate_liquidity_curve_mode(mode: u8) -> Result<(), LiquidityMathError> {
    match mode {
        LIQUIDITY_CURVE_MODE_BASIC | LIQUIDITY_CURVE_MODE_AGGRESSIVE | LIQUIDITY_CURVE_MODE_INDIVIDUAL => Ok(()),
        _ => Err(LiquidityMathError::InvalidInput),
    }
}

pub fn liquidity_curve_mode_label(mode: u8) -> &'static str {
    match mode {
        LIQUIDITY_CURVE_MODE_AGGRESSIVE => "aggressive",
        LIQUIDITY_CURVE_MODE_INDIVIDUAL => "individual",
        _ => "basic",
    }
}

pub fn default_liquidity_curve_custom_params(mode: u8) -> (u64, u16) {
    match mode {
        LIQUIDITY_CURVE_MODE_INDIVIDUAL => (
            AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS + (4 * INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS),
        ),
        _ => (0, 0),
    }
}

pub fn validate_individual_liquidity_curve_params(
    virtual_cpay_reserves_sompi: u64,
    virtual_token_multiplier_bps: u16,
) -> Result<(), LiquidityMathError> {
    if !(INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI..=INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI)
        .contains(&virtual_cpay_reserves_sompi)
    {
        return Err(LiquidityMathError::InvalidInput);
    }
    if virtual_cpay_reserves_sompi % INDIVIDUAL_VIRTUAL_CPAY_STEP_SOMPI != 0 {
        return Err(LiquidityMathError::InvalidInput);
    }
    if !(INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS..=INDIVIDUAL_MAX_VIRTUAL_TOKEN_MULTIPLIER_BPS)
        .contains(&virtual_token_multiplier_bps)
    {
        return Err(LiquidityMathError::InvalidInput);
    }
    if virtual_token_multiplier_bps % INDIVIDUAL_VIRTUAL_TOKEN_MULTIPLIER_STEP_BPS != 0 {
        return Err(LiquidityMathError::InvalidInput);
    }
    Ok(())
}

pub fn validate_liquidity_curve_parameters(
    mode: u8,
    individual_virtual_cpay_reserves_sompi: u64,
    individual_virtual_token_multiplier_bps: u16,
) -> Result<(), LiquidityMathError> {
    match mode {
        LIQUIDITY_CURVE_MODE_BASIC | LIQUIDITY_CURVE_MODE_AGGRESSIVE => {
            if individual_virtual_cpay_reserves_sompi == 0 && individual_virtual_token_multiplier_bps == 0 {
                Ok(())
            } else {
                Err(LiquidityMathError::InvalidInput)
            }
        }
        LIQUIDITY_CURVE_MODE_INDIVIDUAL => {
            validate_individual_liquidity_curve_params(individual_virtual_cpay_reserves_sompi, individual_virtual_token_multiplier_bps)
        }
        _ => Err(LiquidityMathError::InvalidInput),
    }
}

pub fn initial_virtual_cpay_reserves_sompi_for_mode(mode: u8) -> Result<u64, LiquidityMathError> {
    match mode {
        LIQUIDITY_CURVE_MODE_BASIC => Ok(INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI),
        LIQUIDITY_CURVE_MODE_AGGRESSIVE => Ok(AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI),
        _ => Err(LiquidityMathError::InvalidInput),
    }
}

pub fn initial_virtual_cpay_reserves_sompi_for_curve(
    mode: u8,
    individual_virtual_cpay_reserves_sompi: u64,
) -> Result<u64, LiquidityMathError> {
    match mode {
        LIQUIDITY_CURVE_MODE_INDIVIDUAL => {
            validate_individual_liquidity_curve_params(
                individual_virtual_cpay_reserves_sompi,
                INDIVIDUAL_MIN_VIRTUAL_TOKEN_MULTIPLIER_BPS,
            )?;
            Ok(individual_virtual_cpay_reserves_sompi)
        }
        LIQUIDITY_CURVE_MODE_BASIC | LIQUIDITY_CURVE_MODE_AGGRESSIVE => initial_virtual_cpay_reserves_sompi_for_mode(mode),
        _ => Err(LiquidityMathError::InvalidInput),
    }
}

pub fn initial_virtual_token_reserves(max_supply: u128) -> Result<u128, LiquidityMathError> {
    initial_virtual_token_reserves_for_mode(max_supply, LIQUIDITY_CURVE_MODE_BASIC)
}

pub fn initial_virtual_token_reserves_for_mode(max_supply: u128, mode: u8) -> Result<u128, LiquidityMathError> {
    if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
        return Err(LiquidityMathError::InvalidInput);
    }
    let (numerator, denominator) = match mode {
        LIQUIDITY_CURVE_MODE_BASIC => (6u128, 5u128),
        LIQUIDITY_CURVE_MODE_AGGRESSIVE => (21u128, 20u128),
        _ => return Err(LiquidityMathError::InvalidInput),
    };
    max_supply.checked_mul(numerator).ok_or(LiquidityMathError::Overflow)?.checked_div(denominator).ok_or(LiquidityMathError::Overflow)
}

pub fn initial_virtual_token_reserves_for_curve(
    max_supply: u128,
    mode: u8,
    individual_virtual_token_multiplier_bps: u16,
) -> Result<u128, LiquidityMathError> {
    if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
        return Err(LiquidityMathError::InvalidInput);
    }
    match mode {
        LIQUIDITY_CURVE_MODE_INDIVIDUAL => {
            validate_individual_liquidity_curve_params(
                INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI,
                individual_virtual_token_multiplier_bps,
            )?;
            max_supply
                .checked_mul(u128::from(individual_virtual_token_multiplier_bps))
                .ok_or(LiquidityMathError::Overflow)?
                .checked_div(u128::from(VIRTUAL_TOKEN_MULTIPLIER_BPS_DENOMINATOR))
                .ok_or(LiquidityMathError::Overflow)
        }
        LIQUIDITY_CURVE_MODE_BASIC | LIQUIDITY_CURVE_MODE_AGGRESSIVE => initial_virtual_token_reserves_for_mode(max_supply, mode),
        _ => Err(LiquidityMathError::InvalidInput),
    }
}

pub fn calculate_trade_fee(amount: u64, fee_bps: u16) -> Result<u64, LiquidityMathError> {
    let fee = (u128::from(amount)).checked_mul(u128::from(fee_bps)).ok_or(LiquidityMathError::Overflow)? / 10_000u128;
    u64::try_from(fee).map_err(|_| LiquidityMathError::Overflow)
}

pub fn min_gross_input_for_net_input(net_in: u64, fee_bps: u16) -> Result<u64, LiquidityMathError> {
    if net_in == 0 || fee_bps >= 10_000 {
        return Err(LiquidityMathError::InvalidInput);
    }
    if fee_bps == 0 {
        return Ok(net_in);
    }

    let fee_denominator = 10_000u128.checked_sub(u128::from(fee_bps)).ok_or(LiquidityMathError::InvalidInput)?;
    let mut gross = (u128::from(net_in).checked_sub(1).ok_or(LiquidityMathError::InvalidInput)?)
        .checked_mul(10_000u128)
        .ok_or(LiquidityMathError::Overflow)?
        .checked_div(fee_denominator)
        .ok_or(LiquidityMathError::InvalidInput)?
        .checked_add(1)
        .ok_or(LiquidityMathError::Overflow)?;
    let mut gross_u64 = u64::try_from(gross).map_err(|_| LiquidityMathError::Overflow)?;

    while gross_u64 > 1 {
        let previous = gross_u64.checked_sub(1).ok_or(LiquidityMathError::Overflow)?;
        let previous_fee = calculate_trade_fee(previous, fee_bps)?;
        if previous.checked_sub(previous_fee).ok_or(LiquidityMathError::Overflow)? < net_in {
            break;
        }
        gross_u64 = previous;
    }
    while {
        let fee = calculate_trade_fee(gross_u64, fee_bps)?;
        gross_u64.checked_sub(fee).ok_or(LiquidityMathError::Overflow)? < net_in
    } {
        gross = u128::from(gross_u64).checked_add(1).ok_or(LiquidityMathError::Overflow)?;
        gross_u64 = u64::try_from(gross).map_err(|_| LiquidityMathError::Overflow)?;
    }
    Ok(gross_u64)
}

pub fn min_gross_input_for_token_out(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    token_out: u128,
    fee_bps: u16,
) -> Result<u64, LiquidityMathError> {
    if token_out == 0 || virtual_cpay_reserves_sompi == 0 || virtual_token_reserves == 0 {
        return Err(LiquidityMathError::InvalidInput);
    }
    let spendable_tokens = real_token_reserves.checked_sub(MIN_REAL_TOKEN_RESERVE).ok_or(LiquidityMathError::InvalidInput)?;
    if token_out > spendable_tokens {
        return Err(LiquidityMathError::InvalidInput);
    }
    let y_after = virtual_token_reserves.checked_sub(token_out).ok_or(LiquidityMathError::InvalidInput)?;
    if y_after == 0 {
        return Err(LiquidityMathError::InvalidInput);
    }

    let x_before = Uint256::from_u64(virtual_cpay_reserves_sompi);
    let k = x_before * Uint256::from_u128(virtual_token_reserves);
    let x_after = ceil_div_u256(k, Uint256::from_u128(y_after));
    if x_after <= x_before {
        return Err(LiquidityMathError::ZeroOutput);
    }
    let net_in_u256 = x_after - x_before;
    let net_in_u128 = u128::try_from(net_in_u256).map_err(|_| LiquidityMathError::Overflow)?;
    let net_in = u64::try_from(net_in_u128).map_err(|_| LiquidityMathError::Overflow)?;
    let gross_in = min_gross_input_for_net_input(net_in, fee_bps)?;

    let fee = calculate_trade_fee(gross_in, fee_bps)?;
    let net = gross_in.checked_sub(fee).ok_or(LiquidityMathError::Overflow)?;
    let (actual_token_out, _, _, _) = cpmm_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, net)?;
    if actual_token_out < token_out {
        return Err(LiquidityMathError::InvalidState);
    }
    Ok(gross_in)
}

pub fn cpmm_buy(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    cpay_net_in: u64,
) -> Result<(u128, u128, u64, u128), LiquidityMathError> {
    if cpay_net_in == 0 {
        return Err(LiquidityMathError::InvalidInput);
    }
    if real_token_reserves <= MIN_REAL_TOKEN_RESERVE {
        return Err(LiquidityMathError::InvalidInput);
    }
    let x_before = virtual_cpay_reserves_sompi;
    let y_before = virtual_token_reserves;
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
    let spendable_tokens = real_token_reserves.checked_sub(MIN_REAL_TOKEN_RESERVE).ok_or(LiquidityMathError::Overflow)?;
    if token_out > spendable_tokens {
        return Err(LiquidityMathError::InvalidInput);
    }
    let new_real_token_reserves = real_token_reserves.checked_sub(token_out).ok_or(LiquidityMathError::Overflow)?;
    Ok((token_out, new_real_token_reserves, x_after, y_after))
}

pub fn cpmm_sell(
    real_cpay_reserves_sompi: u64,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    token_in: u128,
) -> Result<(u64, u64, u64, u128), LiquidityMathError> {
    if token_in == 0 {
        return Err(LiquidityMathError::InvalidInput);
    }
    let y_before = virtual_token_reserves;
    let y_after = y_before.checked_add(token_in).ok_or(LiquidityMathError::Overflow)?;
    let x_before = virtual_cpay_reserves_sompi;
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
    let spendable_cpay = real_cpay_reserves_sompi.checked_sub(MIN_CPAY_RESERVE_SOMPI).ok_or(LiquidityMathError::Overflow)?;
    if gross_out > spendable_cpay {
        return Err(LiquidityMathError::InvalidInput);
    }
    let new_real_cpay_reserves = real_cpay_reserves_sompi.checked_sub(gross_out).ok_or(LiquidityMathError::Overflow)?;
    Ok((gross_out, new_real_cpay_reserves, x_after, y_after))
}

pub fn max_buy_in_sompi(
    real_token_reserves: u128,
    virtual_cpay_reserves_sompi: u64,
    virtual_token_reserves: u128,
    fee_bps: u16,
) -> Result<u64, LiquidityMathError> {
    let token_out = max_tokens_out(real_token_reserves);
    if token_out == 0 {
        return Ok(0);
    }
    min_gross_input_for_token_out(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, token_out, fee_bps)
}

pub fn max_tokens_out(real_token_reserves: u128) -> u128 {
    real_token_reserves.saturating_sub(MIN_REAL_TOKEN_RESERVE)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn buy_with_gross(
        real_token_reserves: u128,
        virtual_cpay_reserves_sompi: u64,
        virtual_token_reserves: u128,
        gross_in: u64,
        fee_bps: u16,
    ) -> Result<(u64, u64, u128, u128, u64, u128), LiquidityMathError> {
        let fee = calculate_trade_fee(gross_in, fee_bps)?;
        let net = gross_in.checked_sub(fee).ok_or(LiquidityMathError::Overflow)?;
        let (token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
            cpmm_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, net)?;
        Ok((fee, net, token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves))
    }

    #[test]
    fn cpmm_buy_stops_before_final_real_token() {
        let (token_out, remaining, _, _) = cpmm_buy(2, 1_000, 2, 1_000).expect("one token can be bought");
        assert_eq!(token_out, 1);
        assert_eq!(remaining, MIN_REAL_TOKEN_RESERVE);
    }

    #[test]
    fn cpmm_buy_rejects_final_real_token_drain() {
        let err = cpmm_buy(2, 1_000, 3, 2_000).expect_err("final token drain must be rejected");
        assert_eq!(err, LiquidityMathError::InvalidInput);
    }

    #[test]
    fn cpmm_sell_floor_uses_gross_out() {
        let err = cpmm_sell(100, 1_000, 1, 1_000).expect_err("gross-out floor breach must be rejected");
        assert_eq!(err, LiquidityMathError::InvalidInput);
    }

    #[test]
    fn cpmm_sell_rejects_gross_floor_breach_even_when_net_payout_would_fit() {
        let hypothetical_gross_out = 1_000u64;
        let fee = calculate_trade_fee(hypothetical_gross_out, 1_000).expect("fee should calculate");
        let cpay_out = hypothetical_gross_out - fee;
        assert!(hypothetical_gross_out > 1_000 - MIN_CPAY_RESERVE_SOMPI);
        assert!(cpay_out <= 1_000 - MIN_CPAY_RESERVE_SOMPI);

        let err = cpmm_sell(1_000, 2_000, 1, 1).expect_err("gross-out floor breach must be rejected");
        assert_eq!(err, LiquidityMathError::InvalidInput);
    }

    #[test]
    fn initial_no_fee_buy_shape() {
        assert_eq!(
            cpmm_buy(
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                SOMPI_PER_CRYPTIX,
            ),
            Err(LiquidityMathError::ZeroOutput)
        );
        assert_eq!(
            cpmm_buy(
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                2 * SOMPI_PER_CRYPTIX,
            ),
            Err(LiquidityMathError::ZeroOutput)
        );

        let cases = [
            (5, 2u128),
            (10, 4),
            (50, 23),
            (100, 47),
            (500, 239),
            (1_000, 479),
            (5_000, 2_395),
            (10_000, 4_780),
            (100_000, 46_153),
            (500_000, 200_000),
            (1_000_000, 342_857),
            (2_500_000, 600_000),
        ];
        for (cpay, expected) in cases {
            let net = cpay * SOMPI_PER_CRYPTIX;
            let (token_out, _, _, _) =
                cpmm_buy(LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, INITIAL_VIRTUAL_TOKEN_RESERVES, net)
                    .expect("initial buy quote should work");
            assert_eq!(token_out, expected, "{cpay} CPAY");
        }
    }

    #[test]
    fn initial_virtual_token_reserves_scale_with_supply() {
        let cases =
            [(MIN_LIQUIDITY_SUPPLY_RAW, 120_000), (LIQUIDITY_TOKEN_SUPPLY_RAW, 1_200_000), (MAX_LIQUIDITY_SUPPLY_RAW, 12_000_000)];
        for (max_supply, expected) in cases {
            assert_eq!(initial_virtual_token_reserves(max_supply), Ok(expected));
        }
        assert_eq!(initial_virtual_token_reserves(MIN_LIQUIDITY_SUPPLY_RAW - 1), Err(LiquidityMathError::InvalidInput));
        assert_eq!(initial_virtual_token_reserves(MAX_LIQUIDITY_SUPPLY_RAW + 1), Err(LiquidityMathError::InvalidInput));
    }

    #[test]
    fn aggressive_mode_uses_smaller_virtual_reserves() {
        assert_eq!(
            initial_virtual_cpay_reserves_sompi_for_mode(LIQUIDITY_CURVE_MODE_AGGRESSIVE),
            Ok(AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI)
        );
        let cases =
            [(MIN_LIQUIDITY_SUPPLY_RAW, 105_000), (LIQUIDITY_TOKEN_SUPPLY_RAW, 1_050_000), (MAX_LIQUIDITY_SUPPLY_RAW, 10_500_000)];
        for (max_supply, expected) in cases {
            assert_eq!(initial_virtual_token_reserves_for_mode(max_supply, LIQUIDITY_CURVE_MODE_AGGRESSIVE), Ok(expected));
        }
        assert_eq!(validate_liquidity_curve_mode(99), Err(LiquidityMathError::InvalidInput));
    }

    #[test]
    fn individual_mode_uses_strict_integer_curve_params() {
        assert_eq!(
            validate_liquidity_curve_parameters(
                LIQUIDITY_CURVE_MODE_INDIVIDUAL,
                AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                10_500
            ),
            Ok(())
        );
        assert_eq!(
            validate_liquidity_curve_parameters(LIQUIDITY_CURVE_MODE_INDIVIDUAL, INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI, 20_000),
            Ok(())
        );
        assert_eq!(
            initial_virtual_cpay_reserves_sompi_for_curve(
                LIQUIDITY_CURVE_MODE_INDIVIDUAL,
                AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI
            ),
            Ok(AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI)
        );
        assert_eq!(
            initial_virtual_token_reserves_for_curve(LIQUIDITY_TOKEN_SUPPLY_RAW, LIQUIDITY_CURVE_MODE_INDIVIDUAL, 10_500),
            Ok(1_050_000)
        );
        assert_eq!(
            validate_liquidity_curve_parameters(LIQUIDITY_CURVE_MODE_BASIC, AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, 10_500),
            Err(LiquidityMathError::InvalidInput)
        );
        assert_eq!(
            validate_liquidity_curve_parameters(
                LIQUIDITY_CURVE_MODE_INDIVIDUAL,
                INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI + 1,
                10_500
            ),
            Err(LiquidityMathError::InvalidInput)
        );
        assert_eq!(
            validate_liquidity_curve_parameters(
                LIQUIDITY_CURVE_MODE_INDIVIDUAL,
                AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                10_550
            ),
            Err(LiquidityMathError::InvalidInput)
        );
    }

    #[test]
    fn individual_mode_trade_vectors_are_exact_across_range() {
        let buy_cases = [
            (
                "individual_min_buy_1000_cpay_100bps",
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INDIVIDUAL_MIN_VIRTUAL_CPAY_RESERVES_SOMPI,
                10_100,
                1_000 * SOMPI_PER_CRYPTIX,
                100,
                1_000_000_000,
                99_000_000_000,
                998,
                999_002,
                100_099_000_000_000,
                1_009_002,
            ),
            (
                "individual_default_buy_1000_cpay_100bps",
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                10_500,
                1_000 * SOMPI_PER_CRYPTIX,
                100,
                1_000_000_000,
                99_000_000_000,
                519,
                999_481,
                200_099_000_000_000,
                1_049_481,
            ),
            (
                "individual_max_buy_1000_cpay_100bps",
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INDIVIDUAL_MAX_VIRTUAL_CPAY_RESERVES_SOMPI,
                20_000,
                1_000 * SOMPI_PER_CRYPTIX,
                100,
                1_000_000_000,
                99_000_000_000,
                247,
                999_753,
                800_099_000_000_000,
                1_999_753,
            ),
            (
                "individual_custom_buy_12345_cpay_40bps",
                5_000_000,
                330_000_000_000_000,
                14_600,
                12_345 * SOMPI_PER_CRYPTIX,
                40,
                4_938_000_000,
                1_229_562_000_000,
                27_098,
                4_972_902,
                331_229_562_000_000,
                7_272_902,
            ),
        ];

        for (
            name,
            max_supply,
            fixed_cpay,
            multiplier_bps,
            gross_in,
            fee_bps,
            expected_fee,
            expected_net,
            expected_token_out,
            expected_real_token_reserves,
            expected_virtual_cpay,
            expected_virtual_tokens,
        ) in buy_cases
        {
            let virtual_cpay = initial_virtual_cpay_reserves_sompi_for_curve(LIQUIDITY_CURVE_MODE_INDIVIDUAL, fixed_cpay).expect(name);
            let virtual_tokens =
                initial_virtual_token_reserves_for_curve(max_supply, LIQUIDITY_CURVE_MODE_INDIVIDUAL, multiplier_bps).expect(name);
            let (fee, net, token_out, real_token_reserves, new_virtual_cpay, new_virtual_tokens) =
                buy_with_gross(max_supply, virtual_cpay, virtual_tokens, gross_in, fee_bps).expect(name);
            assert_eq!(fee, expected_fee, "{name} fee");
            assert_eq!(net, expected_net, "{name} net");
            assert_eq!(token_out, expected_token_out, "{name} token_out");
            assert_eq!(real_token_reserves, expected_real_token_reserves, "{name} real tokens");
            assert_eq!(new_virtual_cpay, expected_virtual_cpay, "{name} virtual cpay");
            assert_eq!(new_virtual_tokens, expected_virtual_tokens, "{name} virtual tokens");
        }

        let sell_cases = [
            (
                "individual_min_sell_250_tokens_100bps",
                99_100_000_000,
                100_099_000_000_000,
                1_009_002,
                250,
                100,
                24_795_343_483,
                247_953_434,
                24_547_390_049,
                74_304_656_517,
                100_074_204_656_517,
                1_009_252,
            ),
            (
                "individual_max_sell_247_tokens_100bps",
                99_100_000_000,
                800_099_000_000_000,
                1_999_753,
                247,
                100,
                98_812_226_500,
                988_122_265,
                97_824_104_235,
                287_773_500,
                800_000_187_773_500,
                2_000_000,
            ),
            (
                "individual_custom_sell_7777_tokens_40bps",
                1_229_662_000_000,
                331_229_562_000_000,
                7_272_902,
                7_777,
                40,
                353_809_349_880,
                1_415_237_399,
                352_394_112_481,
                875_852_650_120,
                330_875_752_650_120,
                7_280_679,
            ),
        ];

        for (
            name,
            real_cpay,
            virtual_cpay,
            virtual_tokens,
            token_in,
            fee_bps,
            expected_gross_out,
            expected_fee,
            expected_cpay_out,
            expected_real_cpay,
            expected_virtual_cpay,
            expected_virtual_tokens,
        ) in sell_cases
        {
            let (gross_out, new_real_cpay, new_virtual_cpay, new_virtual_tokens) =
                cpmm_sell(real_cpay, virtual_cpay, virtual_tokens, token_in).expect(name);
            let fee = calculate_trade_fee(gross_out, fee_bps).expect(name);
            assert_eq!(gross_out, expected_gross_out, "{name} gross_out");
            assert_eq!(fee, expected_fee, "{name} fee");
            assert_eq!(gross_out - fee, expected_cpay_out, "{name} cpay_out");
            assert_eq!(new_real_cpay, expected_real_cpay, "{name} real cpay");
            assert_eq!(new_virtual_cpay, expected_virtual_cpay, "{name} virtual cpay");
            assert_eq!(new_virtual_tokens, expected_virtual_tokens, "{name} virtual tokens");
        }
    }

    #[test]
    fn min_gross_input_for_token_out_removes_integer_overpay() {
        let budget = 10 * SOMPI_PER_CRYPTIX;
        let (budget_token_out, _, _, _) =
            cpmm_buy(LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, INITIAL_VIRTUAL_TOKEN_RESERVES, budget)
                .expect("budget buy should quote");
        assert_eq!(budget_token_out, 4);

        let canonical = min_gross_input_for_token_out(
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            INITIAL_VIRTUAL_TOKEN_RESERVES,
            budget_token_out,
            0,
        )
        .expect("canonical input should calculate");
        assert_eq!(canonical, 833_336_112);
        assert!(canonical < budget);

        let (previous_token_out, _, _, _) =
            cpmm_buy(LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, INITIAL_VIRTUAL_TOKEN_RESERVES, canonical - 1)
                .expect("previous input should still buy a smaller whole-token amount");
        assert_eq!(previous_token_out, 3);
    }

    #[test]
    fn min_gross_input_for_token_out_accounts_for_trade_fee_flooring() {
        let budget = 1_000 * SOMPI_PER_CRYPTIX;
        let fee_bps = 100;
        let fee = calculate_trade_fee(budget, fee_bps).expect("fee should calculate");
        let net = budget - fee;
        let (budget_token_out, _, _, _) =
            cpmm_buy(LIQUIDITY_TOKEN_SUPPLY_RAW, INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, INITIAL_VIRTUAL_TOKEN_RESERVES, net)
                .expect("budget buy should quote");
        let canonical = min_gross_input_for_token_out(
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            INITIAL_VIRTUAL_TOKEN_RESERVES,
            budget_token_out,
            fee_bps,
        )
        .expect("canonical input should calculate");
        assert!(canonical < budget);

        let canonical_fee = calculate_trade_fee(canonical, fee_bps).expect("fee should calculate");
        let (canonical_token_out, _, _, _) = cpmm_buy(
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            INITIAL_VIRTUAL_TOKEN_RESERVES,
            canonical - canonical_fee,
        )
        .expect("canonical buy should quote");
        assert_eq!(canonical_token_out, budget_token_out);

        let previous = canonical - 1;
        let previous_fee = calculate_trade_fee(previous, fee_bps).expect("fee should calculate");
        let previous_token_out = cpmm_buy(
            LIQUIDITY_TOKEN_SUPPLY_RAW,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            INITIAL_VIRTUAL_TOKEN_RESERVES,
            previous - previous_fee,
        )
        .map(|(token_out, _, _, _)| token_out)
        .unwrap_or(0);
        assert!(previous_token_out < budget_token_out);
    }

    #[test]
    fn no_fee_curve_shape_matches_target_percentages() {
        let cases = [
            (10, 100_000u128, 22_727_272_727_273u128),
            (25, 250_000, 65_789_473_684_211),
            (50, 500_000, 178_571_428_571_429),
            (75, 750_000, 416_666_666_666_667),
            (90, 900_000, 750_000_000_000_000),
            (99, 990_000, 1_178_571_428_571_429),
            (100, 1_000_000, 1_250_000_000_000_000),
        ];
        for (percent, token_out, expected_net_in_sompi) in cases {
            let y_after = INITIAL_VIRTUAL_TOKEN_RESERVES - token_out;
            let x_after = u128::try_from(ceil_div_u256(
                Uint256::from_u64(INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI) * Uint256::from_u128(INITIAL_VIRTUAL_TOKEN_RESERVES),
                Uint256::from_u128(y_after),
            ))
            .expect("x_after should fit u128");
            let net_in = x_after - u128::from(INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI);
            assert_eq!(net_in, expected_net_in_sompi, "{percent}% supply");
        }
    }

    #[test]
    fn same_cpay_buy_is_supply_percentage_stable() {
        let gross_in = 1_000 * SOMPI_PER_CRYPTIX;
        let mut parts_per_million = Vec::new();
        for max_supply in [MIN_LIQUIDITY_SUPPLY_RAW, LIQUIDITY_TOKEN_SUPPLY_RAW, MAX_LIQUIDITY_SUPPLY_RAW] {
            let virtual_tokens = initial_virtual_token_reserves(max_supply).expect("supply should be valid");
            let (token_out, _, _, _) =
                cpmm_buy(max_supply, INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI, virtual_tokens, gross_in).expect("buy should quote");
            parts_per_million.push((token_out * 1_000_000) / max_supply);
        }
        let min_ppm = parts_per_million.iter().copied().min().expect("non-empty");
        let max_ppm = parts_per_million.iter().copied().max().expect("non-empty");
        assert!(max_ppm - min_ppm <= 10, "scaled curve drift too high: {:?}", parts_per_million);
    }

    #[test]
    fn rust_go_determinism_buy_vectors_are_exact() {
        let cases = [
            (
                "initial_buy_10_cpay_no_fee",
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                10 * SOMPI_PER_CRYPTIX,
                0,
                0,
                10 * SOMPI_PER_CRYPTIX,
                4,
                999_996,
                250_001_000_000_000,
                1_199_996,
            ),
            (
                "initial_buy_1000_cpay_100bps",
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                1_000 * SOMPI_PER_CRYPTIX,
                100,
                1_000_000_000,
                99_000_000_000,
                475,
                999_525,
                250_099_000_000_000,
                1_199_525,
            ),
            (
                "aggressive_initial_buy_1000_cpay_100bps",
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                AGGRESSIVE_INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                AGGRESSIVE_INITIAL_VIRTUAL_TOKEN_RESERVES,
                1_000 * SOMPI_PER_CRYPTIX,
                100,
                1_000_000_000,
                99_000_000_000,
                519,
                999_481,
                200_099_000_000_000,
                1_049_481,
            ),
            (
                "custom_buy_fee_250bps",
                777_777,
                1_234_567_890_123,
                987_654,
                987_654_321,
                250,
                24_691_358,
                962_962_963,
                769,
                777_008,
                1_235_530_853_086,
                986_885,
            ),
            ("near_inventory_buy_exact_one", 2, 1_000, 2, 1_000, 0, 0, 1_000, 1, 1, 2_000, 1),
        ];

        for (
            name,
            real_token_reserves,
            virtual_cpay_reserves_sompi,
            virtual_token_reserves,
            gross_in,
            fee_bps,
            expected_fee,
            expected_net,
            expected_token_out,
            expected_real_token_reserves,
            expected_virtual_cpay_reserves_sompi,
            expected_virtual_token_reserves,
        ) in cases
        {
            let (fee, net, token_out, new_real_token_reserves, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                buy_with_gross(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, gross_in, fee_bps)
                    .unwrap_or_else(|err| panic!("{name} failed: {err:?}"));
            assert_eq!(fee, expected_fee, "{name} fee");
            assert_eq!(net, expected_net, "{name} net");
            assert_eq!(token_out, expected_token_out, "{name} token_out");
            assert_eq!(new_real_token_reserves, expected_real_token_reserves, "{name} real tokens");
            assert_eq!(new_virtual_cpay_reserves_sompi, expected_virtual_cpay_reserves_sompi, "{name} virtual cpay");
            assert_eq!(new_virtual_token_reserves, expected_virtual_token_reserves, "{name} virtual tokens");
        }
    }

    #[test]
    fn rust_go_determinism_sell_vectors_are_exact() {
        let cases = [
            (
                "sell_initialish_100_100bps",
                99_100_000_000,
                250_099_000_000_000,
                1_199_525,
                100,
                100,
                20_848_098_365,
                208_480_983,
                20_639_617_382,
                78_251_901_635,
                250_078_151_901_635,
                1_199_625,
            ),
            (
                "sell_custom_250bps",
                20_000_000_000,
                987_654_321_000,
                876_543,
                12_345,
                250,
                13_716_680_384,
                342_917_009,
                13_373_763_375,
                6_283_319_616,
                973_937_640_616,
                888_888,
            ),
            (
                "sell_big_1000bps",
                50_000_000_000_000,
                1_234_567_890_123,
                987_654,
                500_000,
                1_000,
                414_937_845_132,
                41_493_784_513,
                373_444_060_619,
                49_585_062_154_868,
                819_630_044_991,
                1_487_654,
            ),
        ];

        for (
            name,
            real_cpay_reserves_sompi,
            virtual_cpay_reserves_sompi,
            virtual_token_reserves,
            token_in,
            fee_bps,
            expected_gross_out,
            expected_fee,
            expected_cpay_out,
            expected_real_cpay_reserves_sompi,
            expected_virtual_cpay_reserves_sompi,
            expected_virtual_token_reserves,
        ) in cases
        {
            let (gross_out, new_real_cpay_reserves_sompi, new_virtual_cpay_reserves_sompi, new_virtual_token_reserves) =
                cpmm_sell(real_cpay_reserves_sompi, virtual_cpay_reserves_sompi, virtual_token_reserves, token_in)
                    .unwrap_or_else(|err| panic!("{name} failed: {err:?}"));
            let fee = calculate_trade_fee(gross_out, fee_bps).expect("fee should calculate");
            let cpay_out = gross_out - fee;
            assert_eq!(gross_out, expected_gross_out, "{name} gross_out");
            assert_eq!(fee, expected_fee, "{name} fee");
            assert_eq!(cpay_out, expected_cpay_out, "{name} cpay_out");
            assert_eq!(new_real_cpay_reserves_sompi, expected_real_cpay_reserves_sompi, "{name} real cpay");
            assert_eq!(new_virtual_cpay_reserves_sompi, expected_virtual_cpay_reserves_sompi, "{name} virtual cpay");
            assert_eq!(new_virtual_token_reserves, expected_virtual_token_reserves, "{name} virtual tokens");
        }
    }

    #[test]
    fn max_buy_in_sompi_is_gross_and_enforces_exact_boundary() {
        let cases = [
            (
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                0,
                1_249_992_500_037_500,
            ),
            (
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                100,
                1_262_618_686_906_565,
            ),
            (500_000, 1_234_567_890_123, 987_654, 250, 1_298_275_363_323),
        ];

        for (real_tokens, virtual_cpay, virtual_tokens, fee_bps, expected_max) in cases {
            let max = max_buy_in_sompi(real_tokens, virtual_cpay, virtual_tokens, fee_bps).expect("max buy should calculate");
            assert_eq!(max, expected_max);

            let fee = calculate_trade_fee(max, fee_bps).expect("max fee should calculate");
            let net = max - fee;
            let (token_out, new_real_tokens, _, _) =
                cpmm_buy(real_tokens, virtual_cpay, virtual_tokens, net).expect("max gross buy must be accepted");
            assert_eq!(token_out, max_tokens_out(real_tokens));
            assert_eq!(new_real_tokens, MIN_REAL_TOKEN_RESERVE);

            let over = max + 1;
            let over_fee = calculate_trade_fee(over, fee_bps).expect("over fee should calculate");
            let over_net = over - over_fee;
            if let Ok((over_token_out, _, _, _)) = cpmm_buy(real_tokens, virtual_cpay, virtual_tokens, over_net) {
                assert_eq!(over_token_out, token_out);
                assert_ne!(
                    over,
                    min_gross_input_for_token_out(real_tokens, virtual_cpay, virtual_tokens, over_token_out, fee_bps)
                        .expect("canonical over input should calculate")
                );
            }
        }
    }

    #[test]
    fn deterministic_stress_preserves_reserve_floors_and_vault_accounting() {
        let mut real_cpay = INITIAL_REAL_CPAY_RESERVES_SOMPI;
        let mut real_tokens = LIQUIDITY_TOKEN_SUPPLY_RAW;
        let mut virtual_cpay = INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI;
        let mut virtual_tokens = INITIAL_VIRTUAL_TOKEN_RESERVES;
        let mut circulating = 0u128;
        let mut unclaimed_fees = 0u64;
        let mut vault_value = real_cpay;
        let fee_schedule = [0u16, 10, 100, 250, 1_000];
        let mut seed = 0xC0FFEE1234567890u64;

        for step in 0..2_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let fee_bps = fee_schedule[step % fee_schedule.len()];
            let prefer_buy = step % 4 != 3 || circulating == 0;
            if prefer_buy {
                let max_buy = max_buy_in_sompi(real_tokens, virtual_cpay, virtual_tokens, fee_bps).expect("max buy should calculate");
                if max_buy == 0 {
                    continue;
                }
                let cap = max_buy.min(10 * SOMPI_PER_CRYPTIX);
                let gross_in = 1 + (seed % cap);
                let fee = calculate_trade_fee(gross_in, fee_bps).expect("fee should calculate");
                let net = gross_in - fee;
                let Ok((token_out, next_real_tokens, next_virtual_cpay, next_virtual_tokens)) =
                    cpmm_buy(real_tokens, virtual_cpay, virtual_tokens, net)
                else {
                    continue;
                };
                real_cpay = real_cpay.checked_add(net).expect("real CPAY overflow");
                real_tokens = next_real_tokens;
                virtual_cpay = next_virtual_cpay;
                virtual_tokens = next_virtual_tokens;
                circulating = circulating.checked_add(token_out).expect("circulating overflow");
                unclaimed_fees = unclaimed_fees.checked_add(fee).expect("fee overflow");
                vault_value = vault_value.checked_add(gross_in).expect("vault overflow");
            } else {
                let max_sell = circulating.min(10_000);
                if max_sell == 0 {
                    continue;
                }
                let token_in = 1 + u128::from(seed) % max_sell;
                let Ok((gross_out, next_real_cpay, next_virtual_cpay, next_virtual_tokens)) =
                    cpmm_sell(real_cpay, virtual_cpay, virtual_tokens, token_in)
                else {
                    continue;
                };
                let fee = calculate_trade_fee(gross_out, fee_bps).expect("fee should calculate");
                let cpay_out = gross_out.checked_sub(fee).expect("fee underflow");
                if cpay_out == 0 {
                    continue;
                }
                real_cpay = next_real_cpay;
                real_tokens = real_tokens.checked_add(token_in).expect("real token overflow");
                virtual_cpay = next_virtual_cpay;
                virtual_tokens = next_virtual_tokens;
                circulating = circulating.checked_sub(token_in).expect("circulating underflow");
                unclaimed_fees = unclaimed_fees.checked_add(fee).expect("fee overflow");
                vault_value = vault_value.checked_sub(cpay_out).expect("vault underflow");
            }

            assert_eq!(circulating + real_tokens, LIQUIDITY_TOKEN_SUPPLY_RAW);
            assert!(real_tokens >= MIN_REAL_TOKEN_RESERVE);
            assert!(real_cpay >= MIN_CPAY_RESERVE_SOMPI);
            assert!(virtual_cpay > 0);
            assert!(virtual_tokens > 0);
            assert_eq!(vault_value, real_cpay + unclaimed_fees);
        }
    }
}
