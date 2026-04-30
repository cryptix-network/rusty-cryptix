use cryptix_consensus_core::constants::{MAX_SOMPI, SOMPI_PER_CRYPTIX};
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
pub const INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 250_000_000_000_000;
pub const INITIAL_VIRTUAL_TOKEN_RESERVES: u128 = LIQUIDITY_TOKEN_SUPPLY_RAW * 6 / 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiquidityMathError {
    Overflow,
    InvalidInput,
    InvalidState,
    ZeroOutput,
}

pub fn initial_virtual_token_reserves(max_supply: u128) -> Result<u128, LiquidityMathError> {
    if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
        return Err(LiquidityMathError::InvalidInput);
    }
    max_supply.checked_mul(6).ok_or(LiquidityMathError::Overflow)?.checked_div(5).ok_or(LiquidityMathError::Overflow)
}

pub fn calculate_trade_fee(amount: u64, fee_bps: u16) -> Result<u64, LiquidityMathError> {
    let fee = (u128::from(amount)).checked_mul(u128::from(fee_bps)).ok_or(LiquidityMathError::Overflow)? / 10_000u128;
    u64::try_from(fee).map_err(|_| LiquidityMathError::Overflow)
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
    if real_token_reserves <= MIN_REAL_TOKEN_RESERVE {
        return Ok(0);
    }
    let mut low = 0u64;
    let mut high = MAX_SOMPI;
    while low < high {
        let mid = low + (high - low + 1) / 2;
        let fee = calculate_trade_fee(mid, fee_bps)?;
        let Some(net) = mid.checked_sub(fee) else {
            return Err(LiquidityMathError::Overflow);
        };
        let accepted = cpmm_buy(real_token_reserves, virtual_cpay_reserves_sompi, virtual_token_reserves, net).is_ok();
        if accepted {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
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
                1_249_999_999_999_999,
            ),
            (
                LIQUIDITY_TOKEN_SUPPLY_RAW,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                INITIAL_VIRTUAL_TOKEN_RESERVES,
                100,
                1_262_626_262_626_261,
            ),
            (500_000, 1_234_567_890_123, 987_654, 250, 1_298_280_622_171),
        ];

        for (real_tokens, virtual_cpay, virtual_tokens, fee_bps, expected_max) in cases {
            let max = max_buy_in_sompi(real_tokens, virtual_cpay, virtual_tokens, fee_bps).expect("max buy should calculate");
            assert_eq!(max, expected_max);

            let fee = calculate_trade_fee(max, fee_bps).expect("max fee should calculate");
            let net = max - fee;
            let (token_out, new_real_tokens, _, _) =
                cpmm_buy(real_tokens, virtual_cpay, virtual_tokens, net).expect("max gross buy must be accepted");
            assert!(token_out > 0);
            assert!(new_real_tokens >= MIN_REAL_TOKEN_RESERVE);

            let over = max + 1;
            let over_fee = calculate_trade_fee(over, fee_bps).expect("over fee should calculate");
            let over_net = over - over_fee;
            assert_eq!(
                cpmm_buy(real_tokens, virtual_cpay, virtual_tokens, over_net),
                Err(LiquidityMathError::InvalidInput),
                "max+1 gross input must be rejected"
            );
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
