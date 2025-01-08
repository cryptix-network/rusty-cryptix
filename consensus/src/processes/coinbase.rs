use cryptix_consensus_core::{
    coinbase::*,
    errors::coinbase::{CoinbaseError, CoinbaseResult},
    subnets,
    tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput},
    BlockHashMap, BlockHashSet,
};
use std::convert::TryInto;

use crate::{constants, model::stores::ghostdag::GhostdagData};

const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();

const MIN_PAYLOAD_LENGTH: usize =
    LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_SCRIPT_PUB_KEY_VERSION + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60
const SECONDS_PER_MONTH: u64 = 2629800;

pub const SUBSIDY_BY_MONTH_TABLE_SIZE: usize = 426;
pub type SubsidyByMonthTable = [u64; SUBSIDY_BY_MONTH_TABLE_SIZE];

#[derive(Clone)]
pub struct CoinbaseManager {
    coinbase_payload_script_public_key_max_len: u8,
    max_coinbase_payload_len: usize,
    deflationary_phase_daa_score: u64,
    pre_deflationary_phase_base_subsidy: u64,
    target_time_per_block: u64,

    /// Precomputed number of blocks per month
    blocks_per_month: u64,

    /// Precomputed subsidy by month table
    subsidy_by_month_table: SubsidyByMonthTable,
}

/// Struct used to streamline payload parsing
struct PayloadParser<'a> {
    remaining: &'a [u8], // The unparsed remainder
}

impl<'a> PayloadParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    fn take(&mut self, n: usize) -> &[u8] {
        let (segment, remaining) = self.remaining.split_at(n);
        self.remaining = remaining;
        segment
    }
}

impl CoinbaseManager {
    pub fn new(
        coinbase_payload_script_public_key_max_len: u8,
        max_coinbase_payload_len: usize,
        deflationary_phase_daa_score: u64,
        pre_deflationary_phase_base_subsidy: u64,
        target_time_per_block: u64,
    ) -> Self {
        assert!(1000 % target_time_per_block == 0);
        let bps = 1000 / target_time_per_block;
        let blocks_per_month = SECONDS_PER_MONTH * bps;

        // Precomputed subsidy by month table for the actual block per second rate
        // Here values are rounded up so that we keep the same number of rewarding months as in the original 1 BPS table.
        // In a 10 BPS network, the induced increase in total rewards is 51 CYTX (see tests::calc_high_bps_total_rewards_delta())
        let subsidy_by_month_table: SubsidyByMonthTable = core::array::from_fn(|i| (SUBSIDY_BY_MONTH_TABLE[i] + bps - 1) / bps);
        Self {
            coinbase_payload_script_public_key_max_len,
            max_coinbase_payload_len,
            deflationary_phase_daa_score,
            pre_deflationary_phase_base_subsidy,
            target_time_per_block,
            blocks_per_month,
            subsidy_by_month_table,
        }
    }

    #[cfg(test)]
    #[inline]
    pub fn bps(&self) -> u64 {
        1000 / self.target_time_per_block
    }

    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
        &self,
        daa_score: u64,
        miner_data: MinerData<T>,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
    ) -> CoinbaseResult<CoinbaseTransactionTemplate> {
        let mut outputs = Vec::with_capacity(ghostdag_data.mergeset_blues.len() + 1); // + 1 for possible red reward

        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(blue).unwrap();
            if reward_data.subsidy + reward_data.total_fees > 0 {
                outputs
                    .push(TransactionOutput::new(reward_data.subsidy + reward_data.total_fees, reward_data.script_public_key.clone()));
            }
        }

        // Collect all rewards from mergeset reds ∩ DAA window and create a
        // single output rewarding all to the current block (the "merging" block)
        let mut red_reward = 0u64;
        for red in ghostdag_data.mergeset_reds.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(red).unwrap();
            red_reward += reward_data.subsidy + reward_data.total_fees;
        }
        if red_reward > 0 {
            outputs.push(TransactionOutput::new(red_reward, miner_data.script_public_key.clone()));
        }

        // Build the current block's payload
        let subsidy = self.calc_block_subsidy(daa_score);
        let payload = self.serialize_coinbase_payload(&CoinbaseData { blue_score: ghostdag_data.blue_score, subsidy, miner_data })?;

        Ok(CoinbaseTransactionTemplate {
            tx: Transaction::new(constants::TX_VERSION, vec![], outputs, 0, subnets::SUBNETWORK_ID_COINBASE, 0, payload),
            has_red_reward: red_reward > 0,
        })
    }

    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = data.miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }
        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
            .collect();

        Ok(payload)
    }

    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Keep only blue score and subsidy. Note that truncate does not modify capacity, so
        // the usual case where the payloads are the same size will not trigger a reallocation
        payload.truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY);
        payload.extend(
            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
        );

        Ok(payload)
    }

    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
        }

        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        let mut parser = PayloadParser::new(payload);

        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        if parser.remaining.len() < script_pub_key_len as usize {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        }

        let script_public_key =
            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
        let extra_data = parser.remaining;

        Ok(CoinbaseData { blue_score, subsidy, miner_data: MinerData { script_public_key, extra_data } })
    }

    pub fn calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        let months_since_deflationary_phase_started =
            ((daa_score - self.deflationary_phase_daa_score) / self.blocks_per_month) as usize;
        if months_since_deflationary_phase_started >= self.subsidy_by_month_table.len() {
            *(self.subsidy_by_month_table).last().unwrap()
        } else {
            self.subsidy_by_month_table[months_since_deflationary_phase_started]
        }
    }

    #[cfg(test)]
    pub fn legacy_calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        // Note that this calculation implicitly assumes that block per second = 1 (by assuming daa score diff is in second units).
        let months_since_deflationary_phase_started = (daa_score - self.deflationary_phase_daa_score) / SECONDS_PER_MONTH;
        assert!(months_since_deflationary_phase_started <= usize::MAX as u64);
        let months_since_deflationary_phase_started: usize = months_since_deflationary_phase_started as usize;
        if months_since_deflationary_phase_started >= SUBSIDY_BY_MONTH_TABLE.len() {
            *SUBSIDY_BY_MONTH_TABLE.last().unwrap()
        } else {
            SUBSIDY_BY_MONTH_TABLE[months_since_deflationary_phase_started]
        }
    }
}

/*
    This table was pre-calculated by calling `calcDeflationaryPeriodBlockSubsidyFloatCalc` (in cryptixd-go) for all months until reaching 0 subsidy.
    To regenerate this table, run `TestBuildSubsidyTable` in coinbasemanager_test.go (note the `deflationaryPhaseBaseSubsidy` therein).
    These values apply to 1 block per second.
*/
#[rustfmt::skip]
const SUBSIDY_BY_MONTH_TABLE: [u64; 426] = [
    200000000, 188774862, 178179743, 168179283, 158740105, 149830707, 141421356, 133483985, 125992104, 118920711,
    112246204, 105946309, 100000000, 94387431, 89089871, 84089641, 79370052, 74915353, 70710678, 66741992, 62996052,
    59460355, 56123102, 52973154, 50000000, 47193715, 44544935, 42044820, 39685026, 37457676, 35355339, 33370996,
    31498026, 29730177, 28061551, 26486577, 25000000, 23596857, 22272467, 21022410, 19842513, 18728838, 17677669,
    16685498, 15749013, 14865088, 14030775, 13243288, 12500000, 11798428, 11136233, 10511205, 9921256, 9364419,
    8838834, 8342749, 7874506, 7432544, 7015387, 6621644, 6250000, 5899214, 5568116, 5255602, 4960628, 4682209,
    4419417, 4171374, 3937253, 3716272, 3507693, 3310822, 3125000, 2949607, 2784058, 2627801, 2480314, 2341104,
    2209708, 2085687, 1968626, 1858136, 1753846, 1655411, 1562500, 1474803, 1392029, 1313900, 1240157, 1170552,
    1104854, 1042843, 984313, 929068, 876923, 827705, 781250, 737401, 696014, 656950, 620078, 585276, 552427,
    521421, 492156, 464534, 438461, 413852, 390625, 368700, 348007, 328475, 310039, 292638, 276213, 260710, 246078,
    232267, 219230, 206926, 195312, 184350, 174003, 164237, 155019, 146319, 138106, 130355, 123039, 116133, 109615,
    103463, 97656, 92175, 87001, 82118, 77509, 73159, 69053, 65177, 61519, 58066, 54807, 51731, 48828, 46087, 43500,
    41059, 38754, 36579, 34526, 32588, 30759, 29033, 27403, 25865, 24414, 23043, 21750, 20529, 19377, 18289, 17263,
    16294, 15379, 14516, 13701, 12932, 12207, 11521, 10875, 10264, 9688, 9144, 8631, 8147, 7689, 7258, 6850, 6466,
    6103, 5760, 5437, 5132, 4844, 4572, 4315, 4073, 3844, 3629, 3425, 3233, 3051, 2880, 2718, 2566, 2422, 2286, 2157,
    2036, 1922, 1814, 1712, 1616, 1525, 1440, 1359, 1283, 1211, 1143, 1078, 1018, 961, 907, 856, 808, 762, 720, 679,
    641, 605, 571, 539, 509, 480, 453, 428, 404, 381, 360, 339, 320, 302, 285, 269, 254, 240, 226, 214, 202, 190,
    180, 169, 160, 151, 142, 134, 127, 120, 113, 107, 101, 95, 90, 84, 80, 75, 71, 67, 63, 60, 56, 53, 50, 47, 45,
    42, 40, 37, 35, 33, 31, 30, 28, 26, 25, 23, 22, 21, 20, 18, 17, 16, 15, 15, 14, 13, 12, 11, 11, 10, 10, 9, 8,
    8, 7, 7, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
];



#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAINNET_PARAMS;
    use cryptix_consensus_core::{
        config::params::{Params, TESTNET11_PARAMS},
        constants::SOMPI_PER_CRYPTIX,
        network::NetworkId,
        tx::scriptvec,
    };

    #[test]
    fn calc_high_bps_total_rewards_delta() {
        const SECONDS_PER_MONTH: u64 = 2629800;

        let legacy_cbm = create_legacy_manager();
        let pre_deflationary_rewards = legacy_cbm.pre_deflationary_phase_base_subsidy * legacy_cbm.deflationary_phase_daa_score;
        let total_rewards: u64 = pre_deflationary_rewards + SUBSIDY_BY_MONTH_TABLE.iter().map(|x| x * SECONDS_PER_MONTH).sum::<u64>();
        let testnet_11_bps = TESTNET11_PARAMS.bps();
        let total_high_bps_rewards_rounded_up: u64 = pre_deflationary_rewards
            + SUBSIDY_BY_MONTH_TABLE
                .iter()
                .map(|x| ((x + testnet_11_bps - 1) / testnet_11_bps * testnet_11_bps) * SECONDS_PER_MONTH)
                .sum::<u64>();

        let cbm = create_manager(&TESTNET11_PARAMS);
        let total_high_bps_rewards: u64 =
            pre_deflationary_rewards + cbm.subsidy_by_month_table.iter().map(|x| x * cbm.blocks_per_month).sum::<u64>();
        assert_eq!(total_high_bps_rewards_rounded_up, total_high_bps_rewards, "subsidy adjusted to bps must be rounded up");

        let delta = total_high_bps_rewards as i64 - total_rewards as i64;

        println!("Total rewards: {} sompi => {} CYTX", total_rewards, total_rewards / SOMPI_PER_CRYPTIX);
        println!("Total high bps rewards: {} sompi => {} CYTX", total_high_bps_rewards, total_high_bps_rewards / SOMPI_PER_CRYPTIX);
        println!("Delta: {} sompi => {} CYTX", delta, delta / SOMPI_PER_CRYPTIX as i64);
    }

    #[test]
    fn subsidy_by_month_table_test() {
        let cbm = create_legacy_manager();
        cbm.subsidy_by_month_table.iter().enumerate().for_each(|(i, x)| {
            assert_eq!(SUBSIDY_BY_MONTH_TABLE[i], *x, "for 1 BPS, const table and precomputed values must match");
        });

        for network_id in NetworkId::iter() {
            let cbm = create_manager(&network_id.into());
            cbm.subsidy_by_month_table.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    (SUBSIDY_BY_MONTH_TABLE[i] + cbm.bps() - 1) / cbm.bps(),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
        }
    }

    #[test]
    fn subsidy_test() {
        const PRE_DEFLATIONARY_PHASE_BASE_SUBSIDY: u64 = 3900000000;
        const DEFLATIONARY_PHASE_INITIAL_SUBSIDY: u64 = 200000000;
        const SECONDS_PER_MONTH: u64 = 2629800;
        const SECONDS_PER_HALVING: u64 = SECONDS_PER_MONTH * 12;

        for network_id in NetworkId::iter() {
            let params = &network_id.into();
            let cbm = create_manager(params);

            let pre_deflationary_phase_base_subsidy = PRE_DEFLATIONARY_PHASE_BASE_SUBSIDY / params.bps();
            let deflationary_phase_initial_subsidy = DEFLATIONARY_PHASE_INITIAL_SUBSIDY / params.bps();
            let blocks_per_halving = SECONDS_PER_HALVING * params.bps();

            struct Test {
                name: &'static str,
                daa_score: u64,
                expected: u64,
            }

            let tests = vec![
                Test { name: "first mined block", daa_score: 1, expected: pre_deflationary_phase_base_subsidy },
                Test {
                    name: "before deflationary phase",
                    daa_score: params.deflationary_phase_daa_score - 1,
                    expected: pre_deflationary_phase_base_subsidy,
                },
                Test {
                    name: "start of deflationary phase",
                    daa_score: params.deflationary_phase_daa_score,
                    
                    expected: deflationary_phase_initial_subsidy,
                },
                Test {
                    name: "after one halving",
                    daa_score: params.deflationary_phase_daa_score + blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 2,
                },
                Test {
                    name: "after 2 halvings",
                    daa_score: params.deflationary_phase_daa_score + 2 * blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 4,
                },
                Test {
                    name: "after 5 halvings",
                    daa_score: params.deflationary_phase_daa_score + 5 * blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 32,
                },
                Test {
                    name: "after 32 halvings",
                    daa_score: params.deflationary_phase_daa_score + 32 * blocks_per_halving,
                    expected: ((DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 2_u64.pow(32)) + cbm.bps() - 1) / cbm.bps(),
                },
                Test {
                    name: "just before subsidy depleted",
                    daa_score: params.deflationary_phase_daa_score + 35 * blocks_per_halving,
                    expected: 1,
                },
                Test {
                    name: "after subsidy depleted",
                    daa_score: params.deflationary_phase_daa_score + 36 * blocks_per_halving,
                    expected: 0,
                },
            ];

            for t in tests {
                assert_eq!(cbm.calc_block_subsidy(t.daa_score), t.expected, "{} test '{}' failed", network_id, t.name);
                if params.bps() == 1 {
                    assert_eq!(cbm.legacy_calc_block_subsidy(t.daa_score), t.expected, "{} test '{}' failed", network_id, t.name);
                }
            }
        }
    }

    #[test]
    fn payload_serialization_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3];
        let data = CoinbaseData {
            blue_score: 56,
            subsidy: 1050000000,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data as &[u8],
            },
        };

        let payload = cbm.serialize_coinbase_payload(&data).unwrap();
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data, deserialized_data);

        // Test an actual mainnet payload
        let payload_hex =
            "b612c90100000000041a763e07000000000022202b32443ff740012157716d81216d09aebc39e5493c93a7181d92cb756c02c560ac302e31322e382f";
        let mut payload = vec![0u8; payload_hex.len() / 2];
        faster_hex::hex_decode(payload_hex.as_bytes(), &mut payload).unwrap();
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        let expected_data = CoinbaseData {
            blue_score: 29954742,
            subsidy: 31112698372,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(
                    0,
                    scriptvec![
                        32, 43, 50, 68, 63, 247, 64, 1, 33, 87, 113, 109, 129, 33, 109, 9, 174, 188, 57, 229, 73, 60, 147, 167, 24,
                        29, 146, 203, 117, 108, 2, 197, 96, 172,
                    ],
                ),
                extra_data: &[48u8, 46, 49, 50, 46, 56, 47] as &[u8],
            },
        };
        assert_eq!(expected_data, deserialized_data);
    }

    #[test]
    fn modify_payload_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3, 23, 98];
        let data = CoinbaseData {
            blue_score: 56345,
            subsidy: 1050000000,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data,
            },
        };

        let data2 = CoinbaseData {
            blue_score: data.blue_score,
            subsidy: data.subsidy,
            miner_data: MinerData {
                // Modify only miner data
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[33u8, 255, 33])),
                extra_data: &[2u8, 3, 23, 98, 34, 34] as &[u8],
            },
        };

        let mut payload = cbm.serialize_coinbase_payload(&data).unwrap();
        payload = cbm.modify_coinbase_payload(payload, &data2.miner_data).unwrap(); // Update the payload with the modified miner data
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data2, deserialized_data);
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(
            params.coinbase_payload_script_public_key_max_len,
            params.max_coinbase_payload_len,
            params.deflationary_phase_daa_score,
            params.pre_deflationary_phase_base_subsidy,
            params.target_time_per_block,
        )
    }

    /// Return a CoinbaseManager with legacy golang 1 BPS properties
    fn create_legacy_manager() -> CoinbaseManager {
        CoinbaseManager::new(150, 204, 259200, 3900000000, 1000)
    }
}
