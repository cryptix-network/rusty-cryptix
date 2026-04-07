pub const DEFAULT_PAYLOAD_SOFT_CAP_PER_BLOCK_BYTES: u64 = 32_768;
pub const DEFAULT_PAYLOAD_OVERCAP_FEERATE_MULTIPLIER: f64 = 2.0;

/// Policy houses the policy (configuration parameters) which is used to control
/// the generation of block templates. See the documentation for
/// NewBlockTemplate for more details on how each of these parameters are used.
#[derive(Clone)]
pub struct Policy {
    /// max_block_mass is the maximum block mass to be used when generating a block template.
    pub(crate) max_block_mass: u64,
    /// payload soft cap (bytes) considered during template selection. Policy-only, non-consensus.
    pub(crate) payload_soft_cap_per_block_bytes: u64,
    /// multiplier used to derive over-cap feerate floor from minimum relay feerate.
    pub(crate) payload_overcap_feerate_multiplier: f64,
    /// minimum relay feerate in sompi/gram.
    pub(crate) minimum_relay_feerate: f64,
}

impl Policy {
    pub fn new(max_block_mass: u64) -> Self {
        Self {
            max_block_mass,
            payload_soft_cap_per_block_bytes: DEFAULT_PAYLOAD_SOFT_CAP_PER_BLOCK_BYTES,
            payload_overcap_feerate_multiplier: DEFAULT_PAYLOAD_OVERCAP_FEERATE_MULTIPLIER,
            minimum_relay_feerate: 1.0,
        }
    }

    pub fn new_with_payload_policy(
        max_block_mass: u64,
        payload_soft_cap_per_block_bytes: u64,
        payload_overcap_feerate_multiplier: f64,
        minimum_relay_feerate: f64,
    ) -> Self {
        Self { max_block_mass, payload_soft_cap_per_block_bytes, payload_overcap_feerate_multiplier, minimum_relay_feerate }
    }

    pub fn overcap_feerate_floor(&self) -> f64 {
        self.minimum_relay_feerate.max(0.0) * self.payload_overcap_feerate_multiplier
    }
}
