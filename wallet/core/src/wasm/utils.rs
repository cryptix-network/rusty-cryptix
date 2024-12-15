use crate::result::Result;
use js_sys::BigInt;
use cryptix_consensus_core::network::{NetworkType, NetworkTypeT};
use wasm_bindgen::prelude::*;
use workflow_wasm::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "bigint | number | HexString")]
    #[derive(Clone, Debug)]
    pub type ISompiToCryptix;
}

/// Convert a Cryptix string to Sompi represented by bigint.
/// This function provides correct precision handling and
/// can be used to parse user input.
/// @category Wallet SDK
#[wasm_bindgen(js_name = "cryptixToSompi")]
pub fn cryptix_to_sompi(cryptix: String) -> Option<BigInt> {
    crate::utils::try_cryptix_str_to_sompi(cryptix).ok().flatten().map(Into::into)
}

///
/// Convert Sompi to a string representation of the amount in Cryptix.
///
/// @category Wallet SDK
///
#[wasm_bindgen(js_name = "sompiToCryptixString")]
pub fn sompi_to_cryptix_string(sompi: ISompiToCryptix) -> Result<String> {
    let sompi = sompi.try_as_u64()?;
    Ok(crate::utils::sompi_to_cryptix_string(sompi))
}

///
/// Format a Sompi amount to a string representation of the amount in Cryptix with a suffix
/// based on the network type (e.g. `CYTX` for mainnet, `TCYTX` for testnet,
/// `SCYTX` for simnet, `DCYTX` for devnet).
///
/// @category Wallet SDK
///
#[wasm_bindgen(js_name = "sompiToCryptixStringWithSuffix")]
pub fn sompi_to_cryptix_string_with_suffix(sompi: ISompiToCryptix, network: &NetworkTypeT) -> Result<String> {
    let sompi = sompi.try_as_u64()?;
    let network_type = NetworkType::try_from(network)?;
    Ok(crate::utils::sompi_to_cryptix_string_with_suffix(sompi, &network_type))
}
