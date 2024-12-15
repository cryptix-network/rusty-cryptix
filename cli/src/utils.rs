use crate::error::Error;
use crate::result::Result;
use cryptix_consensus_core::constants::SOMPI_PER_CRYPTIX;
use std::fmt::Display;

pub fn try_parse_required_nonzero_cryptix_as_sompi_u64<S: ToString + Display>(cryptix_amount: Option<S>) -> Result<u64> {
    if let Some(cryptix_amount) = cryptix_amount {
        let sompi_amount = cryptix_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_| Error::custom(format!("Supplied Cryptix amount is not valid: '{cryptix_amount}'")))?
            * SOMPI_PER_CRYPTIX as f64;
        if sompi_amount < 0.0 {
            Err(Error::custom("Supplied Cryptix amount is not valid: '{cryptix_amount}'"))
        } else {
            let sompi_amount = sompi_amount as u64;
            if sompi_amount == 0 {
                Err(Error::custom("Supplied required cryptix amount must not be a zero: '{cryptix_amount}'"))
            } else {
                Ok(sompi_amount)
            }
        }
    } else {
        Err(Error::custom("Missing Cryptix amount"))
    }
}

pub fn try_parse_required_cryptix_as_sompi_u64<S: ToString + Display>(cryptix_amount: Option<S>) -> Result<u64> {
    if let Some(cryptix_amount) = cryptix_amount {
        let sompi_amount = cryptix_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_| Error::custom(format!("Supplied Cytxapa amount is not valid: '{cryptix_amount}'")))?
            * SOMPI_PER_CRYPTIX as f64;
        if sompi_amount < 0.0 {
            Err(Error::custom("Supplied Cryptix amount is not valid: '{cryptix_amount}'"))
        } else {
            Ok(sompi_amount as u64)
        }
    } else {
        Err(Error::custom("Missing Cryptix amount"))
    }
}

pub fn try_parse_optional_cryptix_as_sompi_i64<S: ToString + Display>(cryptix_amount: Option<S>) -> Result<Option<i64>> {
    if let Some(cryptix_amount) = cryptix_amount {
        let sompi_amount = cryptix_amount
            .to_string()
            .parse::<f64>()
            .map_err(|_e| Error::custom(format!("Supplied Cytxapa amount is not valid: '{cryptix_amount}'")))?
            * SOMPI_PER_CRYPTIX as f64;
        if sompi_amount < 0.0 {
            Err(Error::custom("Supplied Cryptix amount is not valid: '{cryptix_amount}'"))
        } else {
            Ok(Some(sompi_amount as i64))
        }
    } else {
        Ok(None)
    }
}
