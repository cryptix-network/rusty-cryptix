use cryptix_addresses::Address as CryptixAddress;
use dashmap::DashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use workflow_log::log_info;

pub fn toggle(flag: &Arc<AtomicBool>) -> &'static str {
    let v = !flag.load(Ordering::SeqCst);
    flag.store(v, Ordering::SeqCst);
    if v {
        "on"
    } else {
        "off"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Track {
    Daa = 0,
    Balance,
    Pending,
    Tx,
    Utxo,
}

impl FromStr for Track {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Track, String> {
        match s {
            "daa" => Ok(Track::Daa),
            "balance" => Ok(Track::Balance),
            "pending" => Ok(Track::Pending),
            "tx" => Ok(Track::Tx),
            "utxo" => Ok(Track::Utxo),
            _ => Err(format!("unknown attribute '{}'", s)),
        }
    }
}

impl fmt::Display for Track {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Track::Daa => write!(f, "daa"),
            Track::Balance => write!(f, "balance"),
            Track::Pending => write!(f, "pending"),
            Track::Tx => write!(f, "tx"),
            Track::Utxo => write!(f, "utxo"),
        }
    }
}

pub struct Flags(DashMap<Track, Arc<AtomicBool>>);

impl Default for Flags {
    fn default() -> Self {
        let mut map = DashMap::new();
        let iter = [(Track::Daa, false), (Track::Balance, false), (Track::Pending, false), (Track::Tx, false), (Track::Utxo, false)]
            .into_iter()
            .map(|(flag, default)| (flag, Arc::new(AtomicBool::new(default))));
        map.extend(iter);
        Flags(map)
    }
}

impl Flags {
    pub fn map(&self) -> &DashMap<Track, Arc<AtomicBool>> {
        &self.0
    }

    pub fn toggle(&self, track: Track) {
        let flag = self.0.get(&track).unwrap();
        let v = !flag.load(Ordering::SeqCst);
        flag.store(v, Ordering::SeqCst);
        let s = if v { "on" } else { "off" };
        log_info!("{} is {s}", track.to_string());
    }

    pub fn get(&self, track: Track) -> bool {
        self.0.get(&track).unwrap().load(Ordering::SeqCst)
    }
}

/// Attempts to convert a wallet address string to a 32-byte token address hash.
/// Returns Ok(hash) if successful, or Err with an error message if the address is invalid.
pub fn try_convert_to_token_address(address: &str) -> Result<[u8; 32], String> {
    // First try to parse as hex directly
    if let Ok(bytes) = hex::decode(address.trim_start_matches("0x")) {
        if bytes.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            return Ok(hash);
        } else {
            return Err(format!("Hex address must be 32 bytes (64 hex characters), got {} bytes", bytes.len()));
        }
    }
    
    // If not hex, try to parse as a Cryptix address
    match CryptixAddress::try_from(address) {
        Ok(addr) => {
            let payload = addr.payload.as_slice();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(payload);
            Ok(hash)
        },
        Err(e) => Err(format!("Invalid address format: {}", e))
    }
}

/// Asks the user if they want to convert a wallet address to a token address.
/// Returns true if the user confirms, false otherwise.
pub fn ask_convert_address() -> bool {
    println!("The provided address appears to be a wallet address, not a token address (32-byte hex).");
    println!("Token operations require addresses in raw 32-byte hex format.");
    println!("Would you like to automatically convert this wallet address to a token address? (y/N)");
    
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    } else {
        false
    }
}

/// Attempts to convert a wallet address string to a 32-byte token address hash.
/// This version is specifically for handling Option<String> inputs.
/// Returns Ok(hash) if successful, or Err with an error message if the address is invalid.
pub fn try_convert_option_to_token_address(address: &Option<String>) -> Result<[u8; 32], String> {
    match address {
        Some(addr) => try_convert_to_token_address(addr),
        None => Err("Address is required".to_string())
    }
}

/// Helper function to safely get a string from an Option<String> for display purposes.
/// Returns the string if Some, or a default message if None.
pub fn option_string_to_display(opt: &Option<String>, default: &str) -> String {
    opt.as_ref().map(|s| s.clone()).unwrap_or_else(|| default.to_string())
}
