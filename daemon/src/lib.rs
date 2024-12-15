pub mod cpu_miner;
pub mod error;
pub mod imports;
pub mod cryptixd;
pub mod result;

use std::fmt::Display;

use crate::imports::*;
pub use crate::result::Result;
pub use cpu_miner::{CpuMiner, CpuMinerConfig, CpuMinerCtl};
pub use cryptixd::{Cryptixd, CryptixdConfig, CryptixdCtl};
use workflow_core::runtime;
use workflow_node::process::Event as ProcessEvent;
use workflow_store::fs::*;

pub static LOCATIONS: &[&str] = &[
    "bin",
    "../target/release",
    "../target/debug",
    "../../cryptix-cpu-miner/target/debug",
    "../../cryptix-cpu-miner/target/release",
    "bin/windows-x64",
    "bin/linux-ia32",
    "bin/linux-x64",
    "bin/linux-arm64",
    "bin/macos-x64",
    "bin/macos-aarch64",
];

pub async fn locate_binaries(root: &str, name: &str) -> Result<Vec<PathBuf>> {
    // log_info!("locating binaries in root: {root} name: {name}");

    if !runtime::is_nw() && !runtime::is_node() && !runtime::is_native() {
        return Err(Error::Platform);
    }

    let name = if runtime::is_windows() { name.to_string() + ".exe" } else { name.to_string() };

    let locations = LOCATIONS
        .iter()
        .map(|path| PathBuf::from(&root).join(path).join(&name).normalize().map_err(|e| e.into()))
        .collect::<Result<Vec<_>>>()?;

    let mut list = Vec::new();
    for path in locations {
        if exists(&path).await? {
            list.push(path);
        }
    }

    Ok(list)
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub enum DaemonKind {
    Cryptixd,
    CpuMiner,
}

#[derive(Default)]
pub struct Daemons {
    pub cryptixd: Option<Arc<dyn CryptixdCtl + Send + Sync + 'static>>,
    // pub cryptixd_automute : Arc<
    pub cpu_miner: Option<Arc<dyn CpuMinerCtl + Send + Sync + 'static>>,
}

impl Daemons {
    pub fn new() -> Self {
        Self { cryptixd: None, cpu_miner: None }
    }

    pub fn with_cryptixd(mut self, cryptixd: Arc<dyn CryptixdCtl + Send + Sync + 'static>) -> Self {
        self.cryptixd = Some(cryptixd);
        self
    }

    pub fn with_cpu_miner(mut self, cpu_miner: Arc<dyn CpuMinerCtl + Send + Sync + 'static>) -> Self {
        self.cpu_miner = Some(cpu_miner);
        self
    }

    pub fn cryptixd(&self) -> Arc<dyn CryptixdCtl + Send + Sync + 'static> {
        self.cryptixd.as_ref().expect("accessing Daemons::cryptixd while cryptixd option is None").clone()
    }

    pub fn try_cryptixd(&self) -> Option<Arc<dyn CryptixdCtl + Send + Sync + 'static>> {
        self.cryptixd.clone()
    }

    pub fn cpu_miner(&self) -> Arc<dyn CpuMinerCtl + Send + Sync + 'static> {
        self.cpu_miner.as_ref().expect("accessing Daemons::cpu_miner while cpu_miner option is None").clone()
    }

    pub fn try_cpu_miner(&self) -> Option<Arc<dyn CpuMinerCtl + Send + Sync + 'static>> {
        self.cpu_miner.clone()
    }
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct DaemonEvent {
    pub kind: DaemonKind,
    pub inner: ProcessEvent,
}

impl DaemonEvent {
    pub fn new(kind: DaemonKind, inner: ProcessEvent) -> Self {
        Self { kind, inner }
    }

    pub fn kind(&self) -> &DaemonKind {
        &self.kind
    }
}

impl From<DaemonEvent> for ProcessEvent {
    fn from(event: DaemonEvent) -> Self {
        event.inner
    }
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub uptime: Option<u64>,
}

impl Display for DaemonStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(uptime) = self.uptime {
            write!(f, "running - uptime: {}", format_duration(uptime))?;
        } else {
            write!(f, "not running")?;
        }
        Ok(())
    }
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / (24 * 60 * 60);
    let hours = (seconds / (60 * 60)) % 24;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;

    if days > 0 {
        format!("{0} days {1:02} hours, {2:02} minutes, {3:02} seconds", days, hours, minutes, seconds)
    } else {
        format!("{0:02} hours, {1:02} minutes, {2:02} seconds", hours, minutes, seconds)
    }
}
