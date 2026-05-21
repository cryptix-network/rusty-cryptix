//!
//! Address scanner implementation, responsible for
//! aggregating UTXOs from multiple addresses and
//! building corresponding balances.
//!

use crate::derivation::AddressManager;
use crate::imports::*;
use crate::utxo::balance::AtomicBalance;
use crate::utxo::{UtxoContext, UtxoEntryReference, UtxoEntryReferenceExtension};
use std::cmp::max;

pub const DEFAULT_WINDOW_SIZE: usize = 8;

#[derive(Default, Clone, Debug)]
pub struct SmartScanSummary {
    pub scanned_address_count: usize,
    pub discovered_address_count: usize,
    pub registered_address_count: usize,
    pub last_address_index: u32,
}

#[derive(Default, Clone, Copy)]
pub enum ScanExtent {
    /// Scan until an empty range is found
    #[default]
    EmptyWindow,
    /// Scan until a specific depth (a particular derivation index)
    Depth(u32),
}

enum Provider {
    AddressManager(Arc<AddressManager>),
    AddressSet(HashSet<Address>),
}

pub struct Scan {
    provider: Provider,
    window_size: Option<usize>,
    monitor_window_size: Option<usize>,
    extent: Option<ScanExtent>,
    start_index: Option<u32>,
    balance: Arc<AtomicBalance>,
    current_daa_score: u64,
}

impl Scan {
    pub fn new_with_address_manager(
        address_manager: Arc<AddressManager>,
        balance: &Arc<AtomicBalance>,
        current_daa_score: u64,
        window_size: Option<usize>,
        monitor_window_size: Option<usize>,
        extent: Option<ScanExtent>,
        start_index: Option<u32>,
    ) -> Scan {
        Scan {
            provider: Provider::AddressManager(address_manager),
            window_size,
            monitor_window_size,
            extent,
            start_index,
            balance: balance.clone(),
            current_daa_score,
        }
    }
    pub fn new_with_address_set(addresses: HashSet<Address>, balance: &Arc<AtomicBalance>, current_daa_score: u64) -> Scan {
        Scan {
            provider: Provider::AddressSet(addresses),
            window_size: None,
            monitor_window_size: None,
            extent: None,
            start_index: None,
            balance: balance.clone(),
            current_daa_score,
        }
    }

    pub async fn scan(&self, utxo_context: &UtxoContext) -> Result<()> {
        // block notifications while scanning...
        let _lock = utxo_context.processor().notification_lock().await;

        match &self.provider {
            Provider::AddressManager(address_manager) => self.scan_with_address_manager(address_manager, utxo_context).await,
            Provider::AddressSet(addresses) => self.scan_with_address_set(addresses, utxo_context).await,
        }
    }

    pub async fn scan_with_address_manager(&self, address_manager: &Arc<AddressManager>, utxo_context: &UtxoContext) -> Result<()> {
        let params = utxo_context.processor().network_params()?;

        let window_size = self.window_size.unwrap_or(DEFAULT_WINDOW_SIZE) as u32;
        let extent = self.extent.expect("address manager requires an extent");

        let mut cursor: u32 = self.start_index.unwrap_or(0);
        let mut last_address_index = address_manager.index();

        'scan: loop {
            // scan first up to address index, then in window chunks
            let first = cursor;
            let last = if cursor == 0 { max(last_address_index + 1, window_size) } else { cursor + window_size };
            cursor = last;

            // generate address derivations
            let addresses = address_manager.get_range(first..last)?;
            // register address in the utxo context; NOTE:  during the scan,
            // before `get_utxos_by_addresses()` is complete we may receive
            // new transactions  as such utxo context should be aware of the
            // addresses used before we start interacting with them.
            utxo_context.register_addresses(&addresses).await?;

            let ts = Instant::now();
            let resp = utxo_context.processor().rpc_api().get_utxos_by_addresses(addresses).await?;
            let elapsed_sec = ts.elapsed().as_secs_f32();
            if elapsed_sec > 1.0 {
                log_info!("get_utxos_by_address() fetched {} entries in: {:.4} sec", resp.len(), elapsed_sec);
            }
            yield_executor().await;

            if !resp.is_empty() {
                let refs: Vec<UtxoEntryReference> = resp.into_iter().map(UtxoEntryReference::from).collect();
                for utxo_ref in refs.iter() {
                    if let Some(address) = utxo_ref.utxo.address.as_ref() {
                        if let Some(utxo_address_index) = address_manager.inner().address_to_index_map.get(address) {
                            if last_address_index < *utxo_address_index {
                                last_address_index = *utxo_address_index;
                            }
                        } else {
                            panic!("Account::scan_address_manager() has received an unknown address: `{address}`");
                        }
                    }
                }

                let balance: Balance = refs.iter().fold(Balance::default(), |mut balance, r| {
                    let entry_balance = r.balance(params, self.current_daa_score);
                    balance.mature += entry_balance.mature;
                    balance.pending += entry_balance.pending;
                    balance.mature_utxo_count += entry_balance.mature_utxo_count;
                    balance.pending_utxo_count += entry_balance.pending_utxo_count;
                    balance.stasis_utxo_count += entry_balance.stasis_utxo_count;
                    balance
                });

                utxo_context.extend_from_scan(refs, self.current_daa_score).await?;

                self.balance.add(balance);
            } else {
                match &extent {
                    ScanExtent::EmptyWindow => {
                        if cursor > last_address_index + window_size {
                            break 'scan;
                        }
                    }
                    ScanExtent::Depth(depth) => {
                        if &cursor > depth {
                            break 'scan;
                        }
                    }
                }
            }
            yield_executor().await;
        }

        // update address manager with the last used index
        address_manager.set_index(last_address_index)?;

        Ok(())
    }

    pub async fn scan_smart(&self, utxo_context: &UtxoContext) -> Result<SmartScanSummary> {
        // block notifications while scanning...
        let _lock = utxo_context.processor().notification_lock().await;

        match &self.provider {
            Provider::AddressManager(address_manager) => self.scan_with_address_manager_smart(address_manager, utxo_context).await,
            Provider::AddressSet(addresses) => {
                self.scan_with_address_set(addresses, utxo_context).await?;
                Ok(SmartScanSummary {
                    scanned_address_count: addresses.len(),
                    discovered_address_count: addresses.len(),
                    registered_address_count: addresses.len(),
                    last_address_index: 0,
                })
            }
        }
    }

    pub async fn scan_with_address_manager_smart(
        &self,
        address_manager: &Arc<AddressManager>,
        utxo_context: &UtxoContext,
    ) -> Result<SmartScanSummary> {
        let params = utxo_context.processor().network_params()?;

        let window_size = self.window_size.unwrap_or(DEFAULT_WINDOW_SIZE) as u32;
        let monitor_window_size = self.monitor_window_size.unwrap_or(self.window_size.unwrap_or(DEFAULT_WINDOW_SIZE)) as u32;
        let extent = self.extent.expect("address manager requires an extent");

        let mut cursor: u32 = self.start_index.unwrap_or(0);
        let stored_address_index = address_manager.index();
        let mut last_address_index = stored_address_index;
        let mut last_found_address_index: Option<u32> = None;
        let mut scanned_address_count = 0usize;
        let mut registered_addresses = HashSet::<Address>::new();
        let mut discovered_addresses = HashSet::<Address>::new();

        'scan: loop {
            // Smart scan queries the historical range, but does not subscribe
            // every empty address. Only addresses with UTXOs plus the final
            // active gap window are registered for live notifications.
            let first = cursor;
            if let ScanExtent::Depth(depth) = extent {
                if first > depth {
                    break 'scan;
                }
            }
            let last = match extent {
                ScanExtent::Depth(depth) => first.saturating_add(window_size).min(depth.saturating_add(1)),
                ScanExtent::EmptyWindow => first.saturating_add(window_size),
            };
            if last <= first {
                break 'scan;
            }
            cursor = last;

            let addresses = address_manager.get_range(first..last)?;
            scanned_address_count += addresses.len();

            let ts = Instant::now();
            let resp = utxo_context.processor().rpc_api().get_utxos_by_addresses(addresses).await?;
            let elapsed_sec = ts.elapsed().as_secs_f32();
            if elapsed_sec > 1.0 {
                log_info!("get_utxos_by_address() fetched {} entries in: {:.4} sec", resp.len(), elapsed_sec);
            }
            yield_executor().await;

            if !resp.is_empty() {
                let refs: Vec<UtxoEntryReference> = resp.into_iter().map(UtxoEntryReference::from).collect();
                let mut discovered_batch = Vec::<Address>::new();
                for utxo_ref in refs.iter() {
                    if let Some(address) = utxo_ref.utxo.address.as_ref() {
                        if let Some(utxo_address_index) = address_manager.inner().address_to_index_map.get(address) {
                            if last_address_index < *utxo_address_index {
                                last_address_index = *utxo_address_index;
                            }
                            last_found_address_index = Some(
                                last_found_address_index
                                    .map(|current| max(current, *utxo_address_index))
                                    .unwrap_or(*utxo_address_index),
                            );
                            if discovered_addresses.insert(address.clone()) {
                                discovered_batch.push(address.clone());
                            }
                        } else {
                            panic!("Account::scan_address_manager_smart() has received an unknown address: `{address}`");
                        }
                    }
                }

                if !discovered_batch.is_empty() {
                    utxo_context.register_addresses(&discovered_batch).await?;
                    registered_addresses.extend(discovered_batch);
                }

                let balance: Balance = refs.iter().fold(Balance::default(), |mut balance, r| {
                    let entry_balance = r.balance(params, self.current_daa_score);
                    balance.mature += entry_balance.mature;
                    balance.pending += entry_balance.pending;
                    balance.mature_utxo_count += entry_balance.mature_utxo_count;
                    balance.pending_utxo_count += entry_balance.pending_utxo_count;
                    balance.stasis_utxo_count += entry_balance.stasis_utxo_count;
                    balance
                });

                utxo_context.extend_from_scan(refs, self.current_daa_score).await?;

                self.balance.add(balance);
            } else {
                match &extent {
                    ScanExtent::EmptyWindow => {
                        let gap_anchor = last_found_address_index.unwrap_or(0);
                        if cursor >= gap_anchor.saturating_add(window_size) {
                            break 'scan;
                        }
                    }
                    ScanExtent::Depth(depth) => {
                        if &cursor > depth {
                            break 'scan;
                        }
                    }
                }
            }
            yield_executor().await;
        }

        let monitor_first = last_address_index;
        let monitor_last = last_address_index.saturating_add(monitor_window_size).saturating_add(1);
        let monitor_addresses = address_manager.get_range(monitor_first..monitor_last)?;
        let monitor_addresses =
            monitor_addresses.into_iter().filter(|address| !registered_addresses.contains(address)).collect::<Vec<_>>();
        if !monitor_addresses.is_empty() {
            utxo_context.register_addresses(&monitor_addresses).await?;
            let ts = Instant::now();
            let resp = utxo_context.processor().rpc_api().get_utxos_by_addresses(monitor_addresses.clone()).await?;
            let elapsed_sec = ts.elapsed().as_secs_f32();
            if elapsed_sec > 1.0 {
                log_info!("get_utxos_by_address() fetched {} entries in: {:.4} sec", resp.len(), elapsed_sec);
            }
            scanned_address_count += monitor_addresses.len();
            registered_addresses.extend(monitor_addresses);

            if !resp.is_empty() {
                let refs: Vec<UtxoEntryReference> = resp.into_iter().map(UtxoEntryReference::from).collect();
                for utxo_ref in refs.iter() {
                    if let Some(address) = utxo_ref.utxo.address.as_ref() {
                        if discovered_addresses.insert(address.clone()) {
                            if let Some(utxo_address_index) = address_manager.inner().address_to_index_map.get(address) {
                                if last_address_index < *utxo_address_index {
                                    last_address_index = *utxo_address_index;
                                }
                                last_found_address_index = Some(
                                    last_found_address_index
                                        .map(|current| max(current, *utxo_address_index))
                                        .unwrap_or(*utxo_address_index),
                                );
                            }
                        }
                    }
                }

                let balance: Balance = refs.iter().fold(Balance::default(), |mut balance, r| {
                    let entry_balance = r.balance(params, self.current_daa_score);
                    balance.mature += entry_balance.mature;
                    balance.pending += entry_balance.pending;
                    balance.mature_utxo_count += entry_balance.mature_utxo_count;
                    balance.pending_utxo_count += entry_balance.pending_utxo_count;
                    balance.stasis_utxo_count += entry_balance.stasis_utxo_count;
                    balance
                });

                utxo_context.extend_from_scan(refs, self.current_daa_score).await?;
                self.balance.add(balance);
            }
        }

        address_manager.set_index(last_address_index)?;

        Ok(SmartScanSummary {
            scanned_address_count,
            discovered_address_count: discovered_addresses.len(),
            registered_address_count: registered_addresses.len(),
            last_address_index,
        })
    }

    pub async fn scan_with_address_set(&self, address_set: &HashSet<Address>, utxo_context: &UtxoContext) -> Result<()> {
        let params = utxo_context.processor().network_params()?;
        let address_vec = address_set.iter().cloned().collect::<Vec<_>>();

        utxo_context.register_addresses(&address_vec).await?;
        let resp = utxo_context.processor().rpc_api().get_utxos_by_addresses(address_vec).await?;
        let refs: Vec<UtxoEntryReference> = resp.into_iter().map(UtxoEntryReference::from).collect();

        let balance: Balance = refs.iter().fold(Balance::default(), |mut balance, r| {
            let entry_balance = r.balance(params, self.current_daa_score);
            balance.mature += entry_balance.mature;
            balance.pending += entry_balance.pending;
            balance.mature_utxo_count += entry_balance.mature_utxo_count;
            balance.pending_utxo_count += entry_balance.pending_utxo_count;
            balance.stasis_utxo_count += entry_balance.stasis_utxo_count;
            balance
        });
        yield_executor().await;

        utxo_context.extend_from_scan(refs, self.current_daa_score).await?;

        if !balance.is_empty() {
            self.balance.add(balance);
        }

        Ok(())
    }
}
