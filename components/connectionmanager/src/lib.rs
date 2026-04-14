use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Write,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cryptix_addressmanager::{AddressManager, NetAddress};
use cryptix_core::{debug, info, warn};
use cryptix_p2p_lib::{common::ProtocolError, ConnectionError, Peer, PeerKey};
use cryptix_utils::triggers::SingleTrigger;
use duration_string::DurationString;
use futures_util::future::{join_all, try_join_all};
use itertools::Itertools;
use parking_lot::Mutex as ParkingLotMutex;
use rand::{seq::SliceRandom, thread_rng};
use reqwest::{redirect::Policy as RedirectPolicy, Client as HttpClient, Url as ParsedUrl};
use secp256k1::{schnorr::Signature as SchnorrSignature, Message as SecpMessage, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex as TokioMutex,
    },
    time::{interval, MissedTickBehavior},
};

pub const DEFAULT_BANSERVER_URL: &str = "https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot";
pub const DEFAULT_BANSERVER_SECONDARY_URL: &str = "https://guard.seed2.cryptix-network.org/api/v1/antifraud/snapshot";
pub const ANTI_FRAUD_ZERO_HASH: [u8; 32] = [0u8; 32];
pub const ANTI_FRAUD_HASH_WINDOW_LEN: usize = 3;
const LOCAL_UNIFIED_NODE_BAN_DURATION: Duration = Duration::from_secs(3 * 60 * 60);
const BANSERVER_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);
const BANSERVER_CONSISTENCY_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const BANSERVER_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const BANSERVER_REPLICATION_LAG_TOLERANCE: Duration = Duration::from_secs(15);
const BANSERVER_FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const BANSERVER_MAX_IPS: usize = 4096;
const BANSERVER_MAX_IP_ENTRY_LEN: usize = 64;
const BANSERVER_MAX_NODE_IDS: usize = 4096;
const BANSERVER_NODE_ID_HEX_LEN: usize = 64;
const BANSERVER_SIGNATURE_HEX_LEN: usize = 128;
const BANSERVER_MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const BANSERVER_BANNED_CONNECTION_RETRY_DELAY: Duration = Duration::from_secs(60);
const ANTI_FRAUD_DOMAIN_SEP: &[u8] = b"cryptix-antifraud-snapshot-v1";
const ANTI_FRAUD_SCHEMA_VERSION: u8 = 1;
const ANTI_FRAUD_PERSIST_DIR: &str = "antifraud";
const ANTI_FRAUD_CURRENT_FILE: &str = "current.snapshot";
const ANTI_FRAUD_PREVIOUS_FILE: &str = "previous.snapshot";
const ANTI_FRAUD_PUBKEY_CURRENT_HEX: &str = "c93b4ed533a76866a3c3ea1cc0bc3e70c0dbe32a945057b5dff95b88ce9280dd";
const ANTI_FRAUD_PUBKEY_NEXT_HEX: &str = "fc10777c57060195c83e9885c790c8a26496d305b366b8e5fbf475203c680f79";
const PEER_CANDIDATE_MAX_AGE: Duration = Duration::from_secs(120);

pub struct ConnectionManager {
    p2p_adaptor: Arc<cryptix_p2p_lib::Adaptor>,
    outbound_target: usize,
    inbound_limit: usize,
    dns_seeders: &'static [&'static str],
    default_port: u16,
    address_manager: Arc<ParkingLotMutex<AddressManager>>,
    connection_requests: TokioMutex<HashMap<SocketAddr, ConnectionRequest>>,
    force_next_iteration: UnboundedSender<()>,
    shutdown_signal: SingleTrigger,
    banserver_enabled: bool,
    banserver_primary_url: String,
    banserver_secondary_url: String,
    anti_fraud_network: AntiFraudNetwork,
    anti_fraud_persist_dir: Option<PathBuf>,
    anti_fraud_state: ParkingLotMutex<AntiFraudState>,
    banserver_banned_ips: ParkingLotMutex<HashSet<IpAddr>>,
    banserver_banned_strong_node_ids: ParkingLotMutex<HashSet<[u8; 32]>>,
    locally_banned_unified_node_ids: ParkingLotMutex<HashMap<[u8; 32], Instant>>,
}

#[derive(Clone, Debug)]
struct ConnectionRequest {
    next_attempt: SystemTime,
    is_permanent: bool,
    attempts: u32,
}

#[derive(Clone, Debug)]
struct BanserverPayload {
    enabled: bool,
    snapshot: AntiFraudSnapshot,
}

#[derive(Debug)]
enum BanserverFetchOutcome {
    Enabled(BanserverPayload),
    DisabledByGate(BanserverPayload),
    Unavailable,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SeedServerFailureAction {
    RetrySoon,
    EnablePeerFallback,
    KeepPeerFallback,
}

#[derive(Debug)]
struct EndpointBanserverPayload {
    endpoint_name: &'static str,
    source_url: String,
    enabled: bool,
    payload: Option<BanserverPayload>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AntiFraudMode {
    Full,
    Restricted,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AntiFraudNetwork {
    Mainnet = 0,
    Testnet = 1,
    Devnet = 2,
    Simnet = 3,
}

impl AntiFraudNetwork {
    pub fn from_network_name(name: &str) -> Option<Self> {
        let lower = name.trim().to_ascii_lowercase();
        if lower == "mainnet" || lower == "cryptix-mainnet" {
            return Some(Self::Mainnet);
        }
        if lower == "testnet" || lower == "cryptix-testnet" || lower.starts_with("testnet-") || lower.starts_with("cryptix-testnet-") {
            return Some(Self::Testnet);
        }
        if lower == "devnet" || lower == "cryptix-devnet" {
            return Some(Self::Devnet);
        }
        if lower == "simnet" || lower == "cryptix-simnet" {
            return Some(Self::Simnet);
        }
        None
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            2 => Some(Self::Devnet),
            3 => Some(Self::Simnet),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AntiFraudSnapshotEnvelope {
    pub schema_version: u8,
    pub network: u8,
    pub snapshot_seq: u64,
    pub generated_at_ms: u64,
    pub signing_key_id: u8,
    pub banned_ips: Vec<Vec<u8>>,
    pub banned_node_ids: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
    pub antifraud_enabled: bool,
}

#[derive(Clone, Debug)]
struct AntiFraudSnapshot {
    schema_version: u8,
    network: AntiFraudNetwork,
    snapshot_seq: u64,
    generated_at_ms: u64,
    signing_key_id: u8,
    antifraud_enabled: bool,
    banned_ip_entries: Vec<Vec<u8>>,
    banned_node_id_entries: Vec<[u8; 32]>,
    signature: [u8; 64],
    root_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedSnapshotV1 {
    schema_version: u8,
    network: u8,
    snapshot_seq: u64,
    generated_at_ms: u64,
    signing_key_id: u8,
    #[serde(default = "default_antifraud_enabled")]
    antifraud_enabled: bool,
    banned_ips: Vec<String>,
    banned_node_ids: Vec<String>,
    signature: String,
}

fn default_antifraud_enabled() -> bool {
    true
}

#[derive(Clone, Debug)]
struct PeerSnapshotVote {
    received_at: Instant,
    snapshot: AntiFraudSnapshot,
}

#[derive(Clone, Debug)]
pub struct IngestPeerSnapshotResult {
    pub applied: bool,
    pub root_hash: [u8; 32],
}

#[derive(Debug)]
struct AntiFraudState {
    runtime_enabled: bool,
    current_snapshot: Option<AntiFraudSnapshot>,
    hash_window: [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN],
    peer_votes: HashMap<String, PeerSnapshotVote>,
    peer_fallback_required: bool,
    seed_server_retry_pending: bool,
}

impl Default for AntiFraudState {
    fn default() -> Self {
        Self {
            runtime_enabled: false,
            current_snapshot: None,
            hash_window: [ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN],
            peer_votes: HashMap::new(),
            peer_fallback_required: false,
            seed_server_retry_pending: false,
        }
    }
}

impl ConnectionRequest {
    fn new(is_permanent: bool) -> Self {
        Self { next_attempt: SystemTime::now(), is_permanent, attempts: 0 }
    }
}

impl ConnectionManager {
    pub fn new(
        p2p_adaptor: Arc<cryptix_p2p_lib::Adaptor>,
        outbound_target: usize,
        inbound_limit: usize,
        dns_seeders: &'static [&'static str],
        default_port: u16,
        address_manager: Arc<ParkingLotMutex<AddressManager>>,
        banserver_enabled: bool,
        network_name: String,
        anti_fraud_persist_base_dir: Option<PathBuf>,
    ) -> Arc<Self> {
        let (tx, rx) = unbounded_channel::<()>();
        let banserver_primary_url = DEFAULT_BANSERVER_URL.to_owned();
        let banserver_secondary_url = DEFAULT_BANSERVER_SECONDARY_URL.to_owned();
        let anti_fraud_network = AntiFraudNetwork::from_network_name(&network_name).unwrap_or(AntiFraudNetwork::Mainnet);
        let anti_fraud_persist_dir = anti_fraud_persist_base_dir.map(|path| path.join(ANTI_FRAUD_PERSIST_DIR));
        let manager = Arc::new(Self {
            p2p_adaptor,
            outbound_target,
            inbound_limit,
            address_manager,
            connection_requests: Default::default(),
            force_next_iteration: tx,
            shutdown_signal: SingleTrigger::new(),
            dns_seeders,
            default_port,
            banserver_enabled,
            banserver_primary_url,
            banserver_secondary_url,
            anti_fraud_network,
            anti_fraud_persist_dir,
            anti_fraud_state: ParkingLotMutex::new(AntiFraudState::default()),
            banserver_banned_ips: ParkingLotMutex::new(HashSet::new()),
            banserver_banned_strong_node_ids: ParkingLotMutex::new(HashSet::new()),
            locally_banned_unified_node_ids: ParkingLotMutex::new(HashMap::new()),
        });
        manager.try_load_persisted_snapshot();
        manager.clone().start_event_loop(rx);
        manager.force_next_iteration.send(()).unwrap();
        manager
    }

    fn start_event_loop(self: Arc<Self>, mut rx: UnboundedReceiver<()>) {
        let mut ticker = interval(Duration::from_secs(30));
        let mut banserver_ticker = interval(BANSERVER_REFRESH_INTERVAL);
        let mut banserver_consistency_retry_ticker = interval(BANSERVER_CONSISTENCY_RETRY_INTERVAL);
        let mut banserver_retry_ticker = interval(BANSERVER_RETRY_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        banserver_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        banserver_consistency_retry_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        banserver_retry_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tokio::spawn(async move {
            self.clone().refresh_banserver_bans().await;
            // Consume immediate interval ticks so next refresh/retry are full interval away.
            let _ = banserver_ticker.tick().await;
            let _ = banserver_consistency_retry_ticker.tick().await;
            let _ = banserver_retry_ticker.tick().await;
            loop {
                if self.shutdown_signal.trigger.is_triggered() {
                    break;
                }
                select! {
                    _ = rx.recv() => self.clone().handle_event().await,
                    _ = ticker.tick() => self.clone().handle_event().await,
                    _ = banserver_ticker.tick() => self.clone().refresh_banserver_bans().await,
                    _ = banserver_consistency_retry_ticker.tick(), if self.should_retry_seed_server_snapshot_validation() => self.clone().refresh_banserver_bans().await,
                    _ = banserver_retry_ticker.tick(), if self.should_request_peer_snapshots() => self.clone().request_peer_snapshots_tick().await,
                    _ = self.shutdown_signal.listener.clone() => break,
                }
            }
            debug!("Connection manager event loop exiting");
        });
    }

    async fn handle_event(self: Arc<Self>) {
        debug!("Starting connection loop iteration");
        let peers = self.p2p_adaptor.active_peers();
        let peer_by_address: HashMap<SocketAddr, Peer> = peers.into_iter().map(|peer| (peer.net_address(), peer)).collect();

        self.handle_connection_requests(&peer_by_address).await;
        self.handle_outbound_connections(&peer_by_address).await;
        self.handle_inbound_connections(&peer_by_address).await;
    }

    pub async fn add_connection_request(&self, address: SocketAddr, is_permanent: bool) {
        // If the request already exists, it resets the attempts count and overrides the `is_permanent` setting.
        self.connection_requests.lock().await.insert(address, ConnectionRequest::new(is_permanent));
        self.force_next_iteration.send(()).unwrap(); // We force the next iteration of the connection loop.
    }

    pub async fn stop(&self) {
        self.shutdown_signal.trigger.trigger()
    }

    async fn handle_connection_requests(self: &Arc<Self>, peer_by_address: &HashMap<SocketAddr, Peer>) {
        let mut requests = self.connection_requests.lock().await;
        let mut new_requests = HashMap::with_capacity(requests.len());
        for (address, request) in requests.iter() {
            let address = *address;
            let request = request.clone();
            let is_connected = peer_by_address.contains_key(&address);
            if is_connected && !request.is_permanent {
                // The peer is connected and the request is not permanent - no need to keep the request
                continue;
            }

            if !is_connected && request.next_attempt <= SystemTime::now() {
                if self.is_banserver_banned_ip(address.ip()) {
                    debug!("Skipping connection request {} because it is blocked by banserver list", address);
                    new_requests.insert(
                        address,
                        ConnectionRequest {
                            next_attempt: SystemTime::now() + BANSERVER_BANNED_CONNECTION_RETRY_DELAY,
                            is_permanent: request.is_permanent,
                            attempts: request.attempts,
                        },
                    );
                    continue;
                }

                debug!("Connecting to peer request {}", address);
                match self.p2p_adaptor.connect_peer(address.to_string()).await {
                    Err(err) => {
                        debug!("Failed connecting to peer request: {}, {}", address, err);
                        if request.is_permanent {
                            const MAX_ACCOUNTABLE_ATTEMPTS: u32 = 4;
                            let retry_duration =
                                Duration::from_secs(30u64 * 2u64.pow(min(request.attempts, MAX_ACCOUNTABLE_ATTEMPTS)));
                            debug!("Will retry peer request {} in {}", address, DurationString::from(retry_duration));
                            new_requests.insert(
                                address,
                                ConnectionRequest {
                                    next_attempt: SystemTime::now() + retry_duration,
                                    attempts: request.attempts + 1,
                                    is_permanent: true,
                                },
                            );
                        }
                    }
                    Ok(_) if request.is_permanent => {
                        // Permanent requests are kept forever
                        new_requests.insert(address, ConnectionRequest::new(true));
                    }
                    Ok(_) => {}
                }
            } else {
                new_requests.insert(address, request);
            }
        }

        *requests = new_requests;
    }

    async fn handle_outbound_connections(self: &Arc<Self>, peer_by_address: &HashMap<SocketAddr, Peer>) {
        let active_outbound: HashSet<cryptix_addressmanager::NetAddress> =
            peer_by_address.values().filter(|peer| peer.is_outbound()).map(|peer| peer.net_address().into()).collect();
        if active_outbound.len() >= self.outbound_target {
            return;
        }

        let mut missing_connections = self.outbound_target - active_outbound.len();
        let mut addr_iter = self.address_manager.lock().iterate_prioritized_random_addresses(active_outbound);

        let mut progressing = true;
        let mut connecting = true;
        while connecting && missing_connections > 0 {
            if self.shutdown_signal.trigger.is_triggered() {
                return;
            }
            let mut addrs_to_connect = Vec::with_capacity(missing_connections);
            let mut jobs = Vec::with_capacity(missing_connections);
            for _ in 0..missing_connections {
                let Some(net_addr) = addr_iter.next() else {
                    connecting = false;
                    break;
                };
                if self.is_banserver_banned_ip(net_addr.ip.into()) {
                    debug!("Skipping outbound candidate {} due to banserver list", net_addr);
                    continue;
                }
                let socket_addr = SocketAddr::new(net_addr.ip.into(), net_addr.port).to_string();
                debug!("Connecting to {}", &socket_addr);
                addrs_to_connect.push(net_addr);
                jobs.push(self.p2p_adaptor.connect_peer(socket_addr.clone()));
            }

            if progressing && !jobs.is_empty() {
                // Log only if progress was made
                info!(
                    "Connection manager: has {}/{} outgoing P2P connections, trying to obtain {} additional connection(s)...",
                    self.outbound_target - missing_connections,
                    self.outbound_target,
                    jobs.len(),
                );
                progressing = false;
            } else {
                debug!(
                    "Connection manager: outgoing: {}/{} , connecting: {}, iterator: {}",
                    self.outbound_target - missing_connections,
                    self.outbound_target,
                    jobs.len(),
                    addr_iter.len(),
                );
            }

            for (res, net_addr) in (join_all(jobs).await).into_iter().zip(addrs_to_connect) {
                match res {
                    Ok(_) => {
                        self.address_manager.lock().mark_connection_success(net_addr);
                        missing_connections -= 1;
                        progressing = true;
                    }
                    Err(ConnectionError::ProtocolError(ProtocolError::PeerAlreadyExists(_))) => {
                        // We avoid marking the existing connection as connection failure
                        debug!("Failed connecting to {:?}, peer already exists", net_addr);
                    }
                    Err(err) => {
                        debug!("Failed connecting to {:?}, err: {}", net_addr, err);
                        self.address_manager.lock().mark_connection_failure(net_addr);
                    }
                }
            }
        }

        if missing_connections > 0 && !self.dns_seeders.is_empty() {
            if missing_connections > self.outbound_target / 2 {
                // If we are missing more than half of our target, query all in parallel.
                // This will always be the case on new node start-up and is the most resilient strategy in such a case.
                self.dns_seed_many(self.dns_seeders.len()).await;
            } else {
                // Try to obtain at least twice the number of missing connections
                self.dns_seed_with_address_target(2 * missing_connections).await;
            }
        }
    }

    async fn handle_inbound_connections(self: &Arc<Self>, peer_by_address: &HashMap<SocketAddr, Peer>) {
        let active_inbound = peer_by_address.values().filter(|peer| !peer.is_outbound()).collect_vec();
        let active_inbound_len = active_inbound.len();
        if self.inbound_limit >= active_inbound_len {
            return;
        }

        let mut futures = Vec::with_capacity(active_inbound_len - self.inbound_limit);
        for peer in active_inbound.choose_multiple(&mut thread_rng(), active_inbound_len - self.inbound_limit) {
            debug!("Disconnecting from {} because we're above the inbound limit", peer.net_address());
            futures.push(self.p2p_adaptor.terminate(peer.key()));
        }
        join_all(futures).await;
    }

    /// Queries DNS seeders in random order, one after the other, until obtaining `min_addresses_to_fetch` addresses
    async fn dns_seed_with_address_target(self: &Arc<Self>, min_addresses_to_fetch: usize) {
        let cmgr = self.clone();
        tokio::task::spawn_blocking(move || cmgr.dns_seed_with_address_target_blocking(min_addresses_to_fetch)).await.unwrap();
    }

    fn dns_seed_with_address_target_blocking(self: &Arc<Self>, mut min_addresses_to_fetch: usize) {
        let shuffled_dns_seeders = self.dns_seeders.choose_multiple(&mut thread_rng(), self.dns_seeders.len());
        for &seeder in shuffled_dns_seeders {
            // Query seeders sequentially until reaching the desired number of addresses
            let addrs_len = self.dns_seed_single(seeder);
            if addrs_len >= min_addresses_to_fetch {
                break;
            } else {
                min_addresses_to_fetch -= addrs_len;
            }
        }
    }

    /// Queries `num_seeders_to_query` random DNS seeders in parallel
    async fn dns_seed_many(self: &Arc<Self>, num_seeders_to_query: usize) -> usize {
        info!("Querying {} DNS seeders", num_seeders_to_query);
        let shuffled_dns_seeders = self.dns_seeders.choose_multiple(&mut thread_rng(), num_seeders_to_query);
        let jobs = shuffled_dns_seeders.map(|seeder| {
            let cmgr = self.clone();
            tokio::task::spawn_blocking(move || cmgr.dns_seed_single(seeder))
        });
        try_join_all(jobs).await.unwrap().into_iter().sum()
    }

    /// Query a single DNS seeder and add the obtained addresses to the address manager.
    ///
    /// DNS lookup is a blocking i/o operation so this function is assumed to be called
    /// from a blocking execution context.
    fn dns_seed_single(self: &Arc<Self>, seeder: &str) -> usize {
        info!("Querying DNS seeder {}", seeder);
        // Since the DNS lookup protocol doesn't come with a port, we must assume that the default port is used.
        let addrs = match (seeder, self.default_port).to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                warn!("Error connecting to DNS seeder {}: {}", seeder, e);
                return 0;
            }
        };

        let addrs_len = addrs.len();
        info!("Retrieved {} addresses from DNS seeder {}", addrs_len, seeder);
        let mut amgr_lock = self.address_manager.lock();
        for addr in addrs {
            amgr_lock.add_address(NetAddress::new(addr.ip().into(), addr.port()));
        }

        addrs_len
    }

    /// Bans the given IP and disconnects from all the peers with that IP.
    ///
    /// _GO-CRYPTIXD: BanByIP_
    pub async fn ban(&self, ip: IpAddr) {
        if self.ip_has_permanent_connection(ip).await {
            return;
        }
        for peer in self.p2p_adaptor.active_peers() {
            if peer.net_address().ip() == ip {
                self.p2p_adaptor.terminate(peer.key()).await;
            }
        }
        self.address_manager.lock().ban(ip.into());
    }

    /// Bans the given unified node ID and disconnects all active peers advertising this identity.
    pub async fn ban_unified_node_id(&self, node_id: [u8; 32]) {
        let now = Instant::now();
        let expires_at = now + LOCAL_UNIFIED_NODE_BAN_DURATION;
        {
            let mut local_bans = self.locally_banned_unified_node_ids.lock();
            local_bans.retain(|_, entry_expires_at| *entry_expires_at > now);
            local_bans.insert(node_id, expires_at);
        }
        self.disconnect_peers_by_node_id_list(vec![node_id]).await;
    }

    /// Returns whether the given address is banned.
    pub async fn is_banned(&self, address: &SocketAddr) -> bool {
        self.is_banserver_banned_ip(address.ip())
            || (!self.is_permanent(address).await && self.address_manager.lock().is_banned(address.ip().into()))
    }

    /// Returns whether the given address is a permanent request.
    pub async fn is_permanent(&self, address: &SocketAddr) -> bool {
        self.connection_requests.lock().await.contains_key(address)
    }

    /// Returns whether the given IP has some permanent request.
    pub async fn ip_has_permanent_connection(&self, ip: IpAddr) -> bool {
        self.connection_requests.lock().await.iter().any(|(address, request)| request.is_permanent && address.ip() == ip)
    }

    pub fn is_antifraud_runtime_enabled(&self) -> bool {
        self.anti_fraud_state.lock().runtime_enabled
    }

    fn is_banserver_banned_ip(&self, ip: IpAddr) -> bool {
        if !self.is_antifraud_runtime_enabled() {
            return false;
        }
        self.banserver_banned_ips.lock().contains(&ip)
    }

    pub fn is_banserver_banned_node_id(&self, node_id_raw: &[u8; 32]) -> bool {
        if !self.is_antifraud_runtime_enabled() {
            return false;
        }
        self.banserver_banned_strong_node_ids.lock().contains(node_id_raw)
    }

    pub fn is_unified_node_id_banned(&self, node_id_raw: &[u8; 32]) -> bool {
        let now = Instant::now();
        let mut local_bans = self.locally_banned_unified_node_ids.lock();
        local_bans.retain(|_, entry_expires_at| *entry_expires_at > now);
        if local_bans.contains_key(node_id_raw) {
            return true;
        }
        self.is_banserver_banned_node_id(node_id_raw)
    }

    pub fn is_banserver_banned_strong_node_id(&self, static_id_raw: &[u8; 32]) -> bool {
        self.is_banserver_banned_node_id(static_id_raw)
    }

    pub fn anti_fraud_hash_window(&self) -> [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN] {
        let state = self.anti_fraud_state.lock();
        if !state.runtime_enabled {
            return [ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN];
        }
        state.hash_window
    }

    pub fn anti_fraud_snapshot_envelope(&self) -> Option<AntiFraudSnapshotEnvelope> {
        let state = self.anti_fraud_state.lock();
        state.current_snapshot.clone().map(Into::into)
    }

    pub fn should_request_peer_snapshots(&self) -> bool {
        let state = self.anti_fraud_state.lock();
        if !state.runtime_enabled {
            return false;
        }
        !self.banserver_enabled || state.peer_fallback_required
    }

    pub fn should_retry_seed_server_snapshot_validation(&self) -> bool {
        let state = self.anti_fraud_state.lock();
        state.runtime_enabled && state.seed_server_retry_pending
    }

    pub fn anti_fraud_mode_for_peer_hashes(&self, peer_hashes: &[[u8; 32]]) -> AntiFraudMode {
        if !self.is_antifraud_runtime_enabled() {
            return AntiFraudMode::Full;
        }

        let local = self.anti_fraud_hash_window();
        if Self::is_hash_window_all_zero(&local) {
            // No local non-zero anchor yet => remain gated until overlap exists.
            return AntiFraudMode::Restricted;
        }

        if !Self::validate_hash_window(peer_hashes) {
            return AntiFraudMode::Restricted;
        }
        if Self::is_hash_window_all_zero(peer_hashes) {
            // Peer did not provide any non-zero anchor yet => remain gated.
            return AntiFraudMode::Restricted;
        }
        if Self::has_nonzero_hash_overlap(&local, peer_hashes) {
            AntiFraudMode::Full
        } else {
            AntiFraudMode::Restricted
        }
    }

    pub fn validate_hash_window(entries: &[[u8; 32]]) -> bool {
        if entries.len() != ANTI_FRAUD_HASH_WINDOW_LEN {
            return false;
        }
        let mut seen = HashSet::<[u8; 32]>::new();
        let mut seen_zero = false;
        for hash in entries {
            if *hash == ANTI_FRAUD_ZERO_HASH {
                seen_zero = true;
                continue;
            }
            if seen_zero {
                return false;
            }
            if !seen.insert(*hash) {
                return false;
            }
        }
        true
    }

    fn is_hash_window_all_zero(entries: &[[u8; 32]]) -> bool {
        entries.iter().all(|hash| *hash == ANTI_FRAUD_ZERO_HASH)
    }

    pub fn has_nonzero_hash_overlap(local: &[[u8; 32]], remote: &[[u8; 32]]) -> bool {
        local
            .iter()
            .filter(|hash| **hash != ANTI_FRAUD_ZERO_HASH)
            .any(|local_hash| remote.iter().any(|remote_hash| *remote_hash == *local_hash && *remote_hash != ANTI_FRAUD_ZERO_HASH))
    }

    pub fn ingest_peer_snapshot(
        &self,
        peer_key: PeerKey,
        envelope: AntiFraudSnapshotEnvelope,
    ) -> Result<IngestPeerSnapshotResult, String> {
        if !self.is_antifraud_runtime_enabled() {
            return Ok(IngestPeerSnapshotResult { applied: false, root_hash: ANTI_FRAUD_ZERO_HASH });
        }

        let snapshot = self.normalize_snapshot_envelope(envelope)?;
        let peer_root_hash = snapshot.root_hash;
        let peer_label = peer_key.to_string();
        let now = Instant::now();

        let mut state = self.anti_fraud_state.lock();
        state.peer_votes.insert(peer_label, PeerSnapshotVote { received_at: now, snapshot });
        state.peer_votes.retain(|_, vote| vote.received_at.elapsed() <= PEER_CANDIDATE_MAX_AGE);

        let Some(max_seq) = state.peer_votes.values().map(|vote| vote.snapshot.snapshot_seq).max() else {
            return Ok(IngestPeerSnapshotResult { applied: false, root_hash: peer_root_hash });
        };
        let candidates = state
            .peer_votes
            .values()
            .filter(|vote| vote.snapshot.snapshot_seq == max_seq)
            .map(|vote| vote.snapshot.clone())
            .collect_vec();
        if candidates.is_empty() {
            return Ok(IngestPeerSnapshotResult { applied: false, root_hash: peer_root_hash });
        }

        let mut counts = HashMap::<[u8; 32], usize>::new();
        for candidate in candidates.iter() {
            *counts.entry(candidate.root_hash).or_insert(0) += 1;
        }
        let (winner_hash, winner_votes) = counts.into_iter().max_by_key(|(_, count)| *count).expect("counts is non-empty");
        let strict_majority = winner_votes > (candidates.len() / 2);
        if !strict_majority {
            return Ok(IngestPeerSnapshotResult { applied: false, root_hash: peer_root_hash });
        }

        let winner = candidates.into_iter().find(|candidate| candidate.root_hash == winner_hash).expect("winner hash exists");
        if !winner.antifraud_enabled {
            drop(state);
            if let Err(err) = self.try_apply_snapshot(winner.clone(), "peer-majority-gate-disabled") {
                warn!("Failed to cache disabled peer-gate snapshot: {}", err);
            }
            self.disable_antifraud_runtime("peer snapshot majority gate is false");
            return Ok(IngestPeerSnapshotResult { applied: false, root_hash: peer_root_hash });
        }
        drop(state);
        let applied = self.try_apply_snapshot(winner, "peer-majority")?;
        Ok(IngestPeerSnapshotResult { applied, root_hash: peer_root_hash })
    }

    async fn request_peer_snapshots_tick(self: Arc<Self>) {
        // P2P request/response is handled by antifraud flows.
        // The retry tick keeps the event loop reactive while peer fallback is needed.
        let _ = self.force_next_iteration.send(());
    }

    fn log_antifraud_runtime_transition(was_enabled: bool, enabled: bool, reason: &str) {
        if was_enabled == enabled {
            return;
        }
        if enabled {
            warn!("AntiFraud runtime switched: OFF -> ON ({})", reason);
        } else {
            warn!("AntiFraud runtime switched: ON -> OFF ({})", reason);
        }
    }

    fn log_antifraud_runtime_state(&self, reason: &str) {
        let state = self.anti_fraud_state.lock();
        let snapshot_seq = state.current_snapshot.as_ref().map(|snapshot| snapshot.snapshot_seq).unwrap_or(0);
        info!(
            "AntiFraud runtime state: enabled={}, peer_fallback_required={}, seed_server_retry_pending={}, snapshot_seq={} ({})",
            state.runtime_enabled, state.peer_fallback_required, state.seed_server_retry_pending, snapshot_seq, reason
        );
    }

    fn set_antifraud_runtime_enabled_with_reason(&self, enabled: bool, reason: &str) {
        let was_enabled = {
            let mut state = self.anti_fraud_state.lock();
            let was_enabled = state.runtime_enabled;
            state.runtime_enabled = enabled;
            was_enabled
        };
        Self::log_antifraud_runtime_transition(was_enabled, enabled, reason);
        self.log_antifraud_runtime_state(reason);
    }

    fn disable_antifraud_runtime(&self, reason: &str) {
        let mut state = self.anti_fraud_state.lock();
        let had_snapshot = state.current_snapshot.is_some();
        let had_hashes = state.hash_window.iter().any(|hash| *hash != ANTI_FRAUD_ZERO_HASH);
        let was_enabled = state.runtime_enabled;
        state.runtime_enabled = false;
        state.hash_window = [ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN];
        state.peer_votes.clear();
        state.peer_fallback_required = false;
        state.seed_server_retry_pending = false;
        drop(state);

        let had_ips = !self.banserver_banned_ips.lock().is_empty();
        let had_node_ids = !self.banserver_banned_strong_node_ids.lock().is_empty();
        self.banserver_banned_ips.lock().clear();
        self.banserver_banned_strong_node_ids.lock().clear();

        Self::log_antifraud_runtime_transition(was_enabled, false, reason);
        if was_enabled || had_snapshot || had_hashes || had_ips || had_node_ids {
            info!("AntiFraud runtime disabled: {}. Cleared active anti-fraud enforcement state.", reason);
        }
        self.log_antifraud_runtime_state(reason);
    }

    fn ensure_peer_only_antifraud_runtime(&self, reason: &str) {
        let was_enabled = {
            let mut state = self.anti_fraud_state.lock();
            let was_enabled = state.runtime_enabled;
            if state.current_snapshot.as_ref().map(|snapshot| !snapshot.antifraud_enabled).unwrap_or(false) {
                // Honor the latest signed OFF gate and do not auto-reenable in peer-only mode.
                return;
            }
            let already_peer_only = state.runtime_enabled && state.peer_fallback_required && !state.seed_server_retry_pending;
            if already_peer_only {
                return;
            }
            state.runtime_enabled = true;
            state.peer_fallback_required = true;
            state.seed_server_retry_pending = false;
            was_enabled
        };
        Self::log_antifraud_runtime_transition(was_enabled, true, reason);
        self.log_antifraud_runtime_state(reason);
    }

    fn apply_seed_server_failure_state(state: &mut AntiFraudState) -> SeedServerFailureAction {
        if !state.runtime_enabled {
            state.runtime_enabled = true;
        }

        if state.peer_fallback_required {
            state.seed_server_retry_pending = false;
            return SeedServerFailureAction::KeepPeerFallback;
        }

        if state.seed_server_retry_pending {
            state.seed_server_retry_pending = false;
            state.peer_fallback_required = true;
            return SeedServerFailureAction::EnablePeerFallback;
        }

        state.seed_server_retry_pending = true;
        SeedServerFailureAction::RetrySoon
    }

    fn handle_seed_server_refresh_failure(&self, reason: &str) {
        let (action, was_enabled, enabled) = {
            let mut state = self.anti_fraud_state.lock();
            let was_enabled = state.runtime_enabled;
            let action = Self::apply_seed_server_failure_state(&mut state);
            (action, was_enabled, state.runtime_enabled)
        };
        Self::log_antifraud_runtime_transition(was_enabled, enabled, "seed-server refresh failure fallback logic");

        match action {
            SeedServerFailureAction::KeepPeerFallback => {
                warn!("Banserver refresh failed while peer fallback is active: {}. Keeping peer snapshot fallback enabled.", reason)
            }
            SeedServerFailureAction::EnablePeerFallback => {
                warn!("Banserver refresh failed again: {}. Enabling peer snapshot fallback mode.", reason)
            }
            SeedServerFailureAction::RetrySoon => warn!(
                "Banserver refresh failed: {}. Retrying in {}s before enabling peer fallback.",
                reason,
                BANSERVER_CONSISTENCY_RETRY_INTERVAL.as_secs()
            ),
        }
        self.log_antifraud_runtime_state(reason);
    }

    async fn refresh_banserver_bans(self: Arc<Self>) {
        if !self.banserver_enabled {
            self.ensure_peer_only_antifraud_runtime("banserver disabled by configuration; peer snapshot fallback only");
            return;
        }

        let fetched = match self.fetch_banserver_payload().await {
            BanserverFetchOutcome::Enabled(payload) => payload,
            BanserverFetchOutcome::DisabledByGate(payload) => {
                if let Err(err) = self.try_apply_snapshot(payload.snapshot, "seed-server-gate-disabled") {
                    warn!("Failed to cache disabled anti-fraud gate snapshot: {}", err);
                }
                self.disable_antifraud_runtime("snapshot endpoint antifraud_enabled flag is false");
                return;
            }
            BanserverFetchOutcome::Unavailable => {
                self.handle_seed_server_refresh_failure("no endpoint provided a usable antifraud snapshot");
                return;
            }
        };
        if !fetched.enabled {
            self.disable_antifraud_runtime("snapshot endpoint antifraud_enabled flag is false");
            return;
        }
        self.set_antifraud_runtime_enabled_with_reason(true, "signed snapshot gate is enabled");

        match self.try_apply_snapshot(fetched.snapshot, "seed-server") {
            Ok(applied) => {
                {
                    let mut state = self.anti_fraud_state.lock();
                    state.peer_fallback_required = false;
                    state.seed_server_retry_pending = false;
                }
                if applied {
                    let banned = self.banserver_banned_ips.lock().iter().copied().collect_vec();
                    if !banned.is_empty() {
                        self.disconnect_peers_by_ip_list(banned).await;
                    }
                    let banned_node_ids = self.banserver_banned_strong_node_ids.lock().iter().copied().collect_vec();
                    if !banned_node_ids.is_empty() {
                        self.disconnect_peers_by_node_id_list(banned_node_ids).await;
                    }
                }
            }
            Err(err) => {
                self.handle_seed_server_refresh_failure(&format!("snapshot rejected: {err}"));
                return;
            }
        }

        // Ensure the connection loop reacts quickly to newly updated server bans.
        let _ = self.force_next_iteration.send(());
    }

    async fn fetch_banserver_payload(&self) -> BanserverFetchOutcome {
        let primary_result = self.fetch_banserver_payload_from_endpoint("primary", self.banserver_primary_url.trim()).await;
        let secondary_result = self.fetch_banserver_payload_from_endpoint("secondary", self.banserver_secondary_url.trim()).await;

        let mut endpoint_payloads = Vec::<EndpointBanserverPayload>::with_capacity(2);
        let mut endpoint_errors = Vec::<String>::new();

        match primary_result {
            Ok(payload) => endpoint_payloads.push(payload),
            Err(err) => endpoint_errors.push(format!("primary endpoint unavailable: {err}")),
        }
        match secondary_result {
            Ok(payload) => endpoint_payloads.push(payload),
            Err(err) => endpoint_errors.push(format!("secondary endpoint unavailable: {err}")),
        }

        if endpoint_payloads.iter().any(|entry| !entry.enabled) {
            let mut states = endpoint_payloads
                .iter()
                .map(|entry| format!("{} {}={}", entry.endpoint_name, entry.source_url, entry.enabled))
                .collect_vec();
            states.extend(endpoint_errors.iter().cloned());
            info!("AntiFraud runtime gate from snapshots: {} -> disabled", states.join("; "));
            let mut disabled_payloads = endpoint_payloads
                .iter()
                .filter(|entry| !entry.enabled)
                .filter_map(|entry| entry.payload.as_ref().map(|payload| (entry.endpoint_name, payload.clone())))
                .collect_vec();
            if disabled_payloads.is_empty() {
                return BanserverFetchOutcome::Unavailable;
            }
            let mut selected_index = 0usize;
            for i in 1..disabled_payloads.len() {
                let candidate_seq = disabled_payloads[i].1.snapshot.snapshot_seq;
                let selected_seq = disabled_payloads[selected_index].1.snapshot.snapshot_seq;
                if candidate_seq > selected_seq {
                    selected_index = i;
                    continue;
                }
                if candidate_seq == selected_seq
                    && disabled_payloads[selected_index].0 != "primary"
                    && disabled_payloads[i].0 == "primary"
                {
                    selected_index = i;
                }
            }
            return BanserverFetchOutcome::DisabledByGate(disabled_payloads.swap_remove(selected_index).1);
        }

        let mut enabled_payloads = endpoint_payloads
            .into_iter()
            .filter_map(|entry| entry.payload.map(|payload| (entry.endpoint_name, entry.source_url, payload)))
            .collect_vec();

        if enabled_payloads.is_empty() {
            if endpoint_errors.is_empty() {
                warn!("AntiFraud runtime gate from snapshots: no endpoint provided usable antifraud payload -> unavailable");
            } else {
                warn!("AntiFraud runtime gate from snapshots: {} -> unavailable", endpoint_errors.join("; "));
            }
            return BanserverFetchOutcome::Unavailable;
        }

        if !endpoint_errors.is_empty() {
            warn!(
                "AntiFraud snapshot fetch degraded: {}. Continuing because at least one endpoint is enabled and valid.",
                endpoint_errors.join("; ")
            );
        }

        let mut selected_index = 0usize;
        for i in 1..enabled_payloads.len() {
            let candidate_seq = enabled_payloads[i].2.snapshot.snapshot_seq;
            let selected_seq = enabled_payloads[selected_index].2.snapshot.snapshot_seq;
            if candidate_seq > selected_seq {
                selected_index = i;
                continue;
            }
            if candidate_seq == selected_seq && enabled_payloads[selected_index].0 != "primary" && enabled_payloads[i].0 == "primary" {
                selected_index = i;
            }
        }
        let selected = enabled_payloads.swap_remove(selected_index);
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0);

        for (endpoint_name, endpoint_url, payload) in enabled_payloads.iter() {
            match Self::evaluate_enabled_snapshot_pair(selected.0, &selected.2.snapshot, endpoint_name, &payload.snapshot, now_ms) {
                Ok(None) => {}
                Ok(Some((newer_label, newer_seq, older_label, older_seq, newer_age_ms))) => {
                    warn!(
                        "AntiFraud snapshot temporary replication skew tolerated: newer {} seq={}, older {} seq={}, newer_age_ms={} (<= {})",
                        newer_label,
                        newer_seq,
                        older_label,
                        older_seq,
                        newer_age_ms,
                        BANSERVER_REPLICATION_LAG_TOLERANCE.as_millis()
                    );
                }
                Err(reason) => {
                    warn!(
                        "AntiFraud snapshot mismatch: rejecting update (selected {} {} seq={} hash={}, {} {} seq={} hash={}): {}",
                        selected.0,
                        selected.1,
                        selected.2.snapshot.snapshot_seq,
                        Self::encode_hex(&selected.2.snapshot.root_hash),
                        endpoint_name,
                        endpoint_url,
                        payload.snapshot.snapshot_seq,
                        Self::encode_hex(&payload.snapshot.root_hash),
                        reason
                    );
                    return BanserverFetchOutcome::Unavailable;
                }
            }
        }

        BanserverFetchOutcome::Enabled(selected.2)
    }

    fn evaluate_enabled_snapshot_pair(
        selected_label: &str,
        selected_snapshot: &AntiFraudSnapshot,
        peer_label: &str,
        peer_snapshot: &AntiFraudSnapshot,
        now_ms: u64,
    ) -> Result<Option<(String, u64, String, u64, u64)>, String> {
        if peer_snapshot.snapshot_seq == selected_snapshot.snapshot_seq {
            if peer_snapshot.root_hash != selected_snapshot.root_hash {
                return Err("enabled endpoints disagree on identical snapshot_seq".to_string());
            }
            return Ok(None);
        }

        let (newer_label, newer_snapshot, older_label, older_snapshot) = if peer_snapshot.snapshot_seq > selected_snapshot.snapshot_seq
        {
            (peer_label, peer_snapshot, selected_label, selected_snapshot)
        } else {
            (selected_label, selected_snapshot, peer_label, peer_snapshot)
        };

        let newer_seq = newer_snapshot.snapshot_seq;
        let older_seq = older_snapshot.snapshot_seq;
        let seq_gap = newer_seq - older_seq;
        let newer_age_ms = now_ms.saturating_sub(newer_snapshot.generated_at_ms);
        let tolerance_ms = BANSERVER_REPLICATION_LAG_TOLERANCE.as_millis() as u64;
        if seq_gap == 1 && newer_age_ms <= tolerance_ms {
            return Ok(Some((newer_label.to_owned(), newer_seq, older_label.to_owned(), older_seq, newer_age_ms)));
        }

        Err(format!(
            "enabled endpoints diverged beyond tolerance (seq_gap={} newer_age_ms={} tolerance_ms={})",
            seq_gap, newer_age_ms, tolerance_ms
        ))
    }

    async fn fetch_banserver_payload_from_endpoint(
        &self,
        endpoint_name: &'static str,
        endpoint_url: &str,
    ) -> Result<EndpointBanserverPayload, String> {
        let endpoint_url = endpoint_url.trim();
        let primary_payload = match self.fetch_banserver_json(endpoint_url).await {
            Ok(payload) => payload,
            Err(primary_err) => {
                if let Some(fallback_url) = Self::http_fallback_url(endpoint_url) {
                    match self.fetch_banserver_json(&fallback_url).await {
                        Ok(payload) => {
                            warn!(
                                "Banserver {} HTTPS fetch failed for {} ({}), HTTP fallback {} succeeded",
                                endpoint_name, endpoint_url, primary_err, fallback_url
                            );
                            return Self::parse_endpoint_payload(endpoint_name, &fallback_url, payload);
                        }
                        Err(fallback_err) => {
                            return Err(format!(
                                "{} endpoint fetch failed: primary {} error {}; http fallback error {}",
                                endpoint_name, endpoint_url, primary_err, fallback_err
                            ));
                        }
                    }
                }
                return Err(format!("{} endpoint fetch failed for {}: {}", endpoint_name, endpoint_url, primary_err));
            }
        };

        Self::parse_endpoint_payload(endpoint_name, endpoint_url, primary_payload)
    }

    fn parse_endpoint_payload(
        endpoint_name: &'static str,
        endpoint_url: &str,
        payload: JsonValue,
    ) -> Result<EndpointBanserverPayload, String> {
        let parsed = Self::parse_banserver_payload(payload)
            .map_err(|err| format!("{} endpoint payload parse failed for {}: {}", endpoint_name, endpoint_url, err))?;

        if !parsed.enabled {
            return Ok(EndpointBanserverPayload {
                endpoint_name,
                source_url: endpoint_url.to_owned(),
                enabled: false,
                payload: Some(parsed),
            });
        }
        Ok(EndpointBanserverPayload { endpoint_name, source_url: endpoint_url.to_owned(), enabled: true, payload: Some(parsed) })
    }

    async fn fetch_banserver_json(&self, url: &str) -> Result<JsonValue, String> {
        let parsed_url = ParsedUrl::parse(url).map_err(|err| format!("invalid URL `{url}`: {err}"))?;
        match parsed_url.scheme() {
            "https" | "http" => {}
            scheme => return Err(format!("unsupported URL scheme `{scheme}` (only http/https allowed)")),
        }

        let client = HttpClient::builder()
            // Explicitly allow self-signed/invalid TLS chains to maximize compatibility.
            .danger_accept_invalid_certs(true)
            // Explicitly disable hostname verification as requested for legacy endpoint compatibility.
            .danger_accept_invalid_hostnames(true)
            .redirect(RedirectPolicy::limited(2))
            .timeout(BANSERVER_FETCH_TIMEOUT)
            .build()
            .map_err(|err| format!("failed building HTTP client: {err}"))?;

        let response = client.get(parsed_url).send().await.map_err(|err| format!("request error: {err}"))?;

        if !response.status().is_success() {
            return Err(format!("http status {}", response.status()));
        }

        if let Some(content_length) = response.content_length() {
            if content_length > BANSERVER_MAX_PAYLOAD_BYTES as u64 {
                return Err(format!(
                    "payload too large by content-length: {} bytes (max {})",
                    content_length, BANSERVER_MAX_PAYLOAD_BYTES
                ));
            }
        }

        let body = response.bytes().await.map_err(|err| format!("failed reading response body: {err}"))?;
        if body.len() > BANSERVER_MAX_PAYLOAD_BYTES {
            return Err(format!("payload too large after download: {} bytes (max {})", body.len(), BANSERVER_MAX_PAYLOAD_BYTES));
        }

        serde_json::from_slice::<JsonValue>(&body).map_err(|err| format!("invalid json payload: {err}"))
    }

    fn http_fallback_url(url: &str) -> Option<String> {
        let mut parsed = ParsedUrl::parse(url).ok()?;
        if parsed.scheme() != "https" {
            return None;
        }

        if parsed.port() == Some(443) {
            let _ = parsed.set_port(Some(80));
        }
        parsed.set_scheme("http").ok()?;
        Some(parsed.to_string())
    }

    fn parse_banserver_payload(payload: JsonValue) -> Result<BanserverPayload, String> {
        let root = payload.get("data").unwrap_or(&payload);
        let antifraud_enabled = Self::read_antifraud_enabled(&payload)?;
        let schema_version = Self::read_u64(root, &["schema_version", "schemaVersion"]).ok_or("missing schema_version")? as u8;
        let network = Self::read_network(root).ok_or("missing network")?;
        let snapshot_seq = Self::read_u64(root, &["snapshot_seq", "snapshotSeq"]).ok_or("missing snapshot_seq")?;
        let generated_at_ms = Self::read_u64(root, &["generated_at_ms", "generatedAtMs"]).ok_or("missing generated_at_ms")?;
        let signing_key_id = Self::read_u64(root, &["signing_key_id", "signingKeyId"]).ok_or("missing signing_key_id")? as u8;
        let signature_hex = Self::read_str(root, &["signature"]).ok_or("missing signature")?;
        if signature_hex.len() != BANSERVER_SIGNATURE_HEX_LEN {
            return Err("signature must be 64-byte hex".to_string());
        }
        let signature = Self::decode_hex(signature_hex).ok_or("invalid signature hex")?;

        let ip_values = root.get("banned_ips").and_then(JsonValue::as_array).ok_or("missing banned_ips array")?;
        let node_id_values = root.get("banned_node_ids").and_then(JsonValue::as_array).ok_or("missing banned_node_ids array")?;
        let ip_count = Self::read_u64(root, &["banned_ips_count"]).ok_or("missing banned_ips_count")?;
        if ip_count > BANSERVER_MAX_IPS as u64 {
            return Err(format!("banned_ips_count exceeds max {}", BANSERVER_MAX_IPS));
        }
        if ip_count != ip_values.len() as u64 {
            return Err("banned_ips_count mismatch".to_string());
        }
        let node_count = Self::read_u64(root, &["banned_node_ids_count"]).ok_or("missing banned_node_ids_count")?;
        if node_count > BANSERVER_MAX_NODE_IDS as u64 {
            return Err(format!("banned_node_ids_count exceeds max {}", BANSERVER_MAX_NODE_IDS));
        }
        if node_count != node_id_values.len() as u64 {
            return Err("banned_node_ids_count mismatch".to_string());
        }
        if ip_values.len() > BANSERVER_MAX_IPS {
            return Err(format!("banned_ips_count exceeds max {}", BANSERVER_MAX_IPS));
        }
        if node_id_values.len() > BANSERVER_MAX_NODE_IDS {
            return Err(format!("banned_node_ids_count exceeds max {}", BANSERVER_MAX_NODE_IDS));
        }

        let mut banned_ips = Vec::with_capacity(ip_values.len());
        for value in ip_values {
            let Some(raw_ip) = value.as_str() else { continue };
            if let Some(entry) = Self::parse_ip_string_to_entry(raw_ip) {
                banned_ips.push(entry);
            }
        }
        let mut banned_node_ids = Vec::with_capacity(node_id_values.len());
        for value in node_id_values {
            let Some(raw_node_id) = value.as_str() else { continue };
            if let Some(node_id) = Self::parse_node_id_hex(raw_node_id) {
                banned_node_ids.push(node_id.to_vec());
            }
        }

        let envelope = AntiFraudSnapshotEnvelope {
            schema_version,
            network,
            snapshot_seq,
            generated_at_ms,
            signing_key_id,
            banned_ips,
            banned_node_ids,
            signature,
            antifraud_enabled,
        };

        let snapshot = Self::normalize_snapshot_static(envelope, AntiFraudNetwork::from_u8(network).ok_or("invalid network enum")?)?;
        Ok(BanserverPayload { enabled: antifraud_enabled, snapshot })
    }

    fn read_antifraud_enabled(payload: &JsonValue) -> Result<bool, String> {
        let root = payload.get("data").unwrap_or(payload);
        let value = root
            .get("antifraud_enabled")
            .or_else(|| root.get("antifraudEnabled"))
            .or_else(|| payload.get("antifraud_enabled"))
            .or_else(|| payload.get("antifraudEnabled"))
            .ok_or("missing antifraud_enabled")?;
        value.as_bool().ok_or("antifraud_enabled must be strict boolean true/false".to_string())
    }

    fn read_str<'a>(value: &'a JsonValue, keys: &[&str]) -> Option<&'a str> {
        keys.iter().find_map(|key| value.get(*key).and_then(JsonValue::as_str)).map(str::trim).filter(|s| !s.is_empty())
    }

    fn read_u64(value: &JsonValue, keys: &[&str]) -> Option<u64> {
        keys.iter()
            .find_map(|key| value.get(*key))
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|raw| raw.trim().parse::<u64>().ok())))
    }

    fn read_network(value: &JsonValue) -> Option<u8> {
        let network_value = value.get("network")?;
        if let Some(raw) = network_value.as_u64() {
            return u8::try_from(raw).ok();
        }
        let raw = network_value.as_str()?.trim().to_ascii_lowercase();
        if raw == "mainnet" || raw == "cryptix-mainnet" {
            return Some(AntiFraudNetwork::Mainnet as u8);
        }
        if raw == "testnet" || raw == "cryptix-testnet" || raw.starts_with("testnet-") || raw.starts_with("cryptix-testnet-") {
            return Some(AntiFraudNetwork::Testnet as u8);
        }
        if raw == "devnet" || raw == "cryptix-devnet" {
            return Some(AntiFraudNetwork::Devnet as u8);
        }
        if raw == "simnet" || raw == "cryptix-simnet" {
            return Some(AntiFraudNetwork::Simnet as u8);
        }
        None
    }

    fn normalize_snapshot_envelope(&self, envelope: AntiFraudSnapshotEnvelope) -> Result<AntiFraudSnapshot, String> {
        Self::normalize_snapshot_static(envelope, self.anti_fraud_network)
    }

    fn normalize_snapshot_static(
        envelope: AntiFraudSnapshotEnvelope,
        expected_network: AntiFraudNetwork,
    ) -> Result<AntiFraudSnapshot, String> {
        if envelope.schema_version != ANTI_FRAUD_SCHEMA_VERSION {
            return Err(format!("unsupported schema_version {} (expected {})", envelope.schema_version, ANTI_FRAUD_SCHEMA_VERSION));
        }
        if envelope.banned_ips.len() > BANSERVER_MAX_IPS {
            return Err(format!("banned_ips_count exceeds max {}", BANSERVER_MAX_IPS));
        }
        if envelope.banned_node_ids.len() > BANSERVER_MAX_NODE_IDS {
            return Err(format!("banned_node_ids_count exceeds max {}", BANSERVER_MAX_NODE_IDS));
        }

        let network = AntiFraudNetwork::from_u8(envelope.network).ok_or("invalid network enum")?;
        if network != expected_network {
            return Err("snapshot network mismatch".to_string());
        }

        if envelope.signature.len() != 64 {
            return Err("signature must be exactly 64 bytes".to_string());
        }
        let signature: [u8; 64] = envelope.signature.as_slice().try_into().map_err(|_| "invalid signature length".to_string())?;

        let mut ip_entries = envelope
            .banned_ips
            .into_iter()
            .filter_map(|entry| Self::normalize_ip_entry(&entry))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect_vec();
        ip_entries.sort();

        let mut node_entries = envelope
            .banned_node_ids
            .into_iter()
            .filter_map(|entry| entry.as_slice().try_into().ok())
            .collect::<HashSet<[u8; 32]>>()
            .into_iter()
            .collect_vec();
        node_entries.sort();

        let canonical_payload = Self::build_canonical_payload(
            envelope.schema_version,
            network as u8,
            envelope.snapshot_seq,
            envelope.generated_at_ms,
            envelope.signing_key_id,
            envelope.antifraud_enabled,
            &ip_entries,
            &node_entries,
        )?;
        let root_hash = *blake3::hash(&canonical_payload).as_bytes();
        if !Self::verify_snapshot_signature(network, envelope.signing_key_id, &root_hash, &signature) {
            return Err("invalid snapshot signature".to_string());
        }

        Ok(AntiFraudSnapshot {
            schema_version: envelope.schema_version,
            network,
            snapshot_seq: envelope.snapshot_seq,
            generated_at_ms: envelope.generated_at_ms,
            signing_key_id: envelope.signing_key_id,
            antifraud_enabled: envelope.antifraud_enabled,
            banned_ip_entries: ip_entries,
            banned_node_id_entries: node_entries,
            signature,
            root_hash,
        })
    }

    fn verify_snapshot_signature(network: AntiFraudNetwork, signing_key_id: u8, root_hash: &[u8; 32], signature: &[u8; 64]) -> bool {
        let Some(pubkey_bytes) = Self::pinned_pubkey_for(network, signing_key_id) else {
            return false;
        };
        let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey_bytes) else {
            return false;
        };
        let Ok(sig) = SchnorrSignature::from_slice(signature) else {
            return false;
        };
        let Ok(msg) = SecpMessage::from_digest_slice(root_hash) else {
            return false;
        };
        sig.verify(&msg, &pubkey).is_ok()
    }

    fn pinned_pubkey_for(_network: AntiFraudNetwork, signing_key_id: u8) -> Option<[u8; 32]> {
        match signing_key_id {
            0 => Self::decode_hex_32(ANTI_FRAUD_PUBKEY_CURRENT_HEX),
            1 => Self::decode_hex_32(ANTI_FRAUD_PUBKEY_NEXT_HEX),
            _ => None,
        }
    }

    fn build_canonical_payload(
        schema_version: u8,
        network: u8,
        snapshot_seq: u64,
        generated_at_ms: u64,
        signing_key_id: u8,
        antifraud_enabled: bool,
        banned_ip_entries: &[Vec<u8>],
        banned_node_id_entries: &[[u8; 32]],
    ) -> Result<Vec<u8>, String> {
        if banned_ip_entries.len() > BANSERVER_MAX_IPS || banned_node_id_entries.len() > BANSERVER_MAX_NODE_IDS {
            return Err("entry count exceeds configured maxima".to_string());
        }

        let mut payload = Vec::with_capacity(ANTI_FRAUD_DOMAIN_SEP.len() + 64);
        payload.extend_from_slice(ANTI_FRAUD_DOMAIN_SEP);
        payload.push(schema_version);
        payload.push(network);
        payload.extend_from_slice(&snapshot_seq.to_be_bytes());
        payload.extend_from_slice(&generated_at_ms.to_be_bytes());
        payload.push(signing_key_id);
        payload.push(if antifraud_enabled { 1 } else { 0 });
        payload.extend_from_slice(&(banned_ip_entries.len() as u32).to_be_bytes());
        for entry in banned_ip_entries {
            payload.extend_from_slice(entry);
        }
        payload.extend_from_slice(&(banned_node_id_entries.len() as u32).to_be_bytes());
        for entry in banned_node_id_entries {
            payload.extend_from_slice(entry);
        }
        Ok(payload)
    }

    fn normalize_ip_entry(entry: &[u8]) -> Option<Vec<u8>> {
        if entry.is_empty() {
            return None;
        }
        match entry[0] {
            4 if entry.len() == 5 => {
                let ip = std::net::Ipv4Addr::new(entry[1], entry[2], entry[3], entry[4]);
                let mut out = Vec::with_capacity(5);
                out.push(4);
                out.extend_from_slice(&ip.octets());
                Some(out)
            }
            6 if entry.len() == 17 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&entry[1..17]);
                let ip = std::net::Ipv6Addr::from(octets);
                let mut out = Vec::with_capacity(17);
                out.push(6);
                out.extend_from_slice(&ip.octets());
                Some(out)
            }
            _ => None,
        }
    }

    fn parse_ip_string_to_entry(raw: &str) -> Option<Vec<u8>> {
        let candidate = raw.trim();
        if candidate.is_empty() || candidate.len() > BANSERVER_MAX_IP_ENTRY_LEN {
            return None;
        }
        let ip = candidate.parse::<IpAddr>().ok()?;
        Some(match ip {
            IpAddr::V4(v4) => {
                let mut out = Vec::with_capacity(5);
                out.push(4);
                out.extend_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => {
                let mut out = Vec::with_capacity(17);
                out.push(6);
                out.extend_from_slice(&v6.octets());
                out
            }
        })
    }

    fn parse_node_id_hex(raw: &str) -> Option<[u8; 32]> {
        let candidate = raw.trim();
        if candidate.len() != BANSERVER_NODE_ID_HEX_LEN {
            return None;
        }

        let bytes = candidate.as_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            let high = Self::hex_nibble(bytes[i * 2])?;
            let low = Self::hex_nibble(bytes[i * 2 + 1])?;
            out[i] = (high << 4) | low;
        }
        Some(out)
    }

    fn decode_hex(raw: &str) -> Option<Vec<u8>> {
        let trimmed = raw.trim();
        if trimmed.len() % 2 != 0 {
            return None;
        }
        let bytes = trimmed.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for i in 0..(bytes.len() / 2) {
            let high = Self::hex_nibble(bytes[i * 2])?;
            let low = Self::hex_nibble(bytes[i * 2 + 1])?;
            out.push((high << 4) | low);
        }
        Some(out)
    }

    fn decode_hex_32(raw: &str) -> Option<[u8; 32]> {
        let bytes = Self::decode_hex(raw)?;
        bytes.as_slice().try_into().ok()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    pub fn encode_node_id_hex(node_id: &[u8; 32]) -> String {
        Self::encode_hex(node_id)
    }

    fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn try_apply_snapshot(&self, snapshot: AntiFraudSnapshot, source: &str) -> Result<bool, String> {
        let mut state = self.anti_fraud_state.lock();
        if let Some(current) = state.current_snapshot.as_ref() {
            if snapshot.snapshot_seq < current.snapshot_seq {
                return Err("received older snapshot_seq".to_string());
            }
            if snapshot.snapshot_seq == current.snapshot_seq {
                if snapshot.root_hash != current.root_hash {
                    return Err("same snapshot_seq with different root_hash".to_string());
                }
                return Ok(false);
            }
        }

        let previous_snapshot = state.current_snapshot.clone();
        let old_ips = self.banserver_banned_ips.lock().clone();
        let old_nodes = self.banserver_banned_strong_node_ids.lock().clone();
        let new_ips = snapshot
            .banned_ip_entries
            .iter()
            .filter_map(|entry| match entry.first().copied() {
                Some(4) if entry.len() == 5 => Some(IpAddr::V4(std::net::Ipv4Addr::new(entry[1], entry[2], entry[3], entry[4]))),
                Some(6) if entry.len() == 17 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&entry[1..17]);
                    Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                }
                _ => None,
            })
            .collect::<HashSet<_>>();
        let new_nodes = snapshot.banned_node_id_entries.iter().copied().collect::<HashSet<_>>();
        *self.banserver_banned_ips.lock() = new_ips.clone();
        *self.banserver_banned_strong_node_ids.lock() = new_nodes.clone();
        state.hash_window = Self::advance_hash_window(state.hash_window, snapshot.root_hash);
        state.current_snapshot = Some(snapshot.clone());
        drop(state);

        let _ = self.persist_snapshots(previous_snapshot.as_ref(), Some(&snapshot));
        let added_ips = new_ips.difference(&old_ips).count();
        let removed_ips = old_ips.difference(&new_ips).count();
        let added_nodes = new_nodes.difference(&old_nodes).count();
        let removed_nodes = old_nodes.difference(&new_nodes).count();
        info!(
            "AntiFraud snapshot applied from {}: seq={}, +{} IPs, -{} IPs, +{} node IDs, -{} node IDs (totals: {} IPs, {} node IDs)",
            source,
            snapshot.snapshot_seq,
            added_ips,
            removed_ips,
            added_nodes,
            removed_nodes,
            new_ips.len(),
            new_nodes.len()
        );
        Ok(true)
    }

    fn advance_hash_window(
        current: [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN],
        new_hash: [u8; 32],
    ) -> [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN] {
        if new_hash == ANTI_FRAUD_ZERO_HASH || current[0] == new_hash {
            return current;
        }
        let mut ordered = vec![new_hash];
        for hash in current {
            if hash == ANTI_FRAUD_ZERO_HASH || ordered.iter().any(|existing| *existing == hash) {
                continue;
            }
            ordered.push(hash);
            if ordered.len() == ANTI_FRAUD_HASH_WINDOW_LEN {
                break;
            }
        }
        while ordered.len() < ANTI_FRAUD_HASH_WINDOW_LEN {
            ordered.push(ANTI_FRAUD_ZERO_HASH);
        }
        [ordered[0], ordered[1], ordered[2]]
    }

    pub fn advance_peer_hash_window(
        current: [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN],
        new_hash: [u8; 32],
    ) -> [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN] {
        Self::advance_hash_window(current, new_hash)
    }

    fn anti_fraud_current_path(&self) -> Option<PathBuf> {
        self.anti_fraud_persist_dir.as_ref().map(|dir| dir.join(ANTI_FRAUD_CURRENT_FILE))
    }

    fn anti_fraud_previous_path(&self) -> Option<PathBuf> {
        self.anti_fraud_persist_dir.as_ref().map(|dir| dir.join(ANTI_FRAUD_PREVIOUS_FILE))
    }

    fn try_load_persisted_snapshot(&self) {
        let Some(current_path) = self.anti_fraud_current_path() else { return };
        let previous_path = self.anti_fraud_previous_path();
        let mut loaded = None;
        if let Some(snapshot) = self.load_snapshot_from_disk(&current_path) {
            loaded = Some(snapshot);
        } else if let Some(previous_path) = previous_path.as_ref() {
            loaded = self.load_snapshot_from_disk(previous_path);
        }
        if let Some(snapshot) = loaded {
            let _ = self.try_apply_snapshot(snapshot, "persisted");
        }
    }

    fn load_snapshot_from_disk(&self, path: &Path) -> Option<AntiFraudSnapshot> {
        let bytes = fs::read(path).ok()?;
        let parsed = match serde_json::from_slice::<PersistedSnapshotV1>(&bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!("anti-fraud snapshot {} is corrupted: {}", path.display(), err);
                self.quarantine_file(path);
                return None;
            }
        };

        let banned_ips = match parsed
            .banned_ips
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                Self::decode_hex(raw).ok_or_else(|| format!("invalid banned_ips[{index}] hex entry"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()
        {
            Ok(entries) => entries,
            Err(err) => {
                warn!("anti-fraud snapshot {} is invalid: {}", path.display(), err);
                self.quarantine_file(path);
                return None;
            }
        };
        let banned_node_ids = match parsed
            .banned_node_ids
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                Self::decode_hex(raw).ok_or_else(|| format!("invalid banned_node_ids[{index}] hex entry"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()
        {
            Ok(entries) => entries,
            Err(err) => {
                warn!("anti-fraud snapshot {} is invalid: {}", path.display(), err);
                self.quarantine_file(path);
                return None;
            }
        };
        let signature = match Self::decode_hex(&parsed.signature) {
            Some(signature) => signature,
            None => {
                warn!("anti-fraud snapshot {} is invalid: invalid signature hex entry", path.display());
                self.quarantine_file(path);
                return None;
            }
        };
        let envelope = AntiFraudSnapshotEnvelope {
            schema_version: parsed.schema_version,
            network: parsed.network,
            snapshot_seq: parsed.snapshot_seq,
            generated_at_ms: parsed.generated_at_ms,
            signing_key_id: parsed.signing_key_id,
            antifraud_enabled: parsed.antifraud_enabled,
            banned_ips,
            banned_node_ids,
            signature,
        };
        match self.normalize_snapshot_envelope(envelope) {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                warn!("anti-fraud snapshot {} is invalid: {}", path.display(), err);
                self.quarantine_file(path);
                None
            }
        }
    }

    fn persist_snapshots(&self, previous: Option<&AntiFraudSnapshot>, current: Option<&AntiFraudSnapshot>) -> Result<(), String> {
        let Some(current_path) = self.anti_fraud_current_path() else { return Ok(()) };
        let Some(previous_path) = self.anti_fraud_previous_path() else { return Ok(()) };
        if let Some(parent) = current_path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("failed creating anti-fraud dir: {err}"))?;
        }
        if let Some(previous_snapshot) = previous {
            let bytes = serde_json::to_vec_pretty(&PersistedSnapshotV1::from(previous_snapshot))
                .map_err(|err| format!("failed serializing previous snapshot: {err}"))?;
            Self::write_atomic(&previous_path, &bytes)?;
        }
        if let Some(current_snapshot) = current {
            let bytes = serde_json::to_vec_pretty(&PersistedSnapshotV1::from(current_snapshot))
                .map_err(|err| format!("failed serializing current snapshot: {err}"))?;
            Self::write_atomic(&current_path, &bytes)?;
        }
        Ok(())
    }

    fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let tmp_path = path.with_extension(format!("tmp.{ts}.json"));
        let mut file = File::create(&tmp_path).map_err(|err| format!("failed creating {}: {err}", tmp_path.display()))?;
        file.write_all(data).map_err(|err| format!("failed writing {}: {err}", tmp_path.display()))?;
        file.sync_all().map_err(|err| format!("failed fsync {}: {err}", tmp_path.display()))?;
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        fs::rename(&tmp_path, path).map_err(|err| format!("failed rename {} -> {}: {err}", tmp_path.display(), path.display()))?;
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut quarantined = path.to_path_buf();
        quarantined.set_extension(format!("quarantine.{ts}.json"));
        let _ = fs::rename(path, quarantined);
    }

    async fn disconnect_peers_by_ip_list(&self, ips: Vec<IpAddr>) {
        let ip_set = ips.into_iter().collect::<HashSet<_>>();
        if ip_set.is_empty() {
            return;
        }

        let peers_to_disconnect =
            self.p2p_adaptor.active_peers().into_iter().filter(|peer| ip_set.contains(&peer.net_address().ip())).collect_vec();
        if peers_to_disconnect.is_empty() {
            return;
        }

        info!("Banserver enforcement: disconnecting {} active peer(s) due to newly banned IP entries", peers_to_disconnect.len());
        let disconnect_jobs = peers_to_disconnect.iter().map(|peer| self.p2p_adaptor.terminate(peer.key())).collect_vec();
        join_all(disconnect_jobs).await;
    }

    async fn disconnect_peers_by_node_id_list(&self, node_ids: Vec<[u8; 32]>) {
        let banned_set = node_ids.into_iter().collect::<HashSet<_>>();
        let peers_to_disconnect = self
            .p2p_adaptor
            .active_peers()
            .into_iter()
            .filter(|peer| peer.properties().unified_node_id.map(|node_id| banned_set.contains(&node_id)).unwrap_or(false))
            .collect_vec();
        if peers_to_disconnect.is_empty() {
            return;
        }

        info!(
            "Banserver enforcement: disconnecting {} active peer(s) due to newly banned unified node ID entries",
            peers_to_disconnect.len()
        );
        let disconnect_jobs = peers_to_disconnect.iter().map(|peer| self.p2p_adaptor.terminate(peer.key())).collect_vec();
        join_all(disconnect_jobs).await;
    }
}

impl From<AntiFraudSnapshot> for AntiFraudSnapshotEnvelope {
    fn from(value: AntiFraudSnapshot) -> Self {
        Self {
            schema_version: value.schema_version,
            network: value.network as u8,
            snapshot_seq: value.snapshot_seq,
            generated_at_ms: value.generated_at_ms,
            signing_key_id: value.signing_key_id,
            antifraud_enabled: value.antifraud_enabled,
            banned_ips: value.banned_ip_entries,
            banned_node_ids: value.banned_node_id_entries.into_iter().map(|entry| entry.to_vec()).collect(),
            signature: value.signature.to_vec(),
        }
    }
}

impl From<&AntiFraudSnapshot> for PersistedSnapshotV1 {
    fn from(value: &AntiFraudSnapshot) -> Self {
        Self {
            schema_version: value.schema_version,
            network: value.network as u8,
            snapshot_seq: value.snapshot_seq,
            generated_at_ms: value.generated_at_ms,
            signing_key_id: value.signing_key_id,
            antifraud_enabled: value.antifraud_enabled,
            banned_ips: value.banned_ip_entries.iter().map(|entry| ConnectionManager::encode_hex(entry)).collect(),
            banned_node_ids: value.banned_node_id_entries.iter().map(|entry| ConnectionManager::encode_hex(entry)).collect(),
            signature: ConnectionManager::encode_hex(&value.signature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_banserver_payload_accepts_signed_snapshot() {
        let payload = build_seed_payload();
        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse");
        assert!(parsed.enabled);
        assert_eq!(parsed.snapshot.snapshot_seq, 2);
        assert_eq!(parsed.snapshot.banned_ip_entries.len(), 1);
        assert_eq!(parsed.snapshot.banned_node_id_entries.len(), 1);
    }

    #[test]
    fn parse_banserver_payload_accepts_signed_runtime_disable() {
        let mut payload = build_seed_payload();
        payload["antifraud_enabled"] = json!(false);
        payload["signature"] = json!("5f94c8ec397d696d8c9c95f3c18865cd48a9e4f2b1d31b3c83dec516ed0f0f029812cf87c7abc82c43c4c8ac34fd828bc98e84b8f37459c8458a787398d85076");
        payload["root_hash"] = json!("35debec6b2f2ad6def2f701bb97ad5c1c055a4c35135c1f13e4818727ea9bdb0");

        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse");
        assert!(!parsed.enabled);
        assert_eq!(parsed.snapshot.snapshot_seq, 2);
    }

    #[test]
    fn parse_banserver_payload_rejects_bad_signature() {
        let mut payload = build_seed_payload();
        payload["signature"] = json!("00");
        let err = ConnectionManager::parse_banserver_payload(payload).expect_err("payload must fail");
        assert!(err.contains("signature"));
    }

    #[test]
    fn parse_banserver_payload_rejects_oversized_count() {
        let mut ips = Vec::with_capacity(BANSERVER_MAX_IPS + 10);
        for i in 0..(BANSERVER_MAX_IPS + 10) {
            let octet = (i % 250) as u8;
            ips.push(format!("10.0.{}.{}", octet, (octet + 1) % 250));
        }
        let mut payload = build_seed_payload();
        payload["banned_ips"] = json!(ips);
        let err = ConnectionManager::parse_banserver_payload(payload).expect_err("payload must fail");
        assert!(err.contains("banned_ips_count"));
    }

    #[test]
    fn read_antifraud_enabled_requires_strict_boolean() {
        let enabled_true = json!({"antifraud_enabled": true});
        assert_eq!(ConnectionManager::read_antifraud_enabled(&enabled_true).unwrap(), true);

        let enabled_false = json!({"data": {"antifraud_enabled": false}});
        assert_eq!(ConnectionManager::read_antifraud_enabled(&enabled_false).unwrap(), false);

        let invalid = json!({"antifraud_enabled": "true"});
        let err = ConnectionManager::read_antifraud_enabled(&invalid).expect_err("string flag must be rejected");
        assert!(err.contains("strict boolean"));
    }

    #[test]
    fn validate_hash_window_rules() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        assert!(ConnectionManager::validate_hash_window(&[h1, h2, ANTI_FRAUD_ZERO_HASH]));
        assert!(!ConnectionManager::validate_hash_window(&[h1, ANTI_FRAUD_ZERO_HASH, h2]));
        assert!(!ConnectionManager::validate_hash_window(&[h1, h1, ANTI_FRAUD_ZERO_HASH]));
    }

    #[test]
    fn advance_hash_window_is_newest_first_and_zero_padded() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let w1 = ConnectionManager::advance_hash_window([ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN], h1);
        assert_eq!(w1, [h1, ANTI_FRAUD_ZERO_HASH, ANTI_FRAUD_ZERO_HASH]);
        let w2 = ConnectionManager::advance_hash_window(w1, h2);
        assert_eq!(w2, [h2, h1, ANTI_FRAUD_ZERO_HASH]);
        let w3 = ConnectionManager::advance_hash_window(w2, h3);
        assert_eq!(w3, [h3, h2, h1]);
        let w4 = ConnectionManager::advance_hash_window(w3, h3);
        assert_eq!(w4, w3);
    }

    #[test]
    fn http_fallback_url_converts_https_to_http() {
        let fallback = ConnectionManager::http_fallback_url("https://example.org/api/confirmed-cases/iplist").unwrap();
        assert_eq!(fallback, "http://example.org/api/confirmed-cases/iplist");
    }

    #[test]
    fn has_nonzero_overlap_ignores_zero_hash() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        assert!(ConnectionManager::has_nonzero_hash_overlap(
            &[h1, ANTI_FRAUD_ZERO_HASH, ANTI_FRAUD_ZERO_HASH],
            &[h2, h1, ANTI_FRAUD_ZERO_HASH]
        ));
        assert!(!ConnectionManager::has_nonzero_hash_overlap(
            &[ANTI_FRAUD_ZERO_HASH, ANTI_FRAUD_ZERO_HASH, ANTI_FRAUD_ZERO_HASH],
            &[ANTI_FRAUD_ZERO_HASH, ANTI_FRAUD_ZERO_HASH, ANTI_FRAUD_ZERO_HASH]
        ));
    }

    #[test]
    fn seed_server_failure_state_transitions_retry_then_peer_fallback() {
        let mut state = AntiFraudState::default();
        assert_eq!(ConnectionManager::apply_seed_server_failure_state(&mut state), SeedServerFailureAction::RetrySoon);
        assert!(state.runtime_enabled);
        assert!(state.seed_server_retry_pending);
        assert!(!state.peer_fallback_required);

        assert_eq!(ConnectionManager::apply_seed_server_failure_state(&mut state), SeedServerFailureAction::EnablePeerFallback);
        assert!(state.runtime_enabled);
        assert!(!state.seed_server_retry_pending);
        assert!(state.peer_fallback_required);
    }

    #[test]
    fn seed_server_failure_state_keeps_existing_peer_fallback() {
        let mut state = AntiFraudState {
            runtime_enabled: true,
            current_snapshot: None,
            hash_window: [ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN],
            peer_votes: HashMap::new(),
            peer_fallback_required: true,
            seed_server_retry_pending: true,
        };

        assert_eq!(ConnectionManager::apply_seed_server_failure_state(&mut state), SeedServerFailureAction::KeepPeerFallback);
        assert!(state.runtime_enabled);
        assert!(state.peer_fallback_required);
        assert!(!state.seed_server_retry_pending);
    }

    #[test]
    fn evaluate_enabled_snapshot_pair_rejects_same_seq_different_hash() {
        let now_ms = 1_700_000_020_000u64;
        let selected = snapshot_for_consistency(10, 1_700_000_000_000, 0x11);
        let peer = snapshot_for_consistency(10, 1_700_000_000_100, 0x22);

        let err = ConnectionManager::evaluate_enabled_snapshot_pair("primary", &selected, "secondary", &peer, now_ms)
            .expect_err("same seq with different root hash must fail");
        assert!(err.contains("identical snapshot_seq"));
    }

    #[test]
    fn evaluate_enabled_snapshot_pair_accepts_same_seq_same_hash() {
        let now_ms = 1_700_000_020_000u64;
        let selected = snapshot_for_consistency(10, 1_700_000_000_000, 0x11);
        let peer = snapshot_for_consistency(10, 1_700_000_000_100, 0x11);

        let result = ConnectionManager::evaluate_enabled_snapshot_pair("primary", &selected, "secondary", &peer, now_ms)
            .expect("same seq/hash should pass");
        assert!(result.is_none());
    }

    #[test]
    fn evaluate_enabled_snapshot_pair_allows_one_step_skew_within_tolerance() {
        let tolerance_ms = BANSERVER_REPLICATION_LAG_TOLERANCE.as_millis() as u64;
        let now_ms = 1_700_000_020_000u64;
        let selected = snapshot_for_consistency(11, now_ms - tolerance_ms, 0x22);
        let peer = snapshot_for_consistency(10, now_ms - 30_000, 0x11);

        let result = ConnectionManager::evaluate_enabled_snapshot_pair("primary", &selected, "secondary", &peer, now_ms)
            .expect("one-step skew inside tolerance should pass")
            .expect("skew should be flagged as tolerated");
        assert_eq!(result.0, "primary");
        assert_eq!(result.1, 11);
        assert_eq!(result.2, "secondary");
        assert_eq!(result.3, 10);
        assert_eq!(result.4, tolerance_ms);
    }

    #[test]
    fn evaluate_enabled_snapshot_pair_rejects_skew_beyond_tolerance() {
        let tolerance_ms = BANSERVER_REPLICATION_LAG_TOLERANCE.as_millis() as u64;
        let now_ms = 1_700_000_020_000u64;
        let selected = snapshot_for_consistency(11, now_ms - tolerance_ms - 1, 0x22);
        let peer = snapshot_for_consistency(10, now_ms - 30_000, 0x11);

        let err = ConnectionManager::evaluate_enabled_snapshot_pair("primary", &selected, "secondary", &peer, now_ms)
            .expect_err("skew past tolerance must fail");
        assert!(err.contains("diverged beyond tolerance"));
    }

    #[test]
    fn evaluate_enabled_snapshot_pair_rejects_large_seq_gap() {
        let now_ms = 1_700_000_020_000u64;
        let selected = snapshot_for_consistency(14, now_ms - 1000, 0x44);
        let peer = snapshot_for_consistency(10, now_ms - 30_000, 0x11);

        let err = ConnectionManager::evaluate_enabled_snapshot_pair("primary", &selected, "secondary", &peer, now_ms)
            .expect_err("seq gap > 1 must fail");
        assert!(err.contains("diverged beyond tolerance"));
    }

    fn build_seed_payload() -> JsonValue {
        json!({
            "antifraud_enabled": true,
            "schema_version": 1,
            "network": 0,
            "snapshot_seq": 2,
            "generated_at_ms": 1_700_000_000_100u64,
            "signing_key_id": 0,
            "banned_ips": ["127.0.0.1"],
            "banned_ips_count": 1,
            "banned_node_ids": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
            "banned_node_ids_count": 1,
            "root_hash": "d121e2a127f06866c23799b48883e00e8c844f62a96e2e207457f52e11c7ab2f",
            "signature": "e78caa63a9121ecf7f845ca4bce4b62ca01bb9277af000a5ffd030dc3855c7707d870f6e85a589a1d2b630eddc643a25d93665c7c663d55741fe5e7293bc539f",
        })
    }

    #[test]
    fn http_fallback_url_converts_https_443_to_http_80() {
        let fallback = ConnectionManager::http_fallback_url("https://example.org:443/path").unwrap();
        assert_eq!(fallback, "http://example.org/path");
    }

    fn snapshot_for_consistency(seq: u64, generated_at_ms: u64, root_hash_byte: u8) -> AntiFraudSnapshot {
        let mut root_hash = [0u8; 32];
        root_hash[0] = root_hash_byte;
        AntiFraudSnapshot {
            schema_version: ANTI_FRAUD_SCHEMA_VERSION,
            network: AntiFraudNetwork::Mainnet,
            snapshot_seq: seq,
            generated_at_ms,
            signing_key_id: 0,
            antifraud_enabled: true,
            banned_ip_entries: Vec::new(),
            banned_node_id_entries: Vec::new(),
            signature: [0u8; 64],
            root_hash,
        }
    }
}
