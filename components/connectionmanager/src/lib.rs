use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, SystemTime},
};

use cryptix_addressmanager::{AddressManager, NetAddress};
use cryptix_core::{debug, info, warn};
use cryptix_p2p_lib::{common::ProtocolError, ConnectionError, Peer};
use cryptix_utils::triggers::SingleTrigger;
use duration_string::DurationString;
use futures_util::future::{join_all, try_join_all};
use itertools::Itertools;
use parking_lot::Mutex as ParkingLotMutex;
use rand::{seq::SliceRandom, thread_rng};
use reqwest::{redirect::Policy as RedirectPolicy, Client as HttpClient, Url as ParsedUrl};
use serde_json::Value as JsonValue;
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex as TokioMutex,
    },
    time::{interval, MissedTickBehavior},
};

pub const DEFAULT_BANSERVER_URL: &str = "https://antifraud.cryptix-network.org/api/confirmed-cases/iplist";
const BANSERVER_REFRESH_INTERVAL: Duration = Duration::from_secs(20 * 60);
const BANSERVER_FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const BANSERVER_MAX_IPS: usize = 10_000;
const BANSERVER_MAX_IP_ENTRY_LEN: usize = 64;
const BANSERVER_MAX_NODE_IDS: usize = 10_000;
const BANSERVER_NODE_ID_HEX_LEN: usize = 64;
const BANSERVER_MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const BANSERVER_BANNED_CONNECTION_RETRY_DELAY: Duration = Duration::from_secs(60);

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
    banserver_url: String,
    banserver_banned_ips: ParkingLotMutex<HashSet<IpAddr>>,
    banserver_banned_strong_node_ids: ParkingLotMutex<HashSet<[u8; 32]>>,
}

#[derive(Clone, Debug)]
struct ConnectionRequest {
    next_attempt: SystemTime,
    is_permanent: bool,
    attempts: u32,
}

#[derive(Debug, Default)]
struct BanserverPayload {
    ips: HashSet<IpAddr>,
    strong_node_ids: HashSet<[u8; 32]>,
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
        banserver_url: Option<String>,
    ) -> Arc<Self> {
        let (tx, rx) = unbounded_channel::<()>();
        let banserver_url = banserver_url
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| DEFAULT_BANSERVER_URL.to_owned());
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
            banserver_url,
            banserver_banned_ips: ParkingLotMutex::new(HashSet::new()),
            banserver_banned_strong_node_ids: ParkingLotMutex::new(HashSet::new()),
        });
        manager.clone().start_event_loop(rx);
        manager.force_next_iteration.send(()).unwrap();
        manager
    }

    fn start_event_loop(self: Arc<Self>, mut rx: UnboundedReceiver<()>) {
        let mut ticker = interval(Duration::from_secs(30));
        let mut banserver_ticker = interval(BANSERVER_REFRESH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        banserver_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tokio::spawn(async move {
            if self.banserver_enabled {
                self.clone().refresh_banserver_bans().await;
                // Consume the immediate interval tick so the next refresh is one full interval away.
                let _ = banserver_ticker.tick().await;
            }
            loop {
                if self.shutdown_signal.trigger.is_triggered() {
                    break;
                }
                select! {
                    _ = rx.recv() => self.clone().handle_event().await,
                    _ = ticker.tick() => self.clone().handle_event().await,
                    _ = banserver_ticker.tick(), if self.banserver_enabled => self.clone().refresh_banserver_bans().await,
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

    fn is_banserver_banned_ip(&self, ip: IpAddr) -> bool {
        self.banserver_enabled && self.banserver_banned_ips.lock().contains(&ip)
    }

    pub fn is_banserver_banned_strong_node_id(&self, static_id_raw: &[u8; 32]) -> bool {
        self.banserver_enabled && self.banserver_banned_strong_node_ids.lock().contains(static_id_raw)
    }

    async fn refresh_banserver_bans(self: Arc<Self>) {
        let fetched = match self.fetch_banserver_payload().await {
            Ok(payload) => payload,
            Err(err) => {
                warn!("Banserver refresh failed (URL: {}): {}. Continuing without remote list update.", self.banserver_url, err);
                return;
            }
        };

        let (
            newly_banned_ips,
            removed_ip_count,
            total_ip_count,
            newly_banned_node_id_count,
            removed_node_id_count,
            total_node_id_count,
        ) = {
            let mut ip_state = self.banserver_banned_ips.lock();
            let mut node_id_state = self.banserver_banned_strong_node_ids.lock();

            let newly_banned_ips = fetched.ips.difference(&*ip_state).copied().collect_vec();
            let removed_ip_count = ip_state.difference(&fetched.ips).count();
            let newly_banned_node_id_count = fetched.strong_node_ids.difference(&*node_id_state).count();
            let removed_node_id_count = node_id_state.difference(&fetched.strong_node_ids).count();

            *ip_state = fetched.ips;
            *node_id_state = fetched.strong_node_ids;

            (
                newly_banned_ips,
                removed_ip_count,
                ip_state.len(),
                newly_banned_node_id_count,
                removed_node_id_count,
                node_id_state.len(),
            )
        };

        if newly_banned_ips.is_empty() && removed_ip_count == 0 && newly_banned_node_id_count == 0 && removed_node_id_count == 0 {
            debug!(
                "Banserver refresh completed with no changes ({} active IPs, {} active strong-node IDs)",
                total_ip_count, total_node_id_count
            );
            return;
        }

        info!(
            "Banserver refresh applied: {} newly banned IPs, {} removed IPs, {} total IPs, {} newly banned strong-node IDs, {} removed strong-node IDs, {} total strong-node IDs",
            newly_banned_ips.len(),
            removed_ip_count,
            total_ip_count,
            newly_banned_node_id_count,
            removed_node_id_count,
            total_node_id_count
        );

        if !newly_banned_ips.is_empty() {
            self.disconnect_peers_by_ip_list(newly_banned_ips).await;
        }

        // Ensure the connection loop reacts quickly to newly updated server bans.
        let _ = self.force_next_iteration.send(());
    }

    async fn fetch_banserver_payload(&self) -> Result<BanserverPayload, String> {
        let primary_url = self.banserver_url.trim();
        match self.fetch_banserver_json(primary_url).await {
            Ok(payload) => Self::parse_banserver_payload(payload),
            Err(primary_err) => {
                if let Some(fallback_url) = Self::http_fallback_url(primary_url) {
                    match self.fetch_banserver_json(&fallback_url).await {
                        Ok(payload) => {
                            warn!(
                                "Banserver HTTPS fetch failed for {} ({}), HTTP fallback {} succeeded",
                                primary_url, primary_err, fallback_url
                            );
                            Self::parse_banserver_payload(payload)
                        }
                        Err(fallback_err) => {
                            Err(format!("primary fetch failed: {}; http fallback failed: {}", primary_err, fallback_err))
                        }
                    }
                } else {
                    Err(primary_err)
                }
            }
        }
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
            // Keep hostname verification enabled (default), only cert chain/date checks are relaxed.
            .danger_accept_invalid_hostnames(false)
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
        let ips_values = Self::extract_ip_array(&payload);
        let node_id_values = Self::extract_node_id_array(&payload);
        if ips_values.is_none() && node_id_values.is_none() {
            return Err("missing `ips` or `node_ids` array in banserver payload".to_owned());
        }

        let mut parsed_ips = HashSet::new();
        if let Some(ips_values) = ips_values {
            for raw in ips_values.iter().take(BANSERVER_MAX_IPS) {
                let Some(raw_ip) = raw.as_str() else {
                    continue;
                };
                let candidate = raw_ip.trim();
                if candidate.is_empty() || candidate.len() > BANSERVER_MAX_IP_ENTRY_LEN {
                    continue;
                }
                if let Ok(ip) = candidate.parse::<IpAddr>() {
                    parsed_ips.insert(ip);
                }
            }
        }

        let mut parsed_node_ids = HashSet::new();
        if let Some(node_id_values) = node_id_values {
            for raw in node_id_values.iter().take(BANSERVER_MAX_NODE_IDS) {
                let Some(raw_node_id) = raw.as_str() else {
                    continue;
                };
                if let Some(static_id_raw) = Self::parse_node_id_hex(raw_node_id) {
                    parsed_node_ids.insert(static_id_raw);
                }
            }
        }

        Ok(BanserverPayload { ips: parsed_ips, strong_node_ids: parsed_node_ids })
    }

    fn extract_ip_array(payload: &JsonValue) -> Option<&Vec<JsonValue>> {
        payload
            .get("ips")
            .and_then(JsonValue::as_array)
            .or_else(|| payload.get("data").and_then(|data| data.get("ips")).and_then(JsonValue::as_array))
            .or_else(|| payload.as_array())
    }

    fn extract_node_id_array(payload: &JsonValue) -> Option<&Vec<JsonValue>> {
        payload
            .get("node_ids")
            .and_then(JsonValue::as_array)
            .or_else(|| payload.get("data").and_then(|data| data.get("node_ids")).and_then(JsonValue::as_array))
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

    fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_banserver_ips_accepts_standard_ips_array() {
        let payload = json!({
            "status": "success",
            "count": 2,
            "ips": ["1.2.3.4", "2001:db8::1"]
        });
        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse").ips;
        assert!(parsed.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(parsed.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_banserver_ips_filters_invalid_entries() {
        let payload = json!({
            "ips": ["1.2.3.4", "not-an-ip", "", "  ", null, "999.1.1.1", "2001:db8::1"]
        });
        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse").ips;
        assert!(parsed.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(parsed.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_banserver_ips_respects_max_entries_cap() {
        let mut ips = Vec::with_capacity(BANSERVER_MAX_IPS + 10);
        for i in 0..(BANSERVER_MAX_IPS + 10) {
            let octet = (i % 250) as u8;
            ips.push(format!("10.0.{}.{}", octet, (octet + 1) % 250));
        }
        let payload = json!({ "ips": ips });
        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse").ips;
        assert!(parsed.len() <= BANSERVER_MAX_IPS);
    }

    #[test]
    fn parse_banserver_payload_parses_node_ids() {
        let payload = json!({
            "ips": ["1.2.3.4"],
            "node_ids": [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            ]
        });
        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse");
        assert!(parsed.ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert_eq!(parsed.strong_node_ids.len(), 2);
    }

    #[test]
    fn parse_banserver_payload_filters_invalid_node_ids() {
        let payload = json!({
            "node_ids": [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "xyz",
                "",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaz",
                123
            ]
        });
        let parsed = ConnectionManager::parse_banserver_payload(payload).expect("payload should parse");
        assert_eq!(parsed.strong_node_ids.len(), 1);
    }

    #[test]
    fn parse_banserver_payload_rejects_payload_without_supported_arrays() {
        let payload = json!({ "status": "ok" });
        let err = ConnectionManager::parse_banserver_payload(payload).expect_err("payload must be rejected");
        assert!(err.contains("missing `ips` or `node_ids` array"));
    }

    #[test]
    fn http_fallback_url_converts_https_to_http() {
        let fallback = ConnectionManager::http_fallback_url("https://example.org/api/confirmed-cases/iplist").unwrap();
        assert_eq!(fallback, "http://example.org/api/confirmed-cases/iplist");
    }

    #[test]
    fn http_fallback_url_converts_https_443_to_http_80() {
        let fallback = ConnectionManager::http_fallback_url("https://example.org:443/path").unwrap();
        assert_eq!(fallback, "http://example.org/path");
    }

    #[test]
    fn http_fallback_url_ignores_non_https() {
        assert!(ConnectionManager::http_fallback_url("http://example.org/path").is_none());
        assert!(ConnectionManager::http_fallback_url("ftp://example.org/path").is_none());
    }
}
