use crate::{flow_context::FlowContext, flow_trait::Flow};
use async_trait::async_trait;
use cryptix_connectionmanager::{
    AntiFraudMode, AntiFraudSnapshotEnvelope, ConnectionManager, ANTI_FRAUD_HASH_WINDOW_LEN, ANTI_FRAUD_ZERO_HASH,
};
use cryptix_core::{debug, warn};
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue_with_request_id, make_request, make_response,
    pb::{cryptixd_message::Payload, AntiFraudSnapshotV1Message, RequestAntiFraudSnapshotV1Message},
    IncomingRoute, Router,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::{select, time::interval};

const ANTI_FRAUD_REQUEST_INTERVAL: Duration = Duration::from_secs(20);
const ANTI_FRAUD_MODE_RECHECK_INTERVAL: Duration = Duration::from_secs(1);
const HARD_FORK_PROTOCOL_VERSION: u32 = 7;

fn anti_fraud_hash_window_from_vec(entries: &[[u8; 32]]) -> Option<[[u8; 32]; 3]> {
    if entries.len() != 3 {
        return None;
    }
    Some([entries[0], entries[1], entries[2]])
}

fn normalized_peer_hash_window(entries: &[[u8; 32]]) -> [[u8; 32]; ANTI_FRAUD_HASH_WINDOW_LEN] {
    let candidate = anti_fraud_hash_window_from_vec(entries).unwrap_or([ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN]);
    if ConnectionManager::validate_hash_window(&candidate) {
        candidate
    } else {
        [ANTI_FRAUD_ZERO_HASH; ANTI_FRAUD_HASH_WINDOW_LEN]
    }
}

pub struct AntiFraudSnapshotRequestsFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

impl AntiFraudSnapshotRequestsFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }
}

#[async_trait]
impl Flow for AntiFraudSnapshotRequestsFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (_, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestAntiFraudSnapshotV1)?;
            let Some(connection_manager) = self.ctx.connection_manager() else {
                continue;
            };
            let Some(snapshot) = connection_manager.anti_fraud_snapshot_envelope() else {
                continue;
            };
            let response = AntiFraudSnapshotV1Message {
                schema_version: snapshot.schema_version as u32,
                network: snapshot.network as u32,
                snapshot_seq: snapshot.snapshot_seq,
                generated_at_ms: snapshot.generated_at_ms,
                signing_key_id: snapshot.signing_key_id as u32,
                banned_ips: snapshot.banned_ips,
                banned_node_ids: snapshot.banned_node_ids,
                signature: snapshot.signature,
            };
            self.router.enqueue(make_response!(Payload::AntiFraudSnapshotV1, response, request_id)).await?;
        }
    }
}

pub struct AntiFraudSnapshotSyncFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

impl AntiFraudSnapshotSyncFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }
}

#[async_trait]
impl Flow for AntiFraudSnapshotSyncFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        let request_id = self.incoming_route.id();
        let mut request_ticker = interval(ANTI_FRAUD_REQUEST_INTERVAL);
        let mut mode_ticker = interval(ANTI_FRAUD_MODE_RECHECK_INTERVAL);
        loop {
            select! {
                _ = mode_ticker.tick() => {
                    if self.ctx.is_payload_hf_active() {
                        let properties = self.router.properties();
                        if properties.protocol_version < HARD_FORK_PROTOCOL_VERSION {
                            warn!(
                                "Peer {} still uses pre-HF protocol version {}; reconnecting to enforce v{}+",
                                self.router,
                                properties.protocol_version,
                                HARD_FORK_PROTOCOL_VERSION
                            );
                            self.ctx.hub().terminate(self.router.key()).await;
                            return Ok(());
                        }
                        let Some(connection_manager) = self.ctx.connection_manager() else {
                            continue;
                        };
                        let current_mode = anti_fraud_hash_window_from_vec(&properties.anti_fraud_hashes)
                            .map(|peer_hash_window| connection_manager.anti_fraud_mode_for_peer_hashes(&peer_hash_window))
                            .unwrap_or(AntiFraudMode::Restricted);
                        if properties.anti_fraud_restricted && current_mode == AntiFraudMode::Full {
                            debug!(
                                "Peer {} anti-fraud overlap became valid; reconnecting to upgrade from RESTRICTED_AF to FULL",
                                self.router
                            );
                            self.ctx.hub().terminate(self.router.key()).await;
                            return Ok(());
                        }
                        if !properties.anti_fraud_restricted && current_mode == AntiFraudMode::Restricted {
                            warn!(
                                "Peer {} lost anti-fraud hash overlap; reconnecting to enforce RESTRICTED_AF",
                                self.router
                            );
                            self.ctx.hub().terminate(self.router.key()).await;
                            return Ok(());
                        }
                    }
                }
                _ = request_ticker.tick() => {
                    if let Some(connection_manager) = self.ctx.connection_manager() {
                        if connection_manager.should_request_peer_snapshots() {
                            let request = make_request!(Payload::RequestAntiFraudSnapshotV1, RequestAntiFraudSnapshotV1Message {}, request_id);
                            let _ = self.router.enqueue(request).await;
                        }
                    }
                }
                message = self.incoming_route.recv() => {
                    let Some(message) = message else {
                        return Err(ProtocolError::ConnectionClosed);
                    };
                    let Some(Payload::AntiFraudSnapshotV1(payload)) = message.payload else {
                        return Err(ProtocolError::UnexpectedMessage(
                            "Payload::AntiFraudSnapshotV1",
                            message.payload.as_ref().map(Into::into),
                        ));
                    };
                    let Some(connection_manager) = self.ctx.connection_manager() else {
                        continue;
                    };
                    let Ok(network) = u8::try_from(payload.network) else {
                        continue;
                    };
                    let Ok(schema_version) = u8::try_from(payload.schema_version) else {
                        continue;
                    };
                    let Ok(signing_key_id) = u8::try_from(payload.signing_key_id) else {
                        continue;
                    };
                    let envelope = AntiFraudSnapshotEnvelope {
                        schema_version,
                        network,
                        snapshot_seq: payload.snapshot_seq,
                        generated_at_ms: payload.generated_at_ms,
                        signing_key_id,
                        banned_ips: payload.banned_ips,
                        banned_node_ids: payload.banned_node_ids,
                        signature: payload.signature,
                    };
                    match connection_manager.ingest_peer_snapshot(self.router.key(), envelope) {
                        Ok(result) => {
                            // Keep peer hash view fresh based on verified snapshot messages so
                            // mode rechecks are not stuck on stale handshake hashes.
                            let props = self.router.properties();
                            let current_window = normalized_peer_hash_window(&props.anti_fraud_hashes);
                            let updated_window = ConnectionManager::advance_peer_hash_window(current_window, result.root_hash);
                            if updated_window != current_window {
                                let mut updated_props = (*props).clone();
                                updated_props.anti_fraud_hashes = updated_window.to_vec();
                                self.router.set_properties(Arc::new(updated_props));
                            }

                            if result.applied {
                                debug!("Applied peer anti-fraud snapshot from {}", self.router);
                            }
                        }
                        Err(err) => {
                            warn!("Rejected peer anti-fraud snapshot from {}: {}", self.router, err);
                        }
                    }
                }
            }
        }
    }
}
