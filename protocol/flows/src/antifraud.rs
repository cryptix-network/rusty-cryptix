use crate::{flow_context::FlowContext, flow_trait::Flow, strong_node_claims::STRONG_NODE_CLAIMS_P2P_SERVICE_BIT};
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
const HARD_FORK_PROTOCOL_VERSION: u32 = 9;
const MODE_MISMATCH_THRESHOLD: u8 = 5;

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

fn should_disconnect_on_consecutive_mismatch(streak: &mut u8, mismatch: bool) -> bool {
    if !mismatch {
        *streak = 0;
        return false;
    }

    *streak = streak.saturating_add(1);
    *streak >= MODE_MISMATCH_THRESHOLD
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
                antifraud_enabled: snapshot.antifraud_enabled,
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
        let mut protocol_mismatch_streak = 0u8;
        let mut service_mismatch_streak = 0u8;
        let mut mode_mismatch_streak = 0u8;
        loop {
            select! {
                _ = mode_ticker.tick() => {
                    let Some(connection_manager) = self.ctx.connection_manager() else {
                        protocol_mismatch_streak = 0;
                        service_mismatch_streak = 0;
                        mode_mismatch_streak = 0;
                        continue;
                    };
                    if !self.ctx.is_payload_hf_active() {
                        protocol_mismatch_streak = 0;
                        service_mismatch_streak = 0;
                        mode_mismatch_streak = 0;
                        continue;
                    }

                    let properties = self.router.properties();
                    let protocol_mismatch = properties.protocol_version < HARD_FORK_PROTOCOL_VERSION;
                    if should_disconnect_on_consecutive_mismatch(&mut protocol_mismatch_streak, protocol_mismatch) {
                        warn!(
                            "Peer {} still uses pre-HF protocol version {}; reconnecting to enforce v{}+",
                            self.router,
                            properties.protocol_version,
                            HARD_FORK_PROTOCOL_VERSION
                        );
                        self.ctx.hub().terminate(self.router.key()).await;
                        return Ok(());
                    }
                    if protocol_mismatch {
                        service_mismatch_streak = 0;
                        mode_mismatch_streak = 0;
                        continue;
                    }

                    let missing_strong_node_claims_service =
                        (properties.services & STRONG_NODE_CLAIMS_P2P_SERVICE_BIT) == 0;
                    if should_disconnect_on_consecutive_mismatch(
                        &mut service_mismatch_streak,
                        missing_strong_node_claims_service,
                    ) {
                        warn!(
                            "Peer {} is missing mandatory strong-node-claims service bit after hardfork; reconnecting to renegotiate post-HF capabilities",
                            self.router
                        );
                        self.ctx.hub().terminate(self.router.key()).await;
                        return Ok(());
                    }
                    if missing_strong_node_claims_service {
                        mode_mismatch_streak = 0;
                        continue;
                    }

                    let runtime_enabled = connection_manager.is_antifraud_runtime_enabled();
                    let current_mode = anti_fraud_hash_window_from_vec(&properties.anti_fraud_hashes)
                        .map(|peer_hash_window| {
                            if runtime_enabled {
                                connection_manager.anti_fraud_mode_for_peer_hashes(&peer_hash_window)
                            } else {
                                AntiFraudMode::Full
                            }
                        })
                        .unwrap_or(if runtime_enabled {
                            AntiFraudMode::Restricted
                        } else {
                            AntiFraudMode::Full
                        });
                    let mode_mismatch = (properties.anti_fraud_restricted && current_mode == AntiFraudMode::Full)
                        || (!properties.anti_fraud_restricted && current_mode == AntiFraudMode::Restricted);
                    if !should_disconnect_on_consecutive_mismatch(&mut mode_mismatch_streak, mode_mismatch) {
                        continue;
                    }
                    if properties.anti_fraud_restricted && current_mode == AntiFraudMode::Full {
                        let reason = if runtime_enabled {
                            "anti-fraud overlap became valid"
                        } else {
                            "anti-fraud runtime is disabled"
                        };
                        debug!("Peer {} {}; reconnecting to upgrade from RESTRICTED_AF to FULL", self.router, reason);
                        self.ctx.hub().terminate(self.router.key()).await;
                        return Ok(());
                    }
                    warn!(
                        "Peer {} lost anti-fraud hash overlap; reconnecting to enforce RESTRICTED_AF",
                        self.router
                    );
                    self.ctx.hub().terminate(self.router.key()).await;
                    return Ok(());
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
                    if !connection_manager.is_antifraud_runtime_enabled() {
                        continue;
                    }
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
                        antifraud_enabled: payload.antifraud_enabled,
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

#[cfg(test)]
mod tests {
    use super::{should_disconnect_on_consecutive_mismatch, MODE_MISMATCH_THRESHOLD};

    #[test]
    fn disconnect_helper_triggers_at_threshold() {
        let mut streak = 0u8;
        for _ in 0..(MODE_MISMATCH_THRESHOLD - 1) {
            assert!(!should_disconnect_on_consecutive_mismatch(&mut streak, true));
        }
        assert!(should_disconnect_on_consecutive_mismatch(&mut streak, true));
    }

    #[test]
    fn disconnect_helper_resets_on_healthy_tick() {
        let mut streak = 0u8;
        assert!(!should_disconnect_on_consecutive_mismatch(&mut streak, true));
        assert!(!should_disconnect_on_consecutive_mismatch(&mut streak, false));
        assert_eq!(streak, 0);
    }
}
