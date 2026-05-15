use crate::{flow_context::FlowContext, flow_trait::Flow};
use async_trait::async_trait;
use cryptix_connectionmanager::AntiFraudSnapshotEnvelope;
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
        loop {
            select! {
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
