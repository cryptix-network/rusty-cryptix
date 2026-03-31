use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    hfa::{
        FastIntentP2pData, HFA_MAX_FAST_INTENT_MSGS_PER_SEC, HFA_MAX_FAST_MICROBLOCK_MSGS_PER_SEC, HFA_MAX_INTENT_IDS_PER_MESSAGE,
        HFA_MAX_REQUEST_FAST_INTENTS_MSGS_PER_SEC, HFA_MAX_REQUEST_FAST_INTENT_IDS_PER_SEC, HFA_PULL_ON_MISS_MAX_CONTEXT_IDS,
        HFA_PULL_ON_MISS_MAX_RETRIES, HFA_PULL_ON_MISS_WAIT_BUDGET_MS,
    },
};
use cryptix_core::time::unix_now;
use cryptix_hashes::Hash;
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue, make_message,
    pb::{cryptixd_message::Payload, FastIntentMessage, FastMicroblockMessage, RequestFastIntentsMessage},
    IncomingRoute, Router,
};
use std::{collections::HashMap, sync::Arc};

#[derive(Default)]
struct PeerHfaRateWindow {
    window_start_ms: u64,
    fast_intent_msgs: u64,
    fast_microblock_msgs: u64,
    request_fast_intents_msgs: u64,
    request_fast_intents_ids: u64,
}

impl PeerHfaRateWindow {
    fn roll_window_if_needed(&mut self, now_ms: u64) {
        if self.window_start_ms == 0 || now_ms >= self.window_start_ms.saturating_add(1_000) {
            self.window_start_ms = now_ms;
            self.fast_intent_msgs = 0;
            self.fast_microblock_msgs = 0;
            self.request_fast_intents_msgs = 0;
            self.request_fast_intents_ids = 0;
        }
    }

    fn allow_fast_intent(&mut self, now_ms: u64) -> bool {
        self.roll_window_if_needed(now_ms);
        if self.fast_intent_msgs >= HFA_MAX_FAST_INTENT_MSGS_PER_SEC {
            return false;
        }
        self.fast_intent_msgs = self.fast_intent_msgs.saturating_add(1);
        true
    }

    fn allow_fast_microblock(&mut self, now_ms: u64) -> bool {
        self.roll_window_if_needed(now_ms);
        if self.fast_microblock_msgs >= HFA_MAX_FAST_MICROBLOCK_MSGS_PER_SEC {
            return false;
        }
        self.fast_microblock_msgs = self.fast_microblock_msgs.saturating_add(1);
        true
    }

    fn allow_request_fast_intents(&mut self, now_ms: u64, request_ids: usize) -> bool {
        self.roll_window_if_needed(now_ms);
        if self.request_fast_intents_msgs >= HFA_MAX_REQUEST_FAST_INTENTS_MSGS_PER_SEC {
            return false;
        }
        let request_ids = request_ids as u64;
        if self.request_fast_intents_ids.saturating_add(request_ids) > HFA_MAX_REQUEST_FAST_INTENT_IDS_PER_SEC {
            return false;
        }
        self.request_fast_intents_msgs = self.request_fast_intents_msgs.saturating_add(1);
        self.request_fast_intents_ids = self.request_fast_intents_ids.saturating_add(request_ids);
        true
    }
}

pub struct RequestFastIntentsFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
    rate_window: PeerHfaRateWindow,
}

#[async_trait::async_trait]
impl Flow for RequestFastIntentsFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestFastIntentsFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route, rate_window: PeerHfaRateWindow::default() }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let request = dequeue!(self.incoming_route, Payload::RequestFastIntents)?;
            let now_ms = unix_now();
            let Some(bridge) = self.ctx.hfa_bridge() else {
                continue;
            };
            if !bridge.hfa_enabled() {
                continue;
            }

            if request.intent_ids.len() > HFA_MAX_INTENT_IDS_PER_MESSAGE {
                return Err(ProtocolError::Other("requestFastIntents ids over limit"));
            }
            if !self.rate_window.allow_request_fast_intents(now_ms, request.intent_ids.len()) {
                return Err(ProtocolError::Other("requestFastIntents rate limit exceeded"));
            }

            let mut intent_ids = Vec::with_capacity(request.intent_ids.len());
            for item in request.intent_ids {
                intent_ids.push(item.try_into()?);
            }

            for intent in bridge.get_fast_intents(&intent_ids) {
                self.router
                    .enqueue(make_message!(
                        Payload::FastIntent,
                        FastIntentMessage {
                            intent_id: Some(intent.intent_id.into()),
                            base_transaction: Some((&intent.base_tx).into()),
                            intent_nonce: intent.intent_nonce,
                            client_created_at_ms: intent.client_created_at_ms,
                            max_fee: intent.max_fee,
                        }
                    ))
                    .await?;
            }
        }
    }
}

pub struct FastIntentRelayFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
    pull_retries: HashMap<Hash, usize>,
    pull_last_request_ms: HashMap<Hash, u64>,
    rate_window: PeerHfaRateWindow,
}

#[async_trait::async_trait]
impl Flow for FastIntentRelayFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl FastIntentRelayFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self {
            ctx,
            router,
            incoming_route,
            pull_retries: HashMap::new(),
            pull_last_request_ms: HashMap::new(),
            rate_window: PeerHfaRateWindow::default(),
        }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let msg = self.incoming_route.recv().await.ok_or(ProtocolError::ConnectionClosed)?;
            match msg.payload {
                Some(Payload::FastIntent(payload)) => self.handle_fast_intent(payload).await?,
                Some(Payload::FastMicroblock(payload)) => self.handle_fast_microblock(payload).await?,
                payload => {
                    return Err(ProtocolError::UnexpectedMessage(
                        "Payload::FastIntent | Payload::FastMicroblock",
                        payload.as_ref().map(|v| v.into()),
                    ))
                }
            }

            self.ctx.broadcast_outbound_fast_microblocks().await;
        }
    }

    async fn handle_fast_intent(&mut self, payload: FastIntentMessage) -> Result<(), ProtocolError> {
        if !self.rate_window.allow_fast_intent(unix_now()) {
            return Err(ProtocolError::Other("fastIntent rate limit exceeded"));
        }

        let Some(bridge) = self.ctx.hfa_bridge() else {
            return Ok(());
        };
        if !bridge.hfa_enabled() {
            return Ok(());
        }

        let intent_id: Hash = payload.intent_id.ok_or(ProtocolError::Other("fastIntent missing intentId"))?.try_into()?;
        let base_tx = payload.base_transaction.ok_or(ProtocolError::Other("fastIntent missing baseTransaction"))?.try_into()?;
        let intent = FastIntentP2pData {
            intent_id,
            base_tx,
            intent_nonce: payload.intent_nonce,
            client_created_at_ms: payload.client_created_at_ms,
            max_fee: payload.max_fee,
        };

        let session = self.ctx.consensus().unguarded_session();
        let is_synced = session.async_is_nearly_synced().await;
        let network_id = self.ctx.config.net.to_string();
        bridge.submit_remote_fast_intent(&network_id, intent, session, self.ctx.mining_manager().clone(), is_synced, 0.0).await;

        self.pull_retries.remove(&intent_id);
        self.pull_last_request_ms.remove(&intent_id);

        Ok(())
    }

    async fn handle_fast_microblock(&mut self, payload: FastMicroblockMessage) -> Result<(), ProtocolError> {
        if !self.rate_window.allow_fast_microblock(unix_now()) {
            return Err(ProtocolError::Other("fastMicroblock rate limit exceeded"));
        }

        let Some(bridge) = self.ctx.hfa_bridge() else {
            return Ok(());
        };
        if !bridge.hfa_enabled() {
            return Ok(());
        }

        if payload.intent_ids.len() > HFA_MAX_INTENT_IDS_PER_MESSAGE {
            return Err(ProtocolError::Other("fastMicroblock intent ids over limit"));
        }

        let now_ms = unix_now();
        let mut intent_ids = Vec::with_capacity(payload.intent_ids.len());
        for item in payload.intent_ids {
            intent_ids.push(item.try_into()?);
        }

        let missing = bridge.on_remote_fast_microblock(&intent_ids, now_ms);
        if missing.is_empty() {
            return Ok(());
        }

        let mut to_request = Vec::new();
        let mut pull_fail_count: u64 = 0;
        for intent_id in missing.into_iter().take(HFA_PULL_ON_MISS_MAX_CONTEXT_IDS) {
            let retries = *self.pull_retries.get(&intent_id).unwrap_or(&0);
            if retries >= HFA_PULL_ON_MISS_MAX_RETRIES {
                self.pull_retries.remove(&intent_id);
                self.pull_last_request_ms.remove(&intent_id);
                pull_fail_count = pull_fail_count.saturating_add(1);
                continue;
            }

            let last_request_ms = *self.pull_last_request_ms.get(&intent_id).unwrap_or(&0);
            if now_ms < last_request_ms.saturating_add(HFA_PULL_ON_MISS_WAIT_BUDGET_MS) {
                continue;
            }

            self.pull_retries.insert(intent_id, retries.saturating_add(1));
            self.pull_last_request_ms.insert(intent_id, now_ms);
            to_request.push(intent_id);
        }

        if pull_fail_count > 0 {
            bridge.record_pull_fail(pull_fail_count);
        }

        for chunk in to_request.chunks(HFA_MAX_INTENT_IDS_PER_MESSAGE) {
            self.router
                .enqueue(make_message!(
                    Payload::RequestFastIntents,
                    RequestFastIntentsMessage { intent_ids: chunk.iter().map(Into::into).collect() }
                ))
                .await?;
        }

        Ok(())
    }
}
