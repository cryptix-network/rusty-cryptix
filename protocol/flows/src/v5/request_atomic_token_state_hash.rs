use std::{sync::Arc, time::Duration};

use cryptix_core::warn;
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue_with_request_id, make_response,
    pb::{cryptixd_message::Payload, AtomicTokenStateHashMessage},
    IncomingRoute, Router, BLANK_ROUTE_ID,
};

use crate::{flow_context::FlowContext, flow_trait::Flow};

const ATOMIC_STATE_HASH_RESPONSE_WAIT: Duration = Duration::from_secs(10);
const ATOMIC_STATE_HASH_RESPONSE_POLL: Duration = Duration::from_millis(250);

pub struct RequestAtomicTokenStateHashFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for RequestAtomicTokenStateHashFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (request, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestAtomicTokenStateHash)?;
            if request_id == BLANK_ROUTE_ID {
                return Err(ProtocolError::MisbehavingPeer("RequestAtomicTokenStateHash missing non-zero request id".to_string()));
            }
            let Some(block_hash) = request.block_hash else {
                return Err(ProtocolError::Other("RequestAtomicTokenStateHash missing block hash"));
            };
            let block_hash = block_hash.try_into()?;
            let anchor_daa_score = request.anchor_daa_score;
            let deadline = tokio::time::Instant::now() + ATOMIC_STATE_HASH_RESPONSE_WAIT;
            let state_hash = loop {
                if !self.ctx.is_ibd_running() {
                    let consensus = self.ctx.consensus();
                    let session = consensus.session().await;
                    let local_anchor_matches =
                        session.async_get_header(block_hash).await.map(|header| header.daa_score == anchor_daa_score).unwrap_or(false);
                    if local_anchor_matches {
                        match self.ctx.local_atomic_token_state_hash_for_peer(block_hash).await {
                            Ok(Some(state_hash)) => break Some(state_hash),
                            Ok(None) => {}
                            Err(err) => {
                                warn!(
                                    "Atomic token state hash response unavailable for `{block_hash}`; replying without token state: {err}"
                                );
                                break None;
                            }
                        }
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    break None;
                }
                tokio::time::sleep(ATOMIC_STATE_HASH_RESPONSE_POLL).await;
            };
            let (state_hash, has_state) = match state_hash {
                Some(state_hash) => (state_hash.to_vec(), true),
                None => (Vec::new(), false),
            };

            self.router
                .enqueue(make_response!(
                    Payload::AtomicTokenStateHash,
                    AtomicTokenStateHashMessage { block_hash: Some(block_hash.into()), state_hash, has_state, anchor_daa_score },
                    request_id
                ))
                .await?;
        }
    }
}

impl RequestAtomicTokenStateHashFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }
}
