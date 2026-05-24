use std::sync::Arc;

use cryptix_core::warn;
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue_with_request_id, make_response,
    pb::{cryptixd_message::Payload, BlockLocatorMessage},
    IncomingRoute, Router,
};

use crate::{flow_context::FlowContext, flow_trait::Flow};

use super::is_unsafe_block_status_for_network;

pub struct RequestBlockLocatorFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for RequestBlockLocatorFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestBlockLocatorFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (msg, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestBlockLocator)?;
            let (high, limit) = msg.try_into()?;

            let session = self.ctx.consensus().session().await;
            let locator = session.async_create_block_locator_from_pruning_point(high, limit as usize).await?;
            for hash in locator.iter().copied() {
                if let Some(status) = session.async_get_block_status(hash).await {
                    if is_unsafe_block_status_for_network(status) {
                        let reason = format!("refusing to serve unsafe block locator block {} with status {:?}", hash, status);
                        warn!("{}", reason);
                        return Err(ProtocolError::OtherOwned(reason));
                    }
                }
            }

            self.router
                .enqueue(make_response!(
                    Payload::BlockLocator,
                    BlockLocatorMessage { hashes: locator.into_iter().map(|hash| hash.into()).collect() },
                    request_id
                ))
                .await?;
        }
    }
}
