use crate::{flow_context::FlowContext, flow_trait::Flow};
use cryptix_core::{debug, warn};
use cryptix_p2p_lib::{
    common::ProtocolError, dequeue_with_request_id, make_response, pb::cryptixd_message::Payload, IncomingRoute, Router,
};
use std::sync::Arc;

use super::is_unsafe_block_status_for_network;

pub struct HandleIbdBlockRequests {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for HandleIbdBlockRequests {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl HandleIbdBlockRequests {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (msg, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestIbdBlocks)?;
            let hashes: Vec<_> = msg.try_into()?;

            debug!("got request for {} IBD blocks", hashes.len());
            let session = self.ctx.consensus().unguarded_session();

            for hash in hashes {
                if let Some(status) = session.async_get_block_status(hash).await {
                    if is_unsafe_block_status_for_network(status) {
                        let reason = format!("refusing to serve unsafe IBD block {} with status {:?}", hash, status);
                        warn!("{}", reason);
                        return Err(ProtocolError::OtherOwned(reason));
                    }
                }
                let block = session.async_get_block(hash).await?;
                self.router.enqueue(make_response!(Payload::IbdBlock, (&block).into(), request_id)).await?;
            }
        }
    }
}
