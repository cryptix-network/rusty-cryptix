use crate::{flow_context::FlowContext, flow_trait::Flow};
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue,
    pb::{cryptixd_message::Payload, BlockProducerClaimV1Message},
    IncomingRoute, Router,
};
use std::sync::Arc;

pub struct StrongNodeClaimsRelayFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for StrongNodeClaimsRelayFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl StrongNodeClaimsRelayFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let payload: BlockProducerClaimV1Message = dequeue!(self.incoming_route, Payload::BlockProducerClaimV1)?;
            self.ctx.handle_block_producer_claim(&self.router, payload).await;
        }
    }
}
