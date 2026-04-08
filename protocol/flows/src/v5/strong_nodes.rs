use crate::{flow_context::FlowContext, flow_trait::Flow};
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue,
    pb::{cryptixd_message::Payload, StrongNodeAnnouncementMessage},
    IncomingRoute, Router,
};
use std::sync::Arc;

pub struct StrongNodesRelayFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for StrongNodesRelayFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl StrongNodesRelayFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let payload: StrongNodeAnnouncementMessage = dequeue!(self.incoming_route, Payload::StrongNodeAnnouncement)?;
            self.ctx.handle_strong_node_announcement(&self.router, payload).await;
        }
    }
}
