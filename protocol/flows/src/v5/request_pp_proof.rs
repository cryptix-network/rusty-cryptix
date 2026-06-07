use std::{sync::Arc, time::Instant};

use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue_with_request_id, make_response,
    pb::{cryptixd_message::Payload, PruningPointProofMessage},
    IncomingRoute, Router,
};
use log::{debug, info};

use crate::{flow_context::FlowContext, flow_trait::Flow};

pub struct RequestPruningPointProofFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for RequestPruningPointProofFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestPruningPointProofFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (_, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestPruningPointProof)?;
            let request_started = Instant::now();
            info!("Got pruning point proof request from {}", self.router);
            let proof = self.ctx.consensus().unguarded_session().async_get_pruning_point_proof().await;
            let header_count = proof.iter().map(|headers| headers.len()).sum::<usize>();
            debug!("Built pruning point proof with {} headers", header_count);
            self.router
                .enqueue(make_response!(
                    Payload::PruningPointProof,
                    PruningPointProofMessage { headers: proof.iter().map(|headers| headers.into()).collect() },
                    request_id
                ))
                .await?;
            info!(
                "Queued pruning point proof to {} with {} headers in {} ms",
                self.router,
                header_count,
                request_started.elapsed().as_millis()
            );
        }
    }
}
