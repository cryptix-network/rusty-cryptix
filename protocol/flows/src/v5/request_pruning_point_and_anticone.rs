use std::{sync::Arc, time::Instant};

use cryptix_consensus_core::BlockHashMap;
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue, dequeue_with_request_id, make_response,
    pb::{
        self, cryptixd_message::Payload, BlockWithTrustedDataV4Message, DoneBlocksWithTrustedDataMessage, PruningPointsMessage,
        TrustedAtomicStateChunkMessage, TrustedDataMessage,
    },
    IncomingRoute, Router,
};
use itertools::Itertools;
use log::{debug, info};

use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    v5::ibd::{trusted_atomic_state_chunk_count, IBD_BATCH_SIZE, TRUSTED_ATOMIC_STATE_CHUNK_SIZE},
};

pub struct PruningPointAndItsAnticoneRequestsFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for PruningPointAndItsAnticoneRequestsFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl PruningPointAndItsAnticoneRequestsFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (_, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestPruningPointAndItsAnticone)?;
            let request_started = Instant::now();
            info!("Got request for pruning point and its anticone from {}", self.router);

            let consensus = self.ctx.consensus();
            let mut session = consensus.session().await;

            let pp_headers = session.async_pruning_point_headers().await;
            let Some(proof_pruning_point_header) = pp_headers.last() else {
                return Err(ProtocolError::Other("cannot serve pruning point data without pruning point headers"));
            };
            let payload_hf_active = proof_pruning_point_header.daa_score >= self.ctx.config.params.payload_hf_activation_daa_score;
            info!(
                "Serving {} pruning point headers to {} (pruning_point={} daa={})",
                pp_headers.len(),
                self.router,
                proof_pruning_point_header.hash,
                proof_pruning_point_header.daa_score
            );
            self.router
                .enqueue(make_response!(
                    Payload::PruningPoints,
                    PruningPointsMessage { headers: pp_headers.iter().map(|header| <pb::BlockHeader>::from(&**header)).collect() },
                    request_id
                ))
                .await?;

            let trusted_data_started = Instant::now();
            info!("Preparing pruning point anticone and trusted data for {}", self.router);
            let trusted_data = session.async_get_pruning_point_anticone_and_trusted_data().await?;
            let pp_anticone = &trusted_data.anticone;
            let daa_window = &trusted_data.daa_window_blocks;
            let ghostdag_data = &trusted_data.ghostdag_blocks;
            let atomic_state = if payload_hf_active {
                trusted_data.atomic_state.as_ref()
            } else {
                if trusted_data.atomic_state.is_some() {
                    debug!("Skipping pre-HF pruning-point atomic state transfer; peer reconstructs it from the UTXO set");
                }
                None
            };
            let (
                atomic_consensus_state_hash,
                atomic_state_bytes,
                atomic_consensus_state_byte_length,
                atomic_consensus_state_chunk_count,
            ) = match atomic_state {
                Some(state) => {
                    let state_bytes = state.state_bytes.clone().ok_or(ProtocolError::Other(
                        "cannot serve post-HF pruning-point data without full atomic consensus state bytes",
                    ))?;
                    let byte_length = state_bytes.len() as u64;
                    let chunk_count = trusted_atomic_state_chunk_count(byte_length);
                    (state.state_hash.to_vec(), state_bytes, byte_length, chunk_count)
                }
                None => (Vec::new(), Vec::new(), 0, 0),
            };
            info!(
                "Prepared pruning point anticone and trusted data for {}: anticone_blocks={}, daa_window={}, ghostdag={}, atomic_state_chunks={}, atomic_state_bytes={} in {} ms",
                self.router,
                pp_anticone.len(),
                daa_window.len(),
                ghostdag_data.len(),
                atomic_consensus_state_chunk_count,
                atomic_consensus_state_byte_length,
                trusted_data_started.elapsed().as_millis()
            );
            self.router
                .enqueue(make_response!(
                    Payload::TrustedData,
                    TrustedDataMessage {
                        daa_window: daa_window.iter().map(|daa_block| daa_block.into()).collect_vec(),
                        ghostdag_data: ghostdag_data.iter().map(|gd| gd.into()).collect_vec(),
                        atomic_consensus_state: Vec::new(),
                        atomic_consensus_state_hash: atomic_consensus_state_hash.clone(),
                        atomic_consensus_state_byte_length,
                        atomic_consensus_state_chunk_count,
                    },
                    request_id
                ))
                .await?;

            if !atomic_state_bytes.is_empty() {
                self.send_trusted_atomic_state_chunks(&atomic_consensus_state_hash, &atomic_state_bytes, request_id).await?;
            }

            let daa_window_hash_to_index =
                BlockHashMap::from_iter(daa_window.iter().enumerate().map(|(i, trusted_header)| (trusted_header.header.hash, i)));
            let ghostdag_data_hash_to_index =
                BlockHashMap::from_iter(ghostdag_data.iter().enumerate().map(|(i, trusted_gd)| (trusted_gd.hash, i)));

            for hashes in pp_anticone.chunks(IBD_BATCH_SIZE) {
                for hash in hashes {
                    let hash = *hash;
                    let daa_window_indices = session
                        .async_get_daa_window(hash)
                        .await?
                        .into_iter()
                        .map(|hash| *daa_window_hash_to_index.get(&hash).unwrap() as u64)
                        .collect_vec();
                    let ghostdag_data_indices = session
                        .async_get_trusted_block_associated_ghostdag_data_block_hashes(hash)
                        .await?
                        .into_iter()
                        .map(|hash| *ghostdag_data_hash_to_index.get(&hash).unwrap() as u64)
                        .collect_vec();
                    let block = session.async_get_block(hash).await?;
                    self.router
                        .enqueue(make_response!(
                            Payload::BlockWithTrustedDataV4,
                            BlockWithTrustedDataV4Message { block: Some((&block).into()), daa_window_indices, ghostdag_data_indices },
                            request_id
                        ))
                        .await?;
                }

                if hashes.len() == IBD_BATCH_SIZE {
                    // No timeout here, as we don't care if the syncee takes its time computing,
                    // since it only blocks this dedicated flow
                    drop(session); // Avoid holding the session through dequeue calls
                    dequeue!(self.incoming_route, Payload::RequestNextPruningPointAndItsAnticoneBlocks)?;
                    session = consensus.session().await;
                }
            }

            self.router
                .enqueue(make_response!(Payload::DoneBlocksWithTrustedData, DoneBlocksWithTrustedDataMessage {}, request_id))
                .await?;
            info!(
                "Finished sending pruning point anticone to {}: {} blocks in {} ms",
                self.router,
                pp_anticone.len(),
                request_started.elapsed().as_millis()
            );
        }
    }

    async fn send_trusted_atomic_state_chunks(
        &mut self,
        state_hash: &[u8],
        state_bytes: &[u8],
        request_id: u32,
    ) -> Result<(), ProtocolError> {
        let total_bytes = state_bytes.len() as u64;
        let total_chunks = trusted_atomic_state_chunk_count(total_bytes);
        for (chunk_index, chunk) in state_bytes.chunks(TRUSTED_ATOMIC_STATE_CHUNK_SIZE).enumerate() {
            self.router
                .enqueue(make_response!(
                    Payload::TrustedAtomicStateChunk,
                    TrustedAtomicStateChunkMessage {
                        state_hash: state_hash.to_vec(),
                        chunk_index: chunk_index as u64,
                        total_chunks,
                        total_bytes,
                        chunk: chunk.to_vec(),
                    },
                    request_id
                ))
                .await?;

            let downloaded_chunks = chunk_index as u64 + 1;
            if downloaded_chunks % IBD_BATCH_SIZE as u64 == 0 && downloaded_chunks < total_chunks {
                dequeue!(self.incoming_route, Payload::RequestNextPruningPointAtomicStateChunk)?;
            }
        }
        info!("Finished sending pruning point Atomic state to {} in {} chunk(s)", self.router, total_chunks);
        Ok(())
    }
}
