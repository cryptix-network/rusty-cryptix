//!
//! In v6 the syncee can reconstruct trusted data from the full payload - todo: fix performance
//!
//!

use cryptix_consensus_core::{pruning::PruningPointAtomicState, BlockHashMap};
use cryptix_p2p_lib::{
    common::ProtocolError,
    convert::model::trusted::{
        trusted_atomic_state_chunk_count, TrustedAtomicStateChunk, MAX_TRUSTED_ATOMIC_STATE_BYTES, TRUSTED_ATOMIC_STATE_CHUNK_SIZE,
    },
    dequeue, dequeue_with_request_id, make_response,
    pb::{
        self, cryptixd_message::Payload, BlockWithTrustedDataV4Message, DoneBlocksWithTrustedDataMessage, PruningPointsMessage,
        TrustedDataMessage,
    },
    IncomingRoute, Router,
};
use itertools::Itertools;
use log::debug;
use std::sync::Arc;

use crate::{flow_context::FlowContext, flow_trait::Flow, v5::ibd::IBD_BATCH_SIZE};

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
            debug!("Got request for pruning point and its anticone");

            let consensus = self.ctx.consensus();
            let mut session = consensus.session().await;

            let pp_headers = session.async_pruning_point_headers().await;
            let Some(proof_pruning_point_header) = pp_headers.last() else {
                return Err(ProtocolError::Other("cannot serve pruning point data without pruning point headers"));
            };
            let payload_hf_active = proof_pruning_point_header.daa_score >= self.ctx.config.params.payload_hf_activation_daa_score;
            self.router
                .enqueue(make_response!(
                    Payload::PruningPoints,
                    PruningPointsMessage { headers: pp_headers.iter().map(|header| <pb::BlockHeader>::from(&**header)).collect() },
                    request_id
                ))
                .await?;

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
            let (atomic_consensus_state_hash, atomic_consensus_state_byte_length, atomic_consensus_state_chunk_count) =
                match atomic_state {
                    Some(state) => {
                        let byte_length = state.serialized_state.len() as u64;
                        if byte_length == 0 {
                            return Err(ProtocolError::Other("pruning-point atomic state must not be empty"));
                        }
                        if byte_length > MAX_TRUSTED_ATOMIC_STATE_BYTES {
                            return Err(ProtocolError::OtherOwned(format!(
                                "pruning-point atomic state size {} exceeds transfer limit {}",
                                byte_length, MAX_TRUSTED_ATOMIC_STATE_BYTES
                            )));
                        }
                        (state.state_hash.to_vec(), byte_length, trusted_atomic_state_chunk_count(byte_length))
                    }
                    None => (Vec::new(), 0, 0),
                };
            self.router
                .enqueue(make_response!(
                    Payload::TrustedData,
                    TrustedDataMessage {
                        daa_window: daa_window.iter().map(|daa_block| daa_block.into()).collect_vec(),
                        ghostdag_data: ghostdag_data.iter().map(|gd| gd.into()).collect_vec(),
                        atomic_consensus_state: Vec::new(),
                        atomic_consensus_state_hash,
                        atomic_consensus_state_byte_length,
                        atomic_consensus_state_chunk_count,
                    },
                    request_id
                ))
                .await?;
            if let Some(state) = atomic_state {
                self.send_atomic_state_chunks(state, request_id).await?;
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
            debug!("Finished sending pruning point anticone")
        }
    }

    async fn send_atomic_state_chunks(&mut self, state: &PruningPointAtomicState, request_id: u32) -> Result<(), ProtocolError> {
        let total_bytes = state.serialized_state.len() as u64;
        let total_chunks = trusted_atomic_state_chunk_count(total_bytes);
        for (chunk_index, chunk) in state.serialized_state.chunks(TRUSTED_ATOMIC_STATE_CHUNK_SIZE).enumerate() {
            let chunk_index = chunk_index as u64;
            let chunk_msg: pb::TrustedAtomicStateChunkMessage =
                TrustedAtomicStateChunk::new(state.state_hash, chunk_index, total_chunks, total_bytes, chunk.to_vec()).into();
            self.router.enqueue(make_response!(Payload::TrustedAtomicStateChunk, chunk_msg, request_id)).await?;

            if (chunk_index + 1) % IBD_BATCH_SIZE as u64 == 0 && chunk_index + 1 < total_chunks {
                dequeue!(self.incoming_route, Payload::RequestNextPruningPointAtomicStateChunk)?;
            }
        }
        debug!("Finished sending pruning point atomic state in {} chunks", total_chunks);
        Ok(())
    }
}
