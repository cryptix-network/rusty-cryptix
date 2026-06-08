use crate::{
    flow_context::FlowContext,
    v5::{
        ibd::{HeadersChunkStream, TrustedEntryStream},
        Flow,
    },
};
use cryptix_consensus_core::{
    api::BlockValidationFuture,
    block::Block,
    header::Header,
    pruning::{PruningPointProof, PruningPointsList},
    BlockHashSet,
};
use cryptix_consensusmanager::{spawn_blocking, ConsensusProxy, StagingConsensus};
use cryptix_core::{debug, info, time::unix_now, warn};
use cryptix_hashes::Hash;
use cryptix_muhash::MuHash;
use cryptix_p2p_lib::{
    common::ProtocolError,
    convert::model::trusted::TrustedDataPackage,
    dequeue_with_timeout, make_message,
    pb::{
        cryptixd_message::Payload, RequestAntipastMessage, RequestHeadersMessage, RequestIbdBlocksMessage,
        RequestNextPruningPointAtomicStateChunkMessage, RequestPruningPointAndItsAnticoneMessage, RequestPruningPointProofMessage,
        RequestPruningPointUtxoSetMessage,
    },
    IncomingRoute, Router,
};
use cryptix_utils::channel::JobReceiver;
use futures::future::{join_all, select, try_join_all, Either};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::sleep;

use super::{
    progress::ProgressReporter, trusted_atomic_state_chunk_count, HeadersChunk, PruningPointUtxosetChunkStream, IBD_BATCH_SIZE,
    MAX_IMPORTED_ATOMIC_STATE_BYTES, TRUSTED_ATOMIC_STATE_CHUNK_SIZE,
};

/// Flow for managing IBD - Initial Block Download
pub struct IbdFlow {
    pub(super) ctx: FlowContext,
    pub(super) router: Arc<Router>,
    pub(super) incoming_route: IncomingRoute,

    // Receives relay blocks from relay flow which are out of orphan resolution range and hence trigger IBD
    relay_receiver: JobReceiver<Block>,
}

#[async_trait::async_trait]
impl Flow for IbdFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

pub enum IbdType {
    None,
    Sync(Hash),
    DownloadHeadersProof,
}

const ERR_PROOF_PRUNING_POINT_ALREADY_CURRENT: &str = "the proof pruning point is the same as the current pruning point";

struct QueueChunkOutput {
    jobs: Vec<BlockValidationFuture>,
    daa_score: u64,
    timestamp: u64,
}
// TODO: define a peer banning strategy

impl IbdFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute, relay_receiver: JobReceiver<Block>) -> Self {
        Self { ctx, router, incoming_route, relay_receiver }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        while let Ok(relay_block) = self.relay_receiver.recv().await {
            if let Some(_guard) = self.ctx.try_set_ibd_running(self.router.key(), relay_block.header.daa_score) {
                info!("IBD started with peer {}", self.router);

                let result = self.ibd(relay_block).await;
                cryptix_alloc::collect_allocator(true);
                match result {
                    Ok(_) => info!("IBD with peer {} completed successfully; allocator collection requested", self.router),
                    Err(e) => {
                        info!("IBD with peer {} completed with error: {}; allocator collection requested", self.router, e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn ibd(&mut self, relay_block: Block) -> Result<(), ProtocolError> {
        let mut session = self.ctx.consensus().session().await;

        let negotiation_output = self.negotiate_missing_syncer_chain_segment(&session).await?;
        let ibd_type =
            self.determine_ibd_type(&session, &relay_block.header, negotiation_output.highest_known_syncer_chain_hash).await?;
        match ibd_type {
            IbdType::None => {
                return Err(ProtocolError::Other("peer has no known block and conditions for requesting headers proof are not met"))
            }
            IbdType::Sync(highest_known_syncer_chain_hash) => {
                self.sync_headers(
                    &session,
                    negotiation_output.syncer_virtual_selected_parent,
                    highest_known_syncer_chain_hash,
                    &relay_block,
                )
                .await?;
            }
            IbdType::DownloadHeadersProof => {
                drop(session); // Avoid holding the previous consensus throughout the staging IBD
                let staging = self.ctx.consensus_manager.new_staging_consensus();
                match self.ibd_with_headers_proof(&staging, negotiation_output.syncer_virtual_selected_parent, &relay_block).await {
                    Ok(()) => {
                        spawn_blocking(|| staging.commit()).await.unwrap();
                        info!(
                            "Header download stage of IBD with headers proof completed successfully from {}. Committed staging consensus.",
                            self.router
                        );
                        self.ctx.on_pruning_point_utxoset_override();
                        // This will reobtain the freshly committed staging consensus
                        session = self.ctx.consensus().session().await;
                    }
                    Err(e) => {
                        staging.cancel();
                        if matches!(&e, ProtocolError::Other(ERR_PROOF_PRUNING_POINT_ALREADY_CURRENT)) {
                            session = self.ctx.consensus().session().await;
                            let current_pruning_point = session.async_pruning_point().await;
                            info!(
                                "IBD headers proof from {} points at the current pruning point {}; continuing header/body sync on the active consensus",
                                self.router, current_pruning_point
                            );
                            self.sync_headers(
                                &session,
                                negotiation_output.syncer_virtual_selected_parent,
                                current_pruning_point,
                                &relay_block,
                            )
                            .await?;
                        } else {
                            info!("IBD with headers proof from {} was unsuccessful ({})", self.router, e);
                            return Err(e);
                        }
                    }
                }
            }
        }

        // Sync missing bodies in the past of syncer sink (virtual selected parent)
        self.sync_missing_block_bodies(&session, negotiation_output.syncer_virtual_selected_parent).await?;

        // Relay block might be in the antipast of syncer sink, thus
        // check its past for missing bodies as well.
        self.sync_missing_block_bodies(&session, relay_block.hash()).await?;

        // Following IBD we revalidate orphans since many of them might have been processed during the IBD
        // or are now processable
        let (queued_hashes, virtual_processing_tasks) = self.ctx.revalidate_orphans(&session).await;
        let mut unorphaned_hashes = Vec::with_capacity(queued_hashes.len());
        let results = join_all(virtual_processing_tasks).await;
        for (hash, result) in queued_hashes.into_iter().zip(results) {
            match result {
                Ok(_) => unorphaned_hashes.push(hash),
                // We do not return the error and disconnect here since we don't know
                // that this peer was the origin of the orphan block
                Err(e) => warn!("Validation failed for orphan block {}: {}", hash, e),
            }
        }
        match unorphaned_hashes.len() {
            0 => {}
            n => info!("IBD post processing: unorphaned {} blocks ...{}", n, unorphaned_hashes.last().unwrap()),
        }

        match self.ctx.repair_atomic_index_once().await {
            Ok(true) => info!("IBD post processing: verified AtomicIndex snapshot repair completed"),
            Ok(false) => {}
            Err(err) => warn!(
                "IBD post processing: verified AtomicIndex snapshot repair is not available yet ({}); bootstrap service will retry",
                err
            ),
        }

        Ok(())
    }

    async fn determine_ibd_type(
        &self,
        consensus: &ConsensusProxy,
        relay_header: &Header,
        highest_known_syncer_chain_hash: Option<Hash>,
    ) -> Result<IbdType, ProtocolError> {
        if let Some(highest_known_syncer_chain_hash) = highest_known_syncer_chain_hash {
            let pruning_point = consensus.async_pruning_point().await;
            if consensus.async_is_chain_ancestor_of(pruning_point, highest_known_syncer_chain_hash).await? {
                // The node is only missing a segment in the future of its current pruning point, and the chains
                // agree as well, so we perform a simple sync IBD and only download the missing data
                return Ok(IbdType::Sync(highest_known_syncer_chain_hash));
            }

            // If the pruning point is not in the chain of `highest_known_syncer_chain_hash`, it
            // means it's in its antichain (because if `highest_known_syncer_chain_hash` was in
            // the pruning point's past the pruning point itself would be
            // `highest_known_syncer_chain_hash`). So it means there's a finality conflict.
            // TODO: consider performing additional actions on finality conflicts in addition to disconnecting from the peer (e.g., banning, rpc notification)
            return Ok(IbdType::None);
        }

        let hst_header = consensus.async_get_header(consensus.async_get_headers_selected_tip().await).await.unwrap();
        if relay_header.blue_score >= hst_header.blue_score + self.ctx.config.pruning_depth
            && relay_header.blue_work > hst_header.blue_work
        {
            if unix_now() > consensus.async_creation_timestamp().await + self.ctx.config.finality_duration() {
                let fp = consensus.async_finality_point().await;
                let fp_ts = consensus.async_get_header(fp).await?.timestamp;
                if unix_now() < fp_ts + self.ctx.config.finality_duration() * 3 / 2 {
                    // We reject the headers proof if the node has a relatively up-to-date finality point and current
                    // consensus has matured for long enough (and not recently synced). This is mostly a spam-protector
                    // since subsequent checks identify these violations as well
                    // TODO: consider performing additional actions on finality conflicts in addition to disconnecting from the peer (e.g., banning, rpc notification)
                    return Ok(IbdType::None);
                }
            }

            // The relayed block has sufficient blue score and blue work over the current header selected tip
            Ok(IbdType::DownloadHeadersProof)
        } else {
            Ok(IbdType::None)
        }
    }

    async fn ibd_with_headers_proof(
        &mut self,
        staging: &StagingConsensus,
        syncer_virtual_selected_parent: Hash,
        relay_block: &Block,
    ) -> Result<(), ProtocolError> {
        info!("Starting IBD with headers proof with peer {}", self.router);

        let staging_session = staging.session().await;

        let pruning_point = self.sync_and_validate_pruning_proof(&staging_session).await?;
        self.sync_headers(&staging_session, syncer_virtual_selected_parent, pruning_point, relay_block).await?;
        staging_session.async_validate_pruning_points().await?;
        self.validate_staging_timestamps(&self.ctx.consensus().session().await, &staging_session).await?;
        self.sync_pruning_point_utxoset(&staging_session, pruning_point).await?;
        Ok(())
    }

    async fn sync_and_validate_pruning_proof(&mut self, staging: &ConsensusProxy) -> Result<Hash, ProtocolError> {
        self.router.enqueue(make_message!(Payload::RequestPruningPointProof, RequestPruningPointProofMessage {})).await?;
        let proof_wait_log_interval = Duration::from_secs(15 * 60);
        let proof_wait_started = Instant::now();
        info!(
            "IBD requested pruning point proof from {}; waiting with {} second progress interval",
            self.router,
            proof_wait_log_interval.as_secs()
        );

        // Pruning proof generation and communication can take many minutes on slow peers after a cold start.
        // Keep the session alive across progress intervals so a late proof is still accepted.
        let msg = loop {
            match dequeue_with_timeout!(self.incoming_route, Payload::PruningPointProof, proof_wait_log_interval) {
                Ok(msg) => break msg,
                Err(ProtocolError::Timeout(_)) => {
                    warn!(
                        "IBD is still waiting for pruning point proof from {} after {}; keeping the session open",
                        self.router,
                        format!("{}s", proof_wait_started.elapsed().as_secs())
                    );
                }
                Err(err) => return Err(err),
            }
        };
        let proof_msg_levels = msg.headers.len();
        let proof_msg_header_count = msg.headers.iter().map(|level| level.headers.len()).sum::<usize>();
        info!(
            "IBD dequeued pruning point proof message from {} with {} levels and {} headers after {} ms; converting",
            self.router,
            proof_msg_levels,
            proof_msg_header_count,
            proof_wait_started.elapsed().as_millis()
        );
        let proof: PruningPointProof = msg.try_into()?;
        let proof_header_count = proof.iter().map(|l| l.len()).sum::<usize>();
        info!(
            "IBD converted pruning point proof from {} with {} headers after {} ms; validating",
            self.router,
            proof_header_count,
            proof_wait_started.elapsed().as_millis()
        );

        // Get a new session for current consensus (non staging)
        let consensus = self.ctx.consensus().session().await;

        // The proof is validated in the context of current consensus
        let proof = consensus.clone().spawn_blocking(move |c| c.validate_pruning_proof(&proof).map(|()| proof)).await?;

        let proof_pruning_point_header = proof[0].last().expect("was just ensured by validation");
        let proof_pruning_point = proof_pruning_point_header.hash;
        let proof_pruning_point_daa_score = proof_pruning_point_header.daa_score;
        info!(
            "IBD validated pruning point proof from {}; pruning_point={} daa={}",
            self.router, proof_pruning_point, proof_pruning_point_daa_score
        );

        if proof_pruning_point == self.ctx.config.genesis.hash {
            return Err(ProtocolError::Other("the proof pruning point is the genesis block"));
        }

        if proof_pruning_point == consensus.async_pruning_point().await {
            return Err(ProtocolError::Other(ERR_PROOF_PRUNING_POINT_ALREADY_CURRENT));
        }

        drop(consensus);

        self.router
            .enqueue(make_message!(Payload::RequestPruningPointAndItsAnticone, RequestPruningPointAndItsAnticoneMessage {}))
            .await?;
        let trusted_data_wait_started = Instant::now();
        info!("IBD requested pruning point anticone and trusted data from {}", self.router);

        let msg = dequeue_with_timeout!(self.incoming_route, Payload::PruningPoints)?;
        let pruning_points: PruningPointsList = msg.try_into()?;
        info!(
            "IBD received {} pruning point headers from {} after {} ms",
            pruning_points.len(),
            self.router,
            trusted_data_wait_started.elapsed().as_millis()
        );

        if pruning_points.is_empty() || pruning_points.last().unwrap().hash != proof_pruning_point {
            return Err(ProtocolError::Other("the proof pruning point is not equal to the last pruning point in the list"));
        }

        if pruning_points.first().unwrap().hash != self.ctx.config.genesis.hash {
            return Err(ProtocolError::Other("the first pruning point in the list is expected to be genesis"));
        }

        // Check if past pruning points violate finality of current consensus
        if self.ctx.consensus().session().await.async_are_pruning_points_violating_finality(pruning_points.clone()).await {
            // TODO: consider performing additional actions on finality conflicts in addition to disconnecting from the peer (e.g., banning, rpc notification)
            return Err(ProtocolError::Other("pruning points are violating finality"));
        }

        let msg = dequeue_with_timeout!(self.incoming_route, Payload::TrustedData)?;
        let mut pkg: TrustedDataPackage = msg.try_into()?;
        info!(
            "IBD received trusted data from {} with {} daa entries, {} ghostdag entries, {} Atomic state chunks ({} bytes) after {} ms",
            self.router,
            pkg.daa_window.len(),
            pkg.ghostdag_window.len(),
            pkg.atomic_state_chunk_count,
            pkg.atomic_state_byte_length,
            trusted_data_wait_started.elapsed().as_millis()
        );
        let pruning_point_atomic_state =
            self.receive_pruning_point_atomic_state(&mut pkg, proof_pruning_point, proof_pruning_point_daa_score).await?;

        let mut entry_stream = TrustedEntryStream::new(&self.router, &mut self.incoming_route);
        let Some(pruning_point_entry) = entry_stream.next().await? else {
            return Err(ProtocolError::Other("got `done` message before receiving the pruning point"));
        };

        if pruning_point_entry.block.hash() != proof_pruning_point {
            return Err(ProtocolError::Other("the proof pruning point is not equal to the expected trusted entry"));
        }

        let mut entries = vec![pruning_point_entry];
        while let Some(entry) = entry_stream.next().await? {
            entries.push(entry);
        }

        let mut trusted_set = pkg.build_trusted_subdag(entries)?;

        if self.ctx.config.enable_sanity_checks {
            let con = self.ctx.consensus().unguarded_session_blocking();
            trusted_set = staging
                .clone()
                .spawn_blocking(move |c| {
                    let ref_proof = proof.clone();
                    c.apply_pruning_proof(proof, &trusted_set)?;
                    c.import_pruning_points(pruning_points);

                    info!("Building the proof which was just applied (sanity test)");
                    let built_proof = c.get_pruning_point_proof();
                    let mut mismatch_detected = false;
                    for (i, (ref_level, built_level)) in ref_proof.iter().zip(built_proof.iter()).enumerate() {
                        if ref_level.iter().map(|h| h.hash).collect::<BlockHashSet>()
                            != built_level.iter().map(|h| h.hash).collect::<BlockHashSet>()
                        {
                            mismatch_detected = true;
                            warn!("Locally built proof for level {} does not match the applied one", i);
                        }
                    }
                    if mismatch_detected {
                        info!("Validating the locally built proof (sanity test fallback #2)");
                        // Note: the proof is validated in the context of *current* consensus
                        if let Err(err) = con.validate_pruning_proof(&built_proof) {
                            panic!("Locally built proof failed validation: {}", err);
                        }
                        info!("Locally built proof was validated successfully");
                    } else {
                        info!("Proof was locally built successfully");
                    }
                    Result::<_, ProtocolError>::Ok(trusted_set)
                })
                .await?;
        } else {
            trusted_set = staging
                .clone()
                .spawn_blocking(move |c| {
                    c.apply_pruning_proof(proof, &trusted_set)?;
                    c.import_pruning_points(pruning_points);
                    Result::<_, ProtocolError>::Ok(trusted_set)
                })
                .await?;
        }

        // TODO: add logs to staging commit process

        info!("Starting to process {} trusted blocks", trusted_set.len());
        let mut last_time = Instant::now();
        let mut last_index: usize = 0;
        for (i, tb) in trusted_set.into_iter().enumerate() {
            let now = Instant::now();
            let passed = now.duration_since(last_time);
            if passed > Duration::from_secs(1) {
                info!("Processed {} trusted blocks in the last {:.2}s (total {})", i - last_index, passed.as_secs_f64(), i);
                last_time = now;
                last_index = i;
            }
            // TODO: queue and join in batches
            staging.validate_and_insert_trusted_block(tb).virtual_state_task.await?;
        }
        info!("Done processing trusted blocks");

        if let Some(atomic_state) = pruning_point_atomic_state {
            staging.clone().spawn_blocking(move |c| c.import_pruning_point_atomic_state(proof_pruning_point, atomic_state)).await?;
            debug!("Imported pruning point atomic consensus state");
        }

        Ok(proof_pruning_point)
    }

    async fn receive_pruning_point_atomic_state(
        &mut self,
        pkg: &mut TrustedDataPackage,
        proof_pruning_point: Hash,
        proof_pruning_point_daa_score: u64,
    ) -> Result<Option<cryptix_consensus_core::pruning::PruningPointAtomicState>, ProtocolError> {
        if proof_pruning_point_daa_score < self.ctx.config.params.payload_hf_activation_daa_score {
            if pkg.atomic_state_hash.is_some() || pkg.atomic_state_byte_length != 0 || pkg.atomic_state_chunk_count != 0 {
                debug!("Ignoring pre-HF pruning-point atomic state; consensus reconstructs it from the imported UTXO set");
            }
            if let Some(state_hash) = pkg.atomic_state_hash {
                if pkg.atomic_state_byte_length != 0 || pkg.atomic_state_chunk_count != 0 {
                    self.drain_trusted_atomic_state_chunks(state_hash, pkg.atomic_state_byte_length, pkg.atomic_state_chunk_count)
                        .await?;
                }
            }
            pkg.atomic_state.take();
            return Ok(None);
        }

        let Some(state_hash) = pkg.atomic_state_hash else {
            return Err(ProtocolError::Other("post-HF pruning-point trusted data is missing atomic consensus state hash"));
        };

        // Use the DAA from the validated proof header; the pruning-point header may not be in the local store yet during IBD.
        if let Err(err) = self
            .ctx
            .verify_consensus_atomic_state_hash_quorum_at_daa(proof_pruning_point, state_hash, proof_pruning_point_daa_score)
            .await
        {
            if self.ctx.config.net.is_mainnet() {
                return Err(ProtocolError::OtherOwned(format!(
                    "post-HF pruning-point Atomic state hash quorum failed for {} from peer {}; refusing to import Atomic state from a single peer on mainnet ({})",
                    proof_pruning_point, self.router, err
                )));
            } else {
                let message = format!(
                    "P2P pruning-point atomic root quorum check unavailable for {} from peer {}; continuing with trusted-data root and validating it against the pruning-point commitment on non-mainnet ({})",
                    proof_pruning_point, self.router, err
                );
                if Self::should_warn_pruning_point_atomic_quorum_check_error(&err) {
                    warn!("{message}");
                } else {
                    debug!("{message}");
                }
            }
        }

        if let Some(inline_state) = pkg.atomic_state.take() {
            if inline_state.state_hash != state_hash {
                return Err(ProtocolError::Other("inline pruning-point atomic state hash metadata mismatch"));
            }
            if inline_state.state_bytes.is_none() {
                return Err(ProtocolError::Other(
                    "post-HF pruning-point trusted data carries only an atomic root; full atomic state bytes are required",
                ));
            }
            return Ok(Some(inline_state));
        }

        if pkg.atomic_state_byte_length != 0 || pkg.atomic_state_chunk_count != 0 {
            let state_bytes = self
                .receive_trusted_atomic_state_chunks(state_hash, pkg.atomic_state_byte_length, pkg.atomic_state_chunk_count)
                .await?;
            return Ok(Some(cryptix_consensus_core::pruning::PruningPointAtomicState { state_hash, state_bytes: Some(state_bytes) }));
        }

        Err(ProtocolError::Other("post-HF pruning-point trusted data is missing full atomic consensus state bytes"))
    }

    fn should_warn_pruning_point_atomic_quorum_check_error(err: &str) -> bool {
        err.contains("quorum selected") || err.contains("refusing mainnet")
    }

    async fn receive_trusted_atomic_state_chunks(
        &mut self,
        state_hash: [u8; 32],
        total_bytes: u64,
        total_chunks: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.validate_trusted_atomic_state_metadata(total_bytes, total_chunks)?;

        let initial_capacity = (total_bytes as usize).min(TRUSTED_ATOMIC_STATE_CHUNK_SIZE);
        let mut state_bytes = Vec::with_capacity(initial_capacity);
        for expected_chunk_index in 0..total_chunks {
            let msg = dequeue_with_timeout!(
                self.incoming_route,
                Payload::TrustedAtomicStateChunk,
                cryptix_p2p_lib::common::DEFAULT_TIMEOUT
            )?;
            self.validate_trusted_atomic_state_chunk(
                &msg,
                state_hash,
                expected_chunk_index,
                total_chunks,
                total_bytes,
                state_bytes.len() as u64,
            )?;
            state_bytes.extend_from_slice(&msg.chunk);

            let downloaded_chunks = expected_chunk_index + 1;
            if downloaded_chunks % IBD_BATCH_SIZE as u64 == 0 && downloaded_chunks < total_chunks {
                info!("Downloaded {} pruning point Atomic state chunks from {}", downloaded_chunks, self.router);
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointAtomicStateChunk,
                        RequestNextPruningPointAtomicStateChunkMessage {}
                    ))
                    .await?;
            }
        }

        if state_bytes.len() as u64 != total_bytes {
            return Err(ProtocolError::Other("pruning point Atomic state size mismatch"));
        }
        info!("Finished receiving pruning point Atomic state from {}: {} bytes in {} chunks", self.router, total_bytes, total_chunks);
        Ok(state_bytes)
    }

    async fn drain_trusted_atomic_state_chunks(
        &mut self,
        state_hash: [u8; 32],
        total_bytes: u64,
        total_chunks: u64,
    ) -> Result<(), ProtocolError> {
        self.validate_trusted_atomic_state_metadata(total_bytes, total_chunks)?;

        let mut downloaded_bytes = 0u64;
        for expected_chunk_index in 0..total_chunks {
            let msg = dequeue_with_timeout!(
                self.incoming_route,
                Payload::TrustedAtomicStateChunk,
                cryptix_p2p_lib::common::DEFAULT_TIMEOUT
            )?;
            self.validate_trusted_atomic_state_chunk(
                &msg,
                state_hash,
                expected_chunk_index,
                total_chunks,
                total_bytes,
                downloaded_bytes,
            )?;
            downloaded_bytes = downloaded_bytes.saturating_add(msg.chunk.len() as u64);

            let downloaded_chunks = expected_chunk_index + 1;
            if downloaded_chunks % IBD_BATCH_SIZE as u64 == 0 && downloaded_chunks < total_chunks {
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointAtomicStateChunk,
                        RequestNextPruningPointAtomicStateChunkMessage {}
                    ))
                    .await?;
            }
        }
        Ok(())
    }

    fn validate_trusted_atomic_state_metadata(&self, total_bytes: u64, total_chunks: u64) -> Result<(), ProtocolError> {
        if total_bytes == 0 || total_chunks == 0 {
            return Err(ProtocolError::Other("invalid pruning point Atomic state chunk metadata"));
        }
        if total_bytes > MAX_IMPORTED_ATOMIC_STATE_BYTES {
            return Err(ProtocolError::Other("pruning point Atomic state exceeds maximum import size"));
        }
        let expected_chunks = trusted_atomic_state_chunk_count(total_bytes);
        if total_chunks != expected_chunks {
            return Err(ProtocolError::Other("invalid pruning point Atomic state chunk count"));
        }
        Ok(())
    }

    fn validate_trusted_atomic_state_chunk(
        &self,
        chunk: &cryptix_p2p_lib::pb::TrustedAtomicStateChunkMessage,
        state_hash: [u8; 32],
        expected_chunk_index: u64,
        total_chunks: u64,
        total_bytes: u64,
        downloaded_bytes: u64,
    ) -> Result<(), ProtocolError> {
        if chunk.state_hash.as_slice() != &state_hash[..] {
            return Err(ProtocolError::Other("pruning point Atomic state chunk hash mismatch"));
        }
        if chunk.chunk_index != expected_chunk_index {
            return Err(ProtocolError::Other("unexpected pruning point Atomic state chunk index"));
        }
        if chunk.total_chunks != total_chunks || chunk.total_bytes != total_bytes {
            return Err(ProtocolError::Other("pruning point Atomic state chunk metadata mismatch"));
        }
        if chunk.chunk.is_empty() || chunk.chunk.len() > TRUSTED_ATOMIC_STATE_CHUNK_SIZE {
            return Err(ProtocolError::Other("invalid pruning point Atomic state chunk size"));
        }
        let remaining =
            total_bytes.checked_sub(downloaded_bytes).ok_or(ProtocolError::Other("pruning point Atomic state chunk overflow"))?;
        let expected_len = remaining.min(TRUSTED_ATOMIC_STATE_CHUNK_SIZE as u64) as usize;
        if chunk.chunk.len() != expected_len {
            return Err(ProtocolError::Other("unexpected pruning point Atomic state chunk length"));
        }
        Ok(())
    }

    async fn sync_headers(
        &mut self,
        consensus: &ConsensusProxy,
        syncer_virtual_selected_parent: Hash,
        highest_known_syncer_chain_hash: Hash,
        relay_block: &Block,
    ) -> Result<(), ProtocolError> {
        let highest_shared_header_score = consensus.async_get_header(highest_known_syncer_chain_hash).await?.daa_score;
        let mut progress_reporter = ProgressReporter::new(highest_shared_header_score, relay_block.header.daa_score, "block headers");

        self.router
            .enqueue(make_message!(
                Payload::RequestHeaders,
                RequestHeadersMessage {
                    low_hash: Some(highest_known_syncer_chain_hash.into()),
                    high_hash: Some(syncer_virtual_selected_parent.into())
                }
            ))
            .await?;
        let mut chunk_stream = HeadersChunkStream::new(&self.router, &mut self.incoming_route);

        if let Some(chunk) = chunk_stream.next().await? {
            let (mut prev_daa_score, mut prev_timestamp) = {
                let last_header = chunk.last().expect("chunk is never empty");
                (last_header.daa_score, last_header.timestamp)
            };
            let mut prev_jobs: Vec<BlockValidationFuture> =
                chunk.into_iter().map(|h| consensus.validate_and_insert_block(Block::from_header_arc(h)).virtual_state_task).collect();

            while let Some(chunk) = chunk_stream.next().await? {
                let (current_daa_score, current_timestamp) = {
                    let last_header = chunk.last().expect("chunk is never empty");
                    (last_header.daa_score, last_header.timestamp)
                };
                let current_jobs = chunk
                    .into_iter()
                    .map(|h| consensus.validate_and_insert_block(Block::from_header_arc(h)).virtual_state_task)
                    .collect();
                let prev_chunk_len = prev_jobs.len();
                // Join the previous chunk so that we always concurrently process a chunk and receive another
                try_join_all(prev_jobs).await?;
                // Log the progress
                progress_reporter.report(prev_chunk_len, prev_daa_score, prev_timestamp);
                prev_daa_score = current_daa_score;
                prev_timestamp = current_timestamp;
                prev_jobs = current_jobs;
            }

            let prev_chunk_len = prev_jobs.len();
            try_join_all(prev_jobs).await?;
            progress_reporter.report_completion(prev_chunk_len);
        }

        self.sync_missing_relay_past_headers(consensus, syncer_virtual_selected_parent, relay_block.hash()).await?;

        Ok(())
    }

    async fn sync_missing_relay_past_headers(
        &mut self,
        consensus: &ConsensusProxy,
        syncer_virtual_selected_parent: Hash,
        relay_block_hash: Hash,
    ) -> Result<(), ProtocolError> {
        // Finished downloading syncer selected tip blocks,
        // check if we already have the triggering relay block
        if consensus.async_get_block_status(relay_block_hash).await.is_some() {
            return Ok(());
        }

        // Send a special header request for the sink antipast. This is expected to
        // be a relatively small set since virtual and relay blocks should be close topologically.
        // See server-side handling of `RequestAnticone` for further details.
        self.router
            .enqueue(make_message!(
                Payload::RequestAntipast,
                RequestAntipastMessage {
                    block_hash: Some(syncer_virtual_selected_parent.into()),
                    context_hash: Some(relay_block_hash.into())
                }
            ))
            .await?;

        let msg = dequeue_with_timeout!(self.incoming_route, Payload::BlockHeaders)?;
        let chunk: HeadersChunk = msg.try_into()?;
        let jobs: Vec<BlockValidationFuture> =
            chunk.into_iter().map(|h| consensus.validate_and_insert_block(Block::from_header_arc(h)).virtual_state_task).collect();
        try_join_all(jobs).await?;
        dequeue_with_timeout!(self.incoming_route, Payload::DoneHeaders)?;

        if consensus.async_get_block_status(relay_block_hash).await.is_none() {
            // If the relay block has still not been received, the peer is misbehaving
            Err(ProtocolError::OtherOwned(format!(
                "did not receive relay block {} from peer {} during block download",
                relay_block_hash, self.router
            )))
        } else {
            Ok(())
        }
    }

    async fn validate_staging_timestamps(
        &self,
        consensus: &ConsensusProxy,
        staging_consensus: &ConsensusProxy,
    ) -> Result<(), ProtocolError> {
        let staging_hst = staging_consensus.async_get_header(staging_consensus.async_get_headers_selected_tip().await).await.unwrap();
        let current_hst = consensus.async_get_header(consensus.async_get_headers_selected_tip().await).await.unwrap();
        // If staging is behind current or within 10 minutes ahead of it, then something is wrong and we reject the IBD
        if staging_hst.timestamp < current_hst.timestamp || staging_hst.timestamp - current_hst.timestamp < 600_000 {
            Err(ProtocolError::OtherOwned(format!(
                "The difference between the timestamp of the current selected tip ({}) and the 
staging selected tip ({}) is too small or negative. Aborting IBD...",
                current_hst.timestamp, staging_hst.timestamp
            )))
        } else {
            Ok(())
        }
    }

    async fn sync_pruning_point_utxoset(&mut self, consensus: &ConsensusProxy, pruning_point: Hash) -> Result<(), ProtocolError> {
        self.router
            .enqueue(make_message!(
                Payload::RequestPruningPointUtxoSet,
                RequestPruningPointUtxoSetMessage { pruning_point_hash: Some(pruning_point.into()) }
            ))
            .await?;
        let mut chunk_stream = PruningPointUtxosetChunkStream::new(&self.router, &mut self.incoming_route);
        let mut multiset = MuHash::new();
        while let Some(chunk) = chunk_stream.next().await? {
            multiset = consensus
                .clone()
                .spawn_blocking(move |c| {
                    c.append_imported_pruning_point_utxos(&chunk, &mut multiset);
                    multiset
                })
                .await;
        }
        consensus.clone().spawn_blocking(move |c| c.import_pruning_point_utxo_set(pruning_point, multiset)).await?;
        Ok(())
    }

    async fn sync_missing_block_bodies(&mut self, consensus: &ConsensusProxy, high: Hash) -> Result<(), ProtocolError> {
        // TODO: query consensus in batches
        let sleep_task = sleep(Duration::from_secs(2));
        let hashes_task = consensus.async_get_missing_block_body_hashes(high);
        tokio::pin!(sleep_task);
        tokio::pin!(hashes_task);
        let hashes = match select(sleep_task, hashes_task).await {
            Either::Left((_, hashes_task)) => {
                // We select between the tasks in order to inform the user if this operation is taking too long. On full IBD
                // this operation requires traversing the full DAG which indeed might take several seconds or even minutes.
                info!(
                    "IBD: searching for missing block bodies to request from peer {}. This operation might take several seconds.",
                    self.router
                );
                // Now re-await the original task
                hashes_task.await
            }
            Either::Right((hashes_result, _)) => hashes_result,
        }?;
        if hashes.is_empty() {
            return Ok(());
        }

        let low_header = consensus.async_get_header(*hashes.first().expect("hashes was non empty")).await?;
        let high_header = consensus.async_get_header(*hashes.last().expect("hashes was non empty")).await?;
        let mut progress_reporter = ProgressReporter::new(low_header.daa_score, high_header.daa_score, "blocks");

        let mut iter = hashes.chunks(IBD_BATCH_SIZE);
        let QueueChunkOutput { jobs: mut prev_jobs, daa_score: mut prev_daa_score, timestamp: mut prev_timestamp } =
            self.queue_block_processing_chunk(consensus, iter.next().expect("hashes was non empty")).await?;

        for chunk in iter {
            let QueueChunkOutput { jobs: current_jobs, daa_score: current_daa_score, timestamp: current_timestamp } =
                self.queue_block_processing_chunk(consensus, chunk).await?;
            let prev_chunk_len = prev_jobs.len();
            // Join the previous chunk so that we always concurrently process a chunk and receive another
            try_join_all(prev_jobs).await?;
            // Log the progress
            progress_reporter.report(prev_chunk_len, prev_daa_score, prev_timestamp);
            prev_daa_score = current_daa_score;
            prev_timestamp = current_timestamp;
            prev_jobs = current_jobs;
        }

        let prev_chunk_len = prev_jobs.len();
        try_join_all(prev_jobs).await?;
        progress_reporter.report_completion(prev_chunk_len);

        Ok(())
    }

    async fn queue_block_processing_chunk(
        &mut self,
        consensus: &ConsensusProxy,
        chunk: &[Hash],
    ) -> Result<QueueChunkOutput, ProtocolError> {
        let mut jobs = Vec::with_capacity(chunk.len());
        let mut current_daa_score = 0;
        let mut current_timestamp = 0;
        self.router
            .enqueue(make_message!(
                Payload::RequestIbdBlocks,
                RequestIbdBlocksMessage { hashes: chunk.iter().map(|h| h.into()).collect() }
            ))
            .await?;
        for &expected_hash in chunk {
            let msg = dequeue_with_timeout!(self.incoming_route, Payload::IbdBlock)?;
            let block: Block = msg.try_into()?;
            if block.hash() != expected_hash {
                return Err(ProtocolError::OtherOwned(format!("expected block {} but got {}", expected_hash, block.hash())));
            }
            if block.is_header_only() {
                return Err(ProtocolError::OtherOwned(format!("sent header of {} where expected block with body", block.hash())));
            }
            current_daa_score = block.header.daa_score;
            current_timestamp = block.header.timestamp;
            jobs.push(consensus.validate_and_insert_block(block).virtual_state_task);
        }

        Ok(QueueChunkOutput { jobs, daa_score: current_daa_score, timestamp: current_timestamp })
    }
}
