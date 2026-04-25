//!
//! Logical stream abstractions used throughout the IBD negotiation protocols
//!

use cryptix_consensus_core::{
    errors::consensus::ConsensusError,
    header::Header,
    pruning::PruningPointAtomicState,
    tx::{TransactionOutpoint, UtxoEntry},
};
use cryptix_core::{debug, info};
use cryptix_p2p_lib::{
    common::{ProtocolError, DEFAULT_TIMEOUT},
    convert::model::trusted::{
        trusted_atomic_state_chunk_count, TrustedAtomicStateChunk, TrustedDataEntry, MAX_TRUSTED_ATOMIC_STATE_BYTES,
        MAX_TRUSTED_ATOMIC_STATE_CHUNKS, TRUSTED_ATOMIC_STATE_CHUNK_SIZE,
    },
    make_message,
    pb::{
        cryptixd_message::Payload, RequestNextHeadersMessage, RequestNextPruningPointAndItsAnticoneBlocksMessage,
        RequestNextPruningPointAtomicStateChunkMessage, RequestNextPruningPointUtxoSetChunkMessage,
    },
    IncomingRoute, Router,
};
use std::sync::Arc;
use tokio::time::timeout;

pub const IBD_BATCH_SIZE: usize = 99;

pub async fn receive_trusted_atomic_state_chunks(
    router: &Router,
    incoming_route: &mut IncomingRoute,
    state_hash: [u8; 32],
    total_bytes: u64,
    total_chunks: u64,
) -> Result<PruningPointAtomicState, ProtocolError> {
    validate_trusted_atomic_state_metadata(total_bytes, total_chunks)?;
    let initial_capacity = usize::try_from(total_bytes.min(TRUSTED_ATOMIC_STATE_CHUNK_SIZE as u64))
        .map_err(|_| ProtocolError::OtherOwned(format!("atomic state size {} does not fit this platform", total_bytes)))?;
    let mut serialized_state = Vec::with_capacity(initial_capacity);

    for expected_chunk_index in 0..total_chunks {
        let msg = match timeout(DEFAULT_TIMEOUT, incoming_route.recv()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(ProtocolError::ConnectionClosed),
            Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };
        let chunk: TrustedAtomicStateChunk = match msg.payload {
            Some(Payload::TrustedAtomicStateChunk(payload)) => payload.try_into()?,
            _ => {
                return Err(ProtocolError::UnexpectedMessage(
                    stringify!(Payload::TrustedAtomicStateChunk),
                    msg.payload.as_ref().map(|v| v.into()),
                ))
            }
        };

        validate_trusted_atomic_state_chunk(
            &chunk,
            state_hash,
            expected_chunk_index,
            total_chunks,
            total_bytes,
            serialized_state.len(),
        )?;
        serialized_state.extend_from_slice(&chunk.chunk);

        let downloaded_chunks = expected_chunk_index + 1;
        if downloaded_chunks % IBD_BATCH_SIZE as u64 == 0 && downloaded_chunks < total_chunks {
            info!("Downloaded {} pruning point atomic state chunks", downloaded_chunks);
            router
                .enqueue(make_message!(
                    Payload::RequestNextPruningPointAtomicStateChunk,
                    RequestNextPruningPointAtomicStateChunkMessage {}
                ))
                .await?;
        }
    }

    if serialized_state.len() as u64 != total_bytes {
        return Err(ProtocolError::OtherOwned(format!(
            "pruning-point atomic state size mismatch: expected {}, got {}",
            total_bytes,
            serialized_state.len()
        )));
    }
    info!("Finished receiving pruning point atomic consensus state: {} bytes in {} chunks", total_bytes, total_chunks);
    Ok(PruningPointAtomicState { serialized_state, state_hash })
}

fn validate_trusted_atomic_state_metadata(total_bytes: u64, total_chunks: u64) -> Result<(), ProtocolError> {
    if total_bytes == 0 || total_chunks == 0 {
        return Err(ProtocolError::Other("chunked pruning-point atomic state must declare non-zero bytes and chunks"));
    }
    if total_bytes > MAX_TRUSTED_ATOMIC_STATE_BYTES {
        return Err(ProtocolError::OtherOwned(format!(
            "chunked pruning-point atomic state size {} exceeds transfer limit {}",
            total_bytes, MAX_TRUSTED_ATOMIC_STATE_BYTES
        )));
    }
    if total_chunks > MAX_TRUSTED_ATOMIC_STATE_CHUNKS {
        return Err(ProtocolError::OtherOwned(format!(
            "chunked pruning-point atomic state chunk count {} exceeds transfer limit {}",
            total_chunks, MAX_TRUSTED_ATOMIC_STATE_CHUNKS
        )));
    }
    let expected_chunks = trusted_atomic_state_chunk_count(total_bytes);
    if total_chunks != expected_chunks {
        return Err(ProtocolError::OtherOwned(format!(
            "chunked pruning-point atomic state metadata mismatch: expected {} chunk(s) for {} bytes, got {}",
            expected_chunks, total_bytes, total_chunks
        )));
    }
    Ok(())
}

fn validate_trusted_atomic_state_chunk(
    chunk: &TrustedAtomicStateChunk,
    state_hash: [u8; 32],
    expected_chunk_index: u64,
    total_chunks: u64,
    total_bytes: u64,
    assembled_len: usize,
) -> Result<(), ProtocolError> {
    if chunk.state_hash != state_hash {
        return Err(ProtocolError::Other("pruning-point atomic state chunk hash label mismatch"));
    }
    if chunk.chunk_index != expected_chunk_index {
        return Err(ProtocolError::OtherOwned(format!(
            "unexpected pruning-point atomic state chunk index: expected {}, got {}",
            expected_chunk_index, chunk.chunk_index
        )));
    }
    if chunk.total_chunks != total_chunks || chunk.total_bytes != total_bytes {
        return Err(ProtocolError::Other("pruning-point atomic state chunk metadata changed mid-stream"));
    }
    if chunk.chunk.is_empty() {
        return Err(ProtocolError::Other("pruning-point atomic state chunk must not be empty"));
    }
    if chunk.chunk.len() > TRUSTED_ATOMIC_STATE_CHUNK_SIZE {
        return Err(ProtocolError::OtherOwned(format!(
            "pruning-point atomic state chunk {} size {} exceeds max {}",
            expected_chunk_index,
            chunk.chunk.len(),
            TRUSTED_ATOMIC_STATE_CHUNK_SIZE
        )));
    }

    let assembled_len =
        u64::try_from(assembled_len).map_err(|_| ProtocolError::Other("assembled atomic state length does not fit u64"))?;
    let remaining = total_bytes.saturating_sub(assembled_len);
    if chunk.chunk.len() as u64 > remaining {
        return Err(ProtocolError::OtherOwned(format!(
            "pruning-point atomic state chunk {} size {} exceeds remaining {} bytes",
            expected_chunk_index,
            chunk.chunk.len(),
            remaining
        )));
    }
    let expected_len = remaining.min(TRUSTED_ATOMIC_STATE_CHUNK_SIZE as u64) as usize;
    if chunk.chunk.len() != expected_len {
        return Err(ProtocolError::OtherOwned(format!(
            "pruning-point atomic state chunk {} invalid size: expected {}, got {}",
            expected_chunk_index,
            expected_len,
            chunk.chunk.len()
        )));
    }

    Ok(())
}

pub struct TrustedEntryStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize,
}

impl<'a, 'b> TrustedEntryStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<TrustedDataEntry>, ProtocolError> {
        let res = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::BlockWithTrustedDataV4(payload)) => {
                            let entry: TrustedDataEntry = payload.try_into()?;
                            if entry.block.is_header_only() {
                                Err(ProtocolError::OtherOwned(format!("trusted entry block {} is header only", entry.block.hash())))
                            } else {
                                Ok(Some(entry))
                            }
                        }
                        Some(Payload::DoneBlocksWithTrustedData(_)) => {
                            debug!("trusted entry stream completed after {} items", self.i);
                            Ok(None)
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(Payload::BlockWithTrustedDataV4 | Payload::DoneBlocksWithTrustedData),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(_)) = res {
            self.i += 1;
            if self.i % IBD_BATCH_SIZE == 0 {
                info!("Downloaded {} blocks from the pruning point anticone", self.i - 1);
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointAndItsAnticoneBlocks,
                        RequestNextPruningPointAndItsAnticoneBlocksMessage {}
                    ))
                    .await?;
            }
        }

        res
    }
}

/// A chunk of headers
pub type HeadersChunk = Vec<Arc<Header>>;

pub struct HeadersChunkStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize,
}

impl<'a, 'b> HeadersChunkStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<HeadersChunk>, ProtocolError> {
        let res = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::BlockHeaders(payload)) => {
                            if payload.block_headers.is_empty() {
                                // The syncer should have sent a done message if the search completed, and not an empty list
                                Err(ProtocolError::Other("Received an empty headers message"))
                            } else {
                                Ok(Some(payload.try_into()?))
                            }
                        }
                        Some(Payload::DoneHeaders(_)) => {
                            debug!("headers chunk stream completed after {} chunks", self.i);
                            Ok(None)
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(Payload::BlockHeaders | Payload::DoneHeaders),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(_)) = res {
            self.i += 1;
            self.router.enqueue(make_message!(Payload::RequestNextHeaders, RequestNextHeadersMessage {})).await?;
        }

        res
    }
}

/// A chunk of UTXOs
pub type UtxosetChunk = Vec<(TransactionOutpoint, UtxoEntry)>;

pub struct PruningPointUtxosetChunkStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize, // Chunk index
    utxo_count: usize,
}

impl<'a, 'b> PruningPointUtxosetChunkStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0, utxo_count: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<UtxosetChunk>, ProtocolError> {
        let res: Result<Option<UtxosetChunk>, ProtocolError> = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::PruningPointUtxoSetChunk(payload)) => Ok(Some(payload.try_into()?)),
                        Some(Payload::DonePruningPointUtxoSetChunks(_)) => {
                            info!("Finished receiving the UTXO set. Total UTXOs: {}", self.utxo_count);
                            Ok(None)
                        }
                        Some(Payload::UnexpectedPruningPoint(_)) => {
                            // Although this can happen also to an honest syncer (if his pruning point moves during the sync),
                            // we prefer erring and disconnecting to avoid possible exploits by a syncer repeating this failure
                            Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint))
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(
                                Payload::PruningPointUtxoSetChunk
                                    | Payload::DonePruningPointUtxoSetChunks
                                    | Payload::UnexpectedPruningPoint
                            ),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(chunk)) = res {
            self.i += 1;
            self.utxo_count += chunk.len();
            if self.i % IBD_BATCH_SIZE == 0 {
                info!("Received {} UTXO set chunks so far, totaling in {} UTXOs", self.i, self.utxo_count);
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointUtxoSetChunk,
                        RequestNextPruningPointUtxoSetChunkMessage {}
                    ))
                    .await?;
            }
            Ok(Some(chunk))
        } else {
            res
        }
    }
}
