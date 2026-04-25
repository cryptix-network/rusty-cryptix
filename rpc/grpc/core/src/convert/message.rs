//! Conversions of protowire messages from and to rpc core counterparts.
//!
//! Response payloads in protowire do always contain an error field and generally a set of
//! fields providing the requested data.
//!
//! Responses in rpc core are expressed as RpcResult<XxxResponse>, where Xxx is the called
//! RPC method.
//!
//! The general conversion convention from protowire to rpc core is to consider the error
//! field first and, if present, to return a matching Err(RpcError). If absent, try to
//! convert the set of data fields into a matching XxxResponse rpc core response and, on
//! success, return Ok(XxxResponse), otherwise return a conversion error.
//!
//! Conversely, the general conversion convention from rpc core to protowire, depending on
//! a provided RpcResult is to either convert the Ok(XxxResponse) into the matching set
//! of data fields and provide no error or provide no data fields but an error field in case
//! of Err(RpcError).
//!
//! The SubmitBlockResponse is a notable exception to this general rule.

use crate::protowire::{self, submit_block_response_message::RejectReason};
use cryptix_consensus_core::network::NetworkId;
use cryptix_core::debug;
use cryptix_notify::subscription::Command;
use cryptix_rpc_core::{
    RpcContextualPeerAddress, RpcError, RpcExtraData, RpcFastIntentStatus, RpcHash, RpcIpAddress, RpcNetworkType, RpcPeerAddress,
    RpcResult, SubmitBlockRejectReason, SubmitBlockReport,
};
use cryptix_utils::hex::*;
use std::{collections::HashMap, str::FromStr};

macro_rules! from {
    // Response capture
    ($name:ident : RpcResult<&$from_type:ty>, $to_type:ty, $ctor:block) => {
        impl From<RpcResult<&$from_type>> for $to_type {
            fn from(item: RpcResult<&$from_type>) -> Self {
                match item {
                    Ok($name) => $ctor,
                    Err(err) => {
                        let mut message = Self::default();
                        message.error = Some(err.into());
                        message
                    }
                }
            }
        }
    };

    // Response without parameter capture
    (RpcResult<&$from_type:ty>, $to_type:ty) => {
        impl From<RpcResult<&$from_type>> for $to_type {
            fn from(item: RpcResult<&$from_type>) -> Self {
                Self { error: item.map_err(protowire::RpcError::from).err() }
            }
        }
    };

    // Request and other capture
    ($name:ident : $from_type:ty, $to_type:ty, $body:block) => {
        impl From<$from_type> for $to_type {
            fn from($name: $from_type) -> Self {
                $body
            }
        }
    };

    // Request and other without parameter capture
    ($from_type:ty, $to_type:ty) => {
        impl From<$from_type> for $to_type {
            fn from(_: $from_type) -> Self {
                Self {}
            }
        }
    };
}

macro_rules! try_from {
    // Response capture
    ($name:ident : $from_type:ty, RpcResult<$to_type:ty>, $ctor:block) => {
        impl TryFrom<$from_type> for $to_type {
            type Error = RpcError;
            fn try_from($name: $from_type) -> RpcResult<Self> {
                if let Some(ref err) = $name.error {
                    Err(err.into())
                } else {
                    #[allow(unreachable_code)] // TODO: remove attribute when all converters are implemented
                    Ok($ctor)
                }
            }
        }
    };

    // Response without parameter capture
    ($from_type:ty, RpcResult<$to_type:ty>) => {
        impl TryFrom<$from_type> for $to_type {
            type Error = RpcError;
            fn try_from(item: $from_type) -> RpcResult<Self> {
                item.error.as_ref().map_or(Ok(Self {}), |x| Err(x.into()))
            }
        }
    };

    // Request and other capture
    ($name:ident : $from_type:ty, $to_type:ty, $body:block) => {
        impl TryFrom<$from_type> for $to_type {
            type Error = RpcError;
            fn try_from($name: $from_type) -> RpcResult<Self> {
                #[allow(unreachable_code)] // TODO: remove attribute when all converters are implemented
                Ok($body)
            }
        }
    };

    // Request and other without parameter capture
    ($from_type:ty, $to_type:ty) => {
        impl TryFrom<$from_type> for $to_type {
            type Error = RpcError;
            fn try_from(_: $from_type) -> RpcResult<Self> {
                Ok(Self {})
            }
        }
    };
}

fn fast_intent_status_to_proto(status: RpcFastIntentStatus) -> &'static str {
    match status {
        RpcFastIntentStatus::Received => "received",
        RpcFastIntentStatus::Validated => "validated",
        RpcFastIntentStatus::Locked => "locked",
        RpcFastIntentStatus::FastConfirmed => "fast_confirmed",
        RpcFastIntentStatus::Expired => "expired",
        RpcFastIntentStatus::Dropped => "dropped",
        RpcFastIntentStatus::Rejected => "rejected",
        RpcFastIntentStatus::Cancelled => "cancelled",
        RpcFastIntentStatus::UnknownIntent => "unknown_intent",
    }
}

fn fast_intent_status_from_proto(status: &str) -> RpcResult<RpcFastIntentStatus> {
    match status {
        "received" => Ok(RpcFastIntentStatus::Received),
        "validated" => Ok(RpcFastIntentStatus::Validated),
        "locked" => Ok(RpcFastIntentStatus::Locked),
        "fast_confirmed" => Ok(RpcFastIntentStatus::FastConfirmed),
        "expired" => Ok(RpcFastIntentStatus::Expired),
        "dropped" => Ok(RpcFastIntentStatus::Dropped),
        "rejected" => Ok(RpcFastIntentStatus::Rejected),
        "cancelled" => Ok(RpcFastIntentStatus::Cancelled),
        "unknown_intent" => Ok(RpcFastIntentStatus::UnknownIntent),
        _ => Err(RpcError::General(format!("invalid fast intent status: {status}"))),
    }
}

// ----------------------------------------------------------------------------
// rpc_core to protowire
// ----------------------------------------------------------------------------

from!(item: &cryptix_rpc_core::SubmitBlockReport, RejectReason, {
    match item {
        cryptix_rpc_core::SubmitBlockReport::Success => RejectReason::None,
        cryptix_rpc_core::SubmitBlockReport::Reject(cryptix_rpc_core::SubmitBlockRejectReason::BlockInvalid) => RejectReason::BlockInvalid,
        cryptix_rpc_core::SubmitBlockReport::Reject(cryptix_rpc_core::SubmitBlockRejectReason::IsInIBD) => RejectReason::IsInIbd,
        // The conversion of RouteIsFull falls back to None since there exist no such variant in the original protowire version
        // and we do not want to break backwards compatibility
        cryptix_rpc_core::SubmitBlockReport::Reject(cryptix_rpc_core::SubmitBlockRejectReason::RouteIsFull) => RejectReason::None,
    }
});

from!(item: &cryptix_rpc_core::SubmitBlockRequest, protowire::SubmitBlockRequestMessage, {
    Self { block: Some((&item.block).into()), allow_non_daa_blocks: item.allow_non_daa_blocks }
});
// This conversion breaks the general conversion convention (see file header) since the message may
// contain both a non default reject_reason and a matching error message. In the RouteIsFull case
// reject_reason is None (because this reason has no variant in protowire) but a specific error
// message is provided.
from!(item: RpcResult<&cryptix_rpc_core::SubmitBlockResponse>, protowire::SubmitBlockResponseMessage, {
    let error: Option<protowire::RpcError> = match item.report {
        cryptix_rpc_core::SubmitBlockReport::Success => None,
        cryptix_rpc_core::SubmitBlockReport::Reject(reason) => Some(RpcError::SubmitBlockError(reason).into())
    };
    Self { reject_reason: RejectReason::from(&item.report) as i32, error }
});

from!(item: &cryptix_rpc_core::GetBlockTemplateRequest, protowire::GetBlockTemplateRequestMessage, {
    Self {
        pay_address: (&item.pay_address).into(),
        extra_data: String::from_utf8(item.extra_data.clone()).expect("extra data has to be valid UTF-8"),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetBlockTemplateResponse>, protowire::GetBlockTemplateResponseMessage, {
    Self { block: Some((&item.block).into()), is_synced: item.is_synced, error: None }
});

from!(item: &cryptix_rpc_core::GetBlockRequest, protowire::GetBlockRequestMessage, {
    Self { hash: item.hash.to_string(), include_transactions: item.include_transactions }
});
from!(item: RpcResult<&cryptix_rpc_core::GetBlockResponse>, protowire::GetBlockResponseMessage, {
    Self { block: Some((&item.block).into()), error: None }
});

from!(item: &cryptix_rpc_core::NotifyBlockAddedRequest, protowire::NotifyBlockAddedRequestMessage, {
    Self { command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyBlockAddedResponse>, protowire::NotifyBlockAddedResponseMessage);

from!(&cryptix_rpc_core::GetInfoRequest, protowire::GetInfoRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetInfoResponse>, protowire::GetInfoResponseMessage, {
    Self {
        p2p_id: item.p2p_id.clone(),
        mempool_size: item.mempool_size,
        server_version: item.server_version.clone(),
        is_utxo_indexed: item.is_utxo_indexed,
        is_synced: item.is_synced,
        has_notify_command: item.has_notify_command,
        has_message_id: item.has_message_id,
        error: None,
    }
});

from!(item: &cryptix_rpc_core::NotifyNewBlockTemplateRequest, protowire::NotifyNewBlockTemplateRequestMessage, {
    Self { command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyNewBlockTemplateResponse>, protowire::NotifyNewBlockTemplateResponseMessage);

from!(item: &cryptix_rpc_core::NotifyTokenEventsRequest, protowire::NotifyTokenEventsRequestMessage, {
    Self { command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyTokenEventsResponse>, protowire::NotifyTokenEventsResponseMessage);

// ~~~

from!(&cryptix_rpc_core::GetCurrentNetworkRequest, protowire::GetCurrentNetworkRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetCurrentNetworkResponse>, protowire::GetCurrentNetworkResponseMessage, {
    Self { current_network: item.network.to_string(), error: None }
});

from!(&cryptix_rpc_core::GetPeerAddressesRequest, protowire::GetPeerAddressesRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetPeerAddressesResponse>, protowire::GetPeerAddressesResponseMessage, {
    Self {
        addresses: item.known_addresses.iter().map(|x| x.into()).collect(),
        banned_addresses: item.banned_addresses.iter().map(|x| x.into()).collect(),
        error: None,
    }
});

from!(&cryptix_rpc_core::GetSinkRequest, protowire::GetSinkRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetSinkResponse>, protowire::GetSinkResponseMessage, {
    Self { sink: item.sink.to_string(), error: None }
});

from!(item: &cryptix_rpc_core::GetMempoolEntryRequest, protowire::GetMempoolEntryRequestMessage, {
    Self {
        tx_id: item.transaction_id.to_string(),
        include_orphan_pool: item.include_orphan_pool,
        filter_transaction_pool: item.filter_transaction_pool,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetMempoolEntryResponse>, protowire::GetMempoolEntryResponseMessage, {
    Self { entry: Some((&item.mempool_entry).into()), error: None }
});

from!(item: &cryptix_rpc_core::GetMempoolEntriesRequest, protowire::GetMempoolEntriesRequestMessage, {
    Self { include_orphan_pool: item.include_orphan_pool, filter_transaction_pool: item.filter_transaction_pool }
});
from!(item: RpcResult<&cryptix_rpc_core::GetMempoolEntriesResponse>, protowire::GetMempoolEntriesResponseMessage, {
    Self { entries: item.mempool_entries.iter().map(|x| x.into()).collect(), error: None }
});

from!(&cryptix_rpc_core::GetConnectedPeerInfoRequest, protowire::GetConnectedPeerInfoRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetConnectedPeerInfoResponse>, protowire::GetConnectedPeerInfoResponseMessage, {
    Self { infos: item.peer_info.iter().map(|x| x.into()).collect(), error: None }
});

from!(item: &cryptix_rpc_core::AddPeerRequest, protowire::AddPeerRequestMessage, {
    Self { address: item.peer_address.to_string(), is_permanent: item.is_permanent }
});
from!(RpcResult<&cryptix_rpc_core::AddPeerResponse>, protowire::AddPeerResponseMessage);

from!(item: &cryptix_rpc_core::SubmitTransactionRequest, protowire::SubmitTransactionRequestMessage, {
    Self { transaction: Some((&item.transaction).into()), allow_orphan: item.allow_orphan }
});
from!(item: RpcResult<&cryptix_rpc_core::SubmitTransactionResponse>, protowire::SubmitTransactionResponseMessage, {
    Self { transaction_id: item.transaction_id.to_string(), error: None }
});

from!(item: &cryptix_rpc_core::SubmitTransactionReplacementRequest, protowire::SubmitTransactionReplacementRequestMessage, {
    Self { transaction: Some((&item.transaction).into()) }
});
from!(item: RpcResult<&cryptix_rpc_core::SubmitTransactionReplacementResponse>, protowire::SubmitTransactionReplacementResponseMessage, {
    Self { transaction_id: item.transaction_id.to_string(), replaced_transaction: Some((&item.replaced_transaction).into()), error: None }
});

from!(item: &cryptix_rpc_core::GetSubnetworkRequest, protowire::GetSubnetworkRequestMessage, {
    Self { subnetwork_id: item.subnetwork_id.to_string() }
});
from!(item: RpcResult<&cryptix_rpc_core::GetSubnetworkResponse>, protowire::GetSubnetworkResponseMessage, {
    Self { gas_limit: item.gas_limit, error: None }
});

// ~~~

from!(item: &cryptix_rpc_core::GetVirtualChainFromBlockRequest, protowire::GetVirtualChainFromBlockRequestMessage, {
    Self { start_hash: item.start_hash.to_string(), include_accepted_transaction_ids: item.include_accepted_transaction_ids }
});
from!(item: RpcResult<&cryptix_rpc_core::GetVirtualChainFromBlockResponse>, protowire::GetVirtualChainFromBlockResponseMessage, {
    Self {
        removed_chain_block_hashes: item.removed_chain_block_hashes.iter().map(|x| x.to_string()).collect(),
        added_chain_block_hashes: item.added_chain_block_hashes.iter().map(|x| x.to_string()).collect(),
        accepted_transaction_ids: item.accepted_transaction_ids.iter().map(|x| x.into()).collect(),
        error: None,
    }
});

from!(item: &cryptix_rpc_core::GetBlocksRequest, protowire::GetBlocksRequestMessage, {
    Self {
        low_hash: item.low_hash.map_or(Default::default(), |x| x.to_string()),
        include_blocks: item.include_blocks,
        include_transactions: item.include_transactions,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetBlocksResponse>, protowire::GetBlocksResponseMessage, {
    Self {
        block_hashes: item.block_hashes.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
        blocks: item.blocks.iter().map(|x| x.into()).collect::<Vec<_>>(),
        error: None,
    }
});

from!(&cryptix_rpc_core::GetBlockCountRequest, protowire::GetBlockCountRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetBlockCountResponse>, protowire::GetBlockCountResponseMessage, {
    Self { block_count: item.block_count, header_count: item.header_count, error: None }
});

from!(&cryptix_rpc_core::GetBlockDagInfoRequest, protowire::GetBlockDagInfoRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetBlockDagInfoResponse>, protowire::GetBlockDagInfoResponseMessage, {
    Self {
        network_name: item.network.to_prefixed(),
        block_count: item.block_count,
        header_count: item.header_count,
        tip_hashes: item.tip_hashes.iter().map(|x| x.to_string()).collect(),
        difficulty: item.difficulty,
        past_median_time: item.past_median_time as i64,
        virtual_parent_hashes: item.virtual_parent_hashes.iter().map(|x| x.to_string()).collect(),
        pruning_point_hash: item.pruning_point_hash.to_string(),
        virtual_daa_score: item.virtual_daa_score,
        sink: item.sink.to_string(),
        error: None,
    }
});

from!(item: &cryptix_rpc_core::ResolveFinalityConflictRequest, protowire::ResolveFinalityConflictRequestMessage, {
    Self { finality_block_hash: item.finality_block_hash.to_string() }
});
from!(_item: RpcResult<&cryptix_rpc_core::ResolveFinalityConflictResponse>, protowire::ResolveFinalityConflictResponseMessage, {
    Self { error: None }
});

from!(&cryptix_rpc_core::ShutdownRequest, protowire::ShutdownRequestMessage);
from!(RpcResult<&cryptix_rpc_core::ShutdownResponse>, protowire::ShutdownResponseMessage);

from!(item: &cryptix_rpc_core::GetHeadersRequest, protowire::GetHeadersRequestMessage, {
    Self { start_hash: item.start_hash.to_string(), limit: item.limit, is_ascending: item.is_ascending }
});
from!(item: RpcResult<&cryptix_rpc_core::GetHeadersResponse>, protowire::GetHeadersResponseMessage, {
    Self { headers: item.headers.iter().map(|x| x.hash.to_string()).collect(), error: None }
});

from!(item: &cryptix_rpc_core::GetUtxosByAddressesRequest, protowire::GetUtxosByAddressesRequestMessage, {
    Self { addresses: item.addresses.iter().map(|x| x.into()).collect() }
});
from!(item: RpcResult<&cryptix_rpc_core::GetUtxosByAddressesResponse>, protowire::GetUtxosByAddressesResponseMessage, {
    debug!("GRPC, Creating GetUtxosByAddresses message with {} entries", item.entries.len());
    Self { entries: item.entries.iter().map(|x| x.into()).collect(), error: None }
});

from!(item: &cryptix_rpc_core::GetBalanceByAddressRequest, protowire::GetBalanceByAddressRequestMessage, {
    Self { address: (&item.address).into() }
});
from!(item: RpcResult<&cryptix_rpc_core::GetBalanceByAddressResponse>, protowire::GetBalanceByAddressResponseMessage, {
    debug!("GRPC, Creating GetBalanceByAddress messages");
    Self { balance: item.balance, error: None }
});

from!(item: &cryptix_rpc_core::GetBalancesByAddressesRequest, protowire::GetBalancesByAddressesRequestMessage, {
    Self { addresses: item.addresses.iter().map(|x| x.into()).collect() }
});
from!(item: RpcResult<&cryptix_rpc_core::GetBalancesByAddressesResponse>, protowire::GetBalancesByAddressesResponseMessage, {
    debug!("GRPC, Creating GetUtxosByAddresses message with {} entries", item.entries.len());
    Self { entries: item.entries.iter().map(|x| x.into()).collect(), error: None }
});

from!(&cryptix_rpc_core::GetSinkBlueScoreRequest, protowire::GetSinkBlueScoreRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetSinkBlueScoreResponse>, protowire::GetSinkBlueScoreResponseMessage, {
    Self { blue_score: item.blue_score, error: None }
});

from!(item: &cryptix_rpc_core::BanRequest, protowire::BanRequestMessage, { Self { ip: item.ip.to_string() } });
from!(_item: RpcResult<&cryptix_rpc_core::BanResponse>, protowire::BanResponseMessage, { Self { error: None } });

from!(item: &cryptix_rpc_core::UnbanRequest, protowire::UnbanRequestMessage, { Self { ip: item.ip.to_string() } });
from!(_item: RpcResult<&cryptix_rpc_core::UnbanResponse>, protowire::UnbanResponseMessage, { Self { error: None } });

from!(item: &cryptix_rpc_core::EstimateNetworkHashesPerSecondRequest, protowire::EstimateNetworkHashesPerSecondRequestMessage, {
    Self { window_size: item.window_size, start_hash: item.start_hash.map_or(Default::default(), |x| x.to_string()) }
});
from!(
    item: RpcResult<&cryptix_rpc_core::EstimateNetworkHashesPerSecondResponse>,
    protowire::EstimateNetworkHashesPerSecondResponseMessage,
    { Self { network_hashes_per_second: item.network_hashes_per_second, error: None } }
);

from!(item: &cryptix_rpc_core::GetMempoolEntriesByAddressesRequest, protowire::GetMempoolEntriesByAddressesRequestMessage, {
    Self {
        addresses: item.addresses.iter().map(|x| x.into()).collect(),
        include_orphan_pool: item.include_orphan_pool,
        filter_transaction_pool: item.filter_transaction_pool,
    }
});
from!(
    item: RpcResult<&cryptix_rpc_core::GetMempoolEntriesByAddressesResponse>,
    protowire::GetMempoolEntriesByAddressesResponseMessage,
    { Self { entries: item.entries.iter().map(|x| x.into()).collect(), error: None } }
);

from!(&cryptix_rpc_core::GetCoinSupplyRequest, protowire::GetCoinSupplyRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetCoinSupplyResponse>, protowire::GetCoinSupplyResponseMessage, {
    Self { max_sompi: item.max_sompi, circulating_sompi: item.circulating_sompi, error: None }
});

from!(item: &cryptix_rpc_core::GetDaaScoreTimestampEstimateRequest, protowire::GetDaaScoreTimestampEstimateRequestMessage, {
    Self {
        daa_scores: item.daa_scores.clone()
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetDaaScoreTimestampEstimateResponse>, protowire::GetDaaScoreTimestampEstimateResponseMessage, {
    Self { timestamps: item.timestamps.clone(), error: None }
});

// Fee estimate API

from!(&cryptix_rpc_core::GetFeeEstimateRequest, protowire::GetFeeEstimateRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetFeeEstimateResponse>, protowire::GetFeeEstimateResponseMessage, {
    Self { estimate: Some((&item.estimate).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetFeeEstimateExperimentalRequest, protowire::GetFeeEstimateExperimentalRequestMessage, {
    Self {
        verbose: item.verbose
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetFeeEstimateExperimentalResponse>, protowire::GetFeeEstimateExperimentalResponseMessage, {
    Self {
        estimate: Some((&item.estimate).into()),
        verbose: item.verbose.as_ref().map(|x| x.into()),
        error: None
    }
});

from!(item: &cryptix_rpc_core::GetCurrentBlockColorRequest, protowire::GetCurrentBlockColorRequestMessage, {
    Self {
        hash: item.hash.to_string()
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetCurrentBlockColorResponse>, protowire::GetCurrentBlockColorResponseMessage, {
    Self { blue: item.blue, error: None }
});

from!(item: &cryptix_rpc_core::SubmitFastIntentRequest, protowire::SubmitFastIntentRequestMessage, {
    Self {
        base_tx: Some((&item.base_tx).into()),
        intent_nonce: item.intent_nonce,
        client_created_at_ms: item.client_created_at_ms,
        max_fee: item.max_fee,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::SubmitFastIntentResponse>, protowire::SubmitFastIntentResponseMessage, {
    Self {
        intent_id: item.intent_id.to_string(),
        status: fast_intent_status_to_proto(item.status).to_string(),
        reason: item.reason.clone().unwrap_or_default(),
        node_epoch: item.node_epoch,
        expires_at_ms: item.expires_at_ms.unwrap_or_default(),
        retention_until_ms: item.retention_until_ms.unwrap_or_default(),
        cancel_token: item.cancel_token.clone().unwrap_or_default(),
        basechain_submitted: item.basechain_submitted,
        base_tx_id: item.base_tx_id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
        error: None,
    }
});

from!(item: &cryptix_rpc_core::GetFastIntentStatusRequest, protowire::GetFastIntentStatusRequestMessage, {
    Self {
        intent_id: item.intent_id.to_string(),
        client_last_node_epoch: item.client_last_node_epoch.unwrap_or_default(),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetFastIntentStatusResponse>, protowire::GetFastIntentStatusResponseMessage, {
    Self {
        status: fast_intent_status_to_proto(item.status).to_string(),
        reason: item.reason.clone().unwrap_or_default(),
        node_epoch: item.node_epoch,
        expires_at_ms: item.expires_at_ms.unwrap_or_default(),
        retention_until_ms: item.retention_until_ms.unwrap_or_default(),
        cancel_token: item.cancel_token.clone().unwrap_or_default(),
        has_epoch_changed: item.epoch_changed.is_some(),
        epoch_changed: item.epoch_changed.unwrap_or_default(),
        base_tx_id: item.base_tx_id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
        error: None,
    }
});

from!(item: &cryptix_rpc_core::CancelFastIntentRequest, protowire::CancelFastIntentRequestMessage, {
    Self {
        intent_id: item.intent_id.to_string(),
        cancel_token: item.cancel_token.clone(),
        node_epoch: item.node_epoch,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::CancelFastIntentResponse>, protowire::CancelFastIntentResponseMessage, {
    Self {
        status: fast_intent_status_to_proto(item.status).to_string(),
        reason: item.reason.clone().unwrap_or_default(),
        node_epoch: item.node_epoch,
        retention_until_ms: item.retention_until_ms.unwrap_or_default(),
        has_epoch_changed: item.epoch_changed.is_some(),
        epoch_changed: item.epoch_changed.unwrap_or_default(),
        error: None,
    }
});

from!(&cryptix_rpc_core::PingRequest, protowire::PingRequestMessage);
from!(RpcResult<&cryptix_rpc_core::PingResponse>, protowire::PingResponseMessage);

from!(item: &cryptix_rpc_core::GetMetricsRequest, protowire::GetMetricsRequestMessage, {
    Self {
        process_metrics: item.process_metrics,
        connection_metrics: item.connection_metrics,
        bandwidth_metrics: item.bandwidth_metrics,
        consensus_metrics: item.consensus_metrics,
        storage_metrics: item.storage_metrics,
        custom_metrics: item.custom_metrics,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetMetricsResponse>, protowire::GetMetricsResponseMessage, {
    Self {
        server_time: item.server_time,
        process_metrics: item.process_metrics.as_ref().map(|x| x.into()),
        connection_metrics: item.connection_metrics.as_ref().map(|x| x.into()),
        bandwidth_metrics: item.bandwidth_metrics.as_ref().map(|x| x.into()),
        consensus_metrics: item.consensus_metrics.as_ref().map(|x| x.into()),
        storage_metrics: item.storage_metrics.as_ref().map(|x| x.into()),
        custom_metrics: item
            .custom_metrics
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.into())).collect())
            .unwrap_or_default(),
        error: None,
    }
});

from!(item: &cryptix_rpc_core::GetConnectionsRequest, protowire::GetConnectionsRequestMessage, {
    Self {
        include_profile_data : item.include_profile_data,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetConnectionsResponse>, protowire::GetConnectionsResponseMessage, {
    Self {
        clients: item.clients,
        peers: item.peers as u32,
        profile_data: item.profile_data.as_ref().map(|x| x.into()),
        error: None,
    }
});

from!(&cryptix_rpc_core::GetSystemInfoRequest, protowire::GetSystemInfoRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetSystemInfoResponse>, protowire::GetSystemInfoResponseMessage, {
    Self {
        version : item.version.clone(),
        system_id : item.system_id.as_ref().map(|system_id|system_id.to_hex()).unwrap_or_default(),
        git_hash : item.git_hash.as_ref().map(|git_hash|git_hash.to_hex()).unwrap_or_default(),
        total_memory : item.total_memory,
        core_num : item.cpu_physical_cores as u32,
        fd_limit : item.fd_limit,
        proxy_socket_limit_per_cpu_core : item.proxy_socket_limit_per_cpu_core.unwrap_or_default(),
        error: None,
    }
});

from!(&cryptix_rpc_core::GetServerInfoRequest, protowire::GetServerInfoRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetServerInfoResponse>, protowire::GetServerInfoResponseMessage, {
    Self {
        rpc_api_version: item.rpc_api_version as u32,
        rpc_api_revision: item.rpc_api_revision as u32,
        server_version: item.server_version.clone(),
        network_id: item.network_id.to_string(),
        has_utxo_index: item.has_utxo_index,
        is_synced: item.is_synced,
        virtual_daa_score: item.virtual_daa_score,
        error: None,
    }
});

from!(&cryptix_rpc_core::GetSyncStatusRequest, protowire::GetSyncStatusRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetSyncStatusResponse>, protowire::GetSyncStatusResponseMessage, {
    Self {
        is_synced: item.is_synced,
        error: None,
    }
});
from!(&cryptix_rpc_core::GetStrongNodesRequest, protowire::GetStrongNodesRequestMessage);
from!(item: &cryptix_rpc_core::RpcStrongNodeEntry, protowire::RpcStrongNodeEntry, {
    Self {
        node_id: item.node_id.clone(),
        public_key_xonly: item.public_key_xonly.clone(),
        source: item.source.clone(),
        claimed_blocks: item.claimed_blocks,
        share_bps: item.share_bps,
        last_claim_block_hash: item.last_claim_block_hash.clone(),
        last_claim_time_ms: item.last_claim_time_ms,
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetStrongNodesResponse>, protowire::GetStrongNodesResponseMessage, {
    Self {
        enabled_by_config: item.enabled_by_config,
        hardfork_active: item.hardfork_active,
        runtime_available: item.runtime_available,
        disabled_reason_code: item.disabled_reason_code.clone(),
        disabled_reason_message: item.disabled_reason_message.clone(),
        conflict_total: item.conflict_total,
        window_size: item.window_size,
        entries: item.entries.iter().map(Into::into).collect(),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::RpcTokenContext, protowire::RpcTokenContextMessage, {
    Self {
        at_block_hash: item.at_block_hash.to_string(),
        at_daa_score: item.at_daa_score,
        state_hash: item.state_hash.clone(),
        is_degraded: item.is_degraded,
    }
});
from!(item: &cryptix_rpc_core::RpcTokenAsset, protowire::RpcTokenAssetMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        creator_owner_id: item.creator_owner_id.clone(),
        mint_authority_owner_id: item.mint_authority_owner_id.clone(),
        decimals: item.decimals,
        supply_mode: item.supply_mode,
        max_supply: item.max_supply.clone(),
        total_supply: item.total_supply.clone(),
        name: item.name.clone(),
        symbol: item.symbol.clone(),
        metadata_hex: item.metadata_hex.clone(),
        created_block_hash: item.created_block_hash.map(|hash| hash.to_string()),
        created_daa_score: item.created_daa_score,
        created_at: item.created_at,
    }
});
from!(item: &cryptix_rpc_core::RpcTokenEvent, protowire::RpcTokenEventMessage, {
    Self {
        event_id: item.event_id.clone(),
        sequence: item.sequence,
        accepting_block_hash: item.accepting_block_hash.to_string(),
        txid: item.txid.to_string(),
        event_type: item.event_type,
        apply_status: item.apply_status,
        noop_reason: item.noop_reason,
        ordinal: item.ordinal,
        reorg_of_event_id: item.reorg_of_event_id.clone(),
        op_type: item.op_type,
        asset_id: item.asset_id.clone(),
        from_owner_id: item.from_owner_id.clone(),
        to_owner_id: item.to_owner_id.clone(),
        amount: item.amount.clone(),
    }
});
from!(item: &cryptix_rpc_core::RpcTokenOwnerBalance, protowire::RpcTokenOwnerBalanceMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        balance: item.balance.clone(),
        asset: item.asset.as_ref().map(Into::into),
    }
});
from!(item: &cryptix_rpc_core::RpcTokenHolder, protowire::RpcTokenHolderMessage, {
    Self { owner_id: item.owner_id.clone(), balance: item.balance.clone() }
});
from!(item: &cryptix_rpc_core::RpcLiquidityFeeRecipient, protowire::RpcLiquidityFeeRecipientMessage, {
    Self { owner_id: item.owner_id.clone(), address: item.address.clone(), unclaimed_sompi: item.unclaimed_sompi.clone() }
});
from!(item: &cryptix_rpc_core::RpcLiquidityPoolState, protowire::RpcLiquidityPoolStateMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        pool_nonce: item.pool_nonce,
        fee_bps: item.fee_bps,
        max_supply: item.max_supply.clone(),
        total_supply: item.total_supply.clone(),
        circulating_supply: item.circulating_supply.clone(),
        remaining_pool_supply: item.remaining_pool_supply.clone(),
        curve_reserve_sompi: item.curve_reserve_sompi.clone(),
        unclaimed_fee_total_sompi: item.unclaimed_fee_total_sompi.clone(),
        vault_value_sompi: item.vault_value_sompi.clone(),
        vault_txid: item.vault_txid.to_string(),
        vault_output_index: item.vault_output_index,
        fee_recipients: item.fee_recipients.iter().map(Into::into).collect(),
    }
});
from!(item: &cryptix_rpc_core::RpcLiquidityHolder, protowire::RpcLiquidityHolderMessage, {
    Self { address: item.address.clone(), owner_id: item.owner_id.clone(), balance: item.balance.clone() }
});
from!(item: &cryptix_rpc_core::SimulateTokenOpRequest, protowire::SimulateTokenOpRequestMessage, {
    Self {
        payload_hex: item.payload_hex.clone(),
        owner_id: item.owner_id.clone(),
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::SimulateTokenOpResponse>, protowire::SimulateTokenOpResponseMessage, {
    Self {
        result: item.result.clone(),
        noop_reason: item.noop_reason,
        expected_next_nonce: item.expected_next_nonce,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetTokenBalanceRequest, protowire::GetTokenBalanceRequestMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        owner_id: item.owner_id.clone(),
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenBalanceResponse>, protowire::GetTokenBalanceResponseMessage, {
    Self { balance: item.balance.clone(), context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetTokenNonceRequest, protowire::GetTokenNonceRequestMessage, {
    Self { owner_id: item.owner_id.clone(), at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenNonceResponse>, protowire::GetTokenNonceResponseMessage, {
    Self { expected_next_nonce: item.expected_next_nonce, context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetTokenAssetRequest, protowire::GetTokenAssetRequestMessage, {
    Self { asset_id: item.asset_id.clone(), at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenAssetResponse>, protowire::GetTokenAssetResponseMessage, {
    Self { asset: item.asset.as_ref().map(Into::into), context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetTokenOpStatusRequest, protowire::GetTokenOpStatusRequestMessage, {
    Self { txid: item.txid.to_string(), at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenOpStatusResponse>, protowire::GetTokenOpStatusResponseMessage, {
    Self {
        accepting_block_hash: item.accepting_block_hash.map(|hash| hash.to_string()),
        apply_status: item.apply_status,
        noop_reason: item.noop_reason,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetTokenStateHashRequest, protowire::GetTokenStateHashRequestMessage, {
    Self { at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenStateHashResponse>, protowire::GetTokenStateHashResponseMessage, {
    Self { context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetTokenSpendabilityRequest, protowire::GetTokenSpendabilityRequestMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        owner_id: item.owner_id.clone(),
        min_daa_for_spend: item.min_daa_for_spend,
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenSpendabilityResponse>, protowire::GetTokenSpendabilityResponseMessage, {
    Self {
        can_spend: item.can_spend,
        reason: item.reason.clone(),
        balance: item.balance.clone(),
        expected_next_nonce: item.expected_next_nonce,
        min_daa_for_spend: item.min_daa_for_spend,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetTokenEventsRequest, protowire::GetTokenEventsRequestMessage, {
    Self {
        after_sequence: item.after_sequence,
        limit: item.limit,
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenEventsResponse>, protowire::GetTokenEventsResponseMessage, {
    Self { events: item.events.iter().map(Into::into).collect(), context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetTokenAssetsRequest, protowire::GetTokenAssetsRequestMessage, {
    Self {
        offset: item.offset,
        limit: item.limit,
        query: item.query.clone(),
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenAssetsResponse>, protowire::GetTokenAssetsResponseMessage, {
    Self {
        assets: item.assets.iter().map(Into::into).collect(),
        total: item.total,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetTokenBalancesByOwnerRequest, protowire::GetTokenBalancesByOwnerRequestMessage, {
    Self {
        owner_id: item.owner_id.clone(),
        offset: item.offset,
        limit: item.limit,
        include_assets: item.include_assets,
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenBalancesByOwnerResponse>, protowire::GetTokenBalancesByOwnerResponseMessage, {
    Self {
        balances: item.balances.iter().map(Into::into).collect(),
        total: item.total,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetTokenHoldersRequest, protowire::GetTokenHoldersRequestMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        offset: item.offset,
        limit: item.limit,
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenHoldersResponse>, protowire::GetTokenHoldersResponseMessage, {
    Self {
        holders: item.holders.iter().map(Into::into).collect(),
        total: item.total,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetTokenOwnerIdByAddressRequest, protowire::GetTokenOwnerIdByAddressRequestMessage, {
    Self { address: item.address.clone(), at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenOwnerIdByAddressResponse>, protowire::GetTokenOwnerIdByAddressResponseMessage, {
    Self {
        owner_id: item.owner_id.clone(),
        reason: item.reason.clone(),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetLiquidityPoolStateRequest, protowire::GetLiquidityPoolStateRequestMessage, {
    Self { asset_id: item.asset_id.clone(), at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetLiquidityPoolStateResponse>, protowire::GetLiquidityPoolStateResponseMessage, {
    Self {
        pool: item.pool.as_ref().map(Into::into),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetLiquidityQuoteRequest, protowire::GetLiquidityQuoteRequestMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        side: item.side,
        exact_in_amount: item.exact_in_amount.clone(),
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetLiquidityQuoteResponse>, protowire::GetLiquidityQuoteResponseMessage, {
    Self {
        side: item.side,
        exact_in_amount: item.exact_in_amount.clone(),
        fee_amount_sompi: item.fee_amount_sompi.clone(),
        net_in_amount: item.net_in_amount.clone(),
        amount_out: item.amount_out.clone(),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetLiquidityFeeStateRequest, protowire::GetLiquidityFeeStateRequestMessage, {
    Self { asset_id: item.asset_id.clone(), at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetLiquidityFeeStateResponse>, protowire::GetLiquidityFeeStateResponseMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        fee_bps: item.fee_bps,
        total_unclaimed_sompi: item.total_unclaimed_sompi.clone(),
        recipients: item.recipients.iter().map(Into::into).collect(),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetLiquidityClaimPreviewRequest, protowire::GetLiquidityClaimPreviewRequestMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        recipient_address: item.recipient_address.clone(),
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(
    item: RpcResult<&cryptix_rpc_core::GetLiquidityClaimPreviewResponse>,
    protowire::GetLiquidityClaimPreviewResponseMessage,
    {
        Self {
            recipient_address: item.recipient_address.clone(),
            owner_id: item.owner_id.clone(),
            claimable_amount_sompi: item.claimable_amount_sompi.clone(),
            min_payout_sompi: item.min_payout_sompi.clone(),
            claimable_now: item.claimable_now,
            reason: item.reason.clone(),
            context: Some((&item.context).into()),
            error: None,
        }
    }
);
from!(item: &cryptix_rpc_core::GetLiquidityHoldersRequest, protowire::GetLiquidityHoldersRequestMessage, {
    Self {
        asset_id: item.asset_id.clone(),
        offset: item.offset,
        limit: item.limit,
        at_block_hash: item.at_block_hash.map(|hash| hash.to_string()),
    }
});
from!(item: RpcResult<&cryptix_rpc_core::GetLiquidityHoldersResponse>, protowire::GetLiquidityHoldersResponseMessage, {
    Self {
        holders: item.holders.iter().map(Into::into).collect(),
        total: item.total,
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::ExportTokenSnapshotRequest, protowire::ExportTokenSnapshotRequestMessage, {
    Self { path: item.path.clone() }
});
from!(item: RpcResult<&cryptix_rpc_core::ExportTokenSnapshotResponse>, protowire::ExportTokenSnapshotResponseMessage, {
    Self { exported: item.exported, context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::ImportTokenSnapshotRequest, protowire::ImportTokenSnapshotRequestMessage, {
    Self { path: item.path.clone() }
});
from!(item: RpcResult<&cryptix_rpc_core::ImportTokenSnapshotResponse>, protowire::ImportTokenSnapshotResponseMessage, {
    Self { imported: item.imported, context: Some((&item.context).into()), error: None }
});
from!(item: &cryptix_rpc_core::GetTokenHealthRequest, protowire::GetTokenHealthRequestMessage, {
    Self { at_block_hash: item.at_block_hash.map(|hash| hash.to_string()) }
});
from!(item: RpcResult<&cryptix_rpc_core::GetTokenHealthResponse>, protowire::GetTokenHealthResponseMessage, {
    Self {
        is_degraded: item.is_degraded,
        bootstrap_in_progress: item.bootstrap_in_progress,
        live_correct: item.live_correct,
        token_state: item.token_state.clone(),
        last_applied_block: item.last_applied_block.map(|hash| hash.to_string()),
        last_sequence: item.last_sequence,
        state_hash: item.state_hash.clone(),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::RpcScBootstrapSource, protowire::RpcScBootstrapSourceMessage, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        protocol_version: item.protocol_version,
        network_id: item.network_id.clone(),
        node_identity: item.node_identity.clone(),
        at_block_hash: item.at_block_hash.to_string(),
        at_daa_score: item.at_daa_score,
        state_hash_at_fp: item.state_hash_at_fp.clone(),
        window_start_block_hash: item.window_start_block_hash.to_string(),
        window_end_block_hash: item.window_end_block_hash.to_string(),
    }
});
from!(item: &cryptix_rpc_core::RpcScManifestSignature, protowire::RpcScManifestSignatureMessage, {
    Self { signer_pubkey_hex: item.signer_pubkey_hex.clone(), signature_hex: item.signature_hex.clone() }
});
from!(&cryptix_rpc_core::GetScBootstrapSourcesRequest, protowire::GetScBootstrapSourcesRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetScBootstrapSourcesResponse>, protowire::GetScBootstrapSourcesResponseMessage, {
    Self {
        sources: item.sources.iter().map(Into::into).collect(),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetScSnapshotManifestRequest, protowire::GetScSnapshotManifestRequestMessage, {
    Self { snapshot_id: item.snapshot_id.clone() }
});
from!(item: RpcResult<&cryptix_rpc_core::GetScSnapshotManifestResponse>, protowire::GetScSnapshotManifestResponseMessage, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        manifest_hex: item.manifest_hex.clone(),
        manifest_signatures: item.manifest_signatures.iter().map(Into::into).collect(),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetScSnapshotChunkRequest, protowire::GetScSnapshotChunkRequestMessage, {
    Self { snapshot_id: item.snapshot_id.clone(), chunk_index: item.chunk_index, chunk_size: item.chunk_size }
});
from!(item: RpcResult<&cryptix_rpc_core::GetScSnapshotChunkResponse>, protowire::GetScSnapshotChunkResponseMessage, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        chunk_index: item.chunk_index,
        total_chunks: item.total_chunks,
        file_size: item.file_size,
        chunk_hex: item.chunk_hex.clone(),
        error: None,
    }
});
from!(item: &cryptix_rpc_core::GetScReplayWindowChunkRequest, protowire::GetScReplayWindowChunkRequestMessage, {
    Self { snapshot_id: item.snapshot_id.clone(), chunk_index: item.chunk_index, chunk_size: item.chunk_size }
});
from!(item: RpcResult<&cryptix_rpc_core::GetScReplayWindowChunkResponse>, protowire::GetScReplayWindowChunkResponseMessage, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        chunk_index: item.chunk_index,
        total_chunks: item.total_chunks,
        file_size: item.file_size,
        chunk_hex: item.chunk_hex.clone(),
        error: None,
    }
});
from!(&cryptix_rpc_core::GetScSnapshotHeadRequest, protowire::GetScSnapshotHeadRequestMessage);
from!(item: RpcResult<&cryptix_rpc_core::GetScSnapshotHeadResponse>, protowire::GetScSnapshotHeadResponseMessage, {
    Self {
        head: item.head.as_ref().map(Into::into),
        context: Some((&item.context).into()),
        error: None,
    }
});
from!(
    item: &cryptix_rpc_core::GetConsensusAtomicStateHashRequest,
    protowire::GetConsensusAtomicStateHashRequestMessage,
    { Self { block_hash: item.block_hash.to_string() } }
);
from!(
    item: RpcResult<&cryptix_rpc_core::GetConsensusAtomicStateHashResponse>,
    protowire::GetConsensusAtomicStateHashResponseMessage,
    { Self { state_hash: item.state_hash.clone(), error: None } }
);

from!(item: &cryptix_rpc_core::NotifyUtxosChangedRequest, protowire::NotifyUtxosChangedRequestMessage, {
    Self { addresses: item.addresses.iter().map(|x| x.into()).collect(), command: item.command.into() }
});
from!(item: &cryptix_rpc_core::NotifyUtxosChangedRequest, protowire::StopNotifyingUtxosChangedRequestMessage, {
    Self { addresses: item.addresses.iter().map(|x| x.into()).collect() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyUtxosChangedResponse>, protowire::NotifyUtxosChangedResponseMessage);
from!(RpcResult<&cryptix_rpc_core::NotifyUtxosChangedResponse>, protowire::StopNotifyingUtxosChangedResponseMessage);

from!(item: &cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideRequest, protowire::NotifyPruningPointUtxoSetOverrideRequestMessage, {
    Self { command: item.command.into() }
});
from!(&cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideRequest, protowire::StopNotifyingPruningPointUtxoSetOverrideRequestMessage);
from!(
    RpcResult<&cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideResponse>,
    protowire::NotifyPruningPointUtxoSetOverrideResponseMessage
);
from!(
    RpcResult<&cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideResponse>,
    protowire::StopNotifyingPruningPointUtxoSetOverrideResponseMessage
);

from!(item: &cryptix_rpc_core::NotifyFinalityConflictRequest, protowire::NotifyFinalityConflictRequestMessage, {
    Self { command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyFinalityConflictResponse>, protowire::NotifyFinalityConflictResponseMessage);

from!(item: &cryptix_rpc_core::NotifyVirtualDaaScoreChangedRequest, protowire::NotifyVirtualDaaScoreChangedRequestMessage, {
    Self { command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyVirtualDaaScoreChangedResponse>, protowire::NotifyVirtualDaaScoreChangedResponseMessage);

from!(item: &cryptix_rpc_core::NotifyVirtualChainChangedRequest, protowire::NotifyVirtualChainChangedRequestMessage, {
    Self { include_accepted_transaction_ids: item.include_accepted_transaction_ids, command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifyVirtualChainChangedResponse>, protowire::NotifyVirtualChainChangedResponseMessage);

from!(item: &cryptix_rpc_core::NotifySinkBlueScoreChangedRequest, protowire::NotifySinkBlueScoreChangedRequestMessage, {
    Self { command: item.command.into() }
});
from!(RpcResult<&cryptix_rpc_core::NotifySinkBlueScoreChangedResponse>, protowire::NotifySinkBlueScoreChangedResponseMessage);

// ----------------------------------------------------------------------------
// protowire to rpc_core
// ----------------------------------------------------------------------------

from!(item: RejectReason, cryptix_rpc_core::SubmitBlockReport, {
    match item {
        RejectReason::None => cryptix_rpc_core::SubmitBlockReport::Success,
        RejectReason::BlockInvalid => cryptix_rpc_core::SubmitBlockReport::Reject(cryptix_rpc_core::SubmitBlockRejectReason::BlockInvalid),
        RejectReason::IsInIbd => cryptix_rpc_core::SubmitBlockReport::Reject(cryptix_rpc_core::SubmitBlockRejectReason::IsInIBD),
    }
});

try_from!(item: &protowire::SubmitBlockRequestMessage, cryptix_rpc_core::SubmitBlockRequest, {
    Self {
        block: item
            .block
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("SubmitBlockRequestMessage".to_string(), "block".to_string()))?
            .try_into()?,
        allow_non_daa_blocks: item.allow_non_daa_blocks,
    }
});
impl TryFrom<&protowire::SubmitBlockResponseMessage> for cryptix_rpc_core::SubmitBlockResponse {
    type Error = RpcError;
    // This conversion breaks the general conversion convention (see file header) since the message may
    // contain both a non-None reject_reason and a matching error message. Things get even challenging
    // in the RouteIsFull case where reject_reason is None (because this reason has no variant in protowire)
    // but a specific error message is provided.
    fn try_from(item: &protowire::SubmitBlockResponseMessage) -> RpcResult<Self> {
        let report: SubmitBlockReport =
            RejectReason::try_from(item.reject_reason).map_err(|_| RpcError::PrimitiveToEnumConversionError)?.into();
        if let Some(ref err) = item.error {
            match report {
                SubmitBlockReport::Success => {
                    if err.message == RpcError::SubmitBlockError(SubmitBlockRejectReason::RouteIsFull).to_string() {
                        Ok(Self { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::RouteIsFull) })
                    } else {
                        Err(err.into())
                    }
                }
                SubmitBlockReport::Reject(_) => Ok(Self { report }),
            }
        } else {
            Ok(Self { report })
        }
    }
}

try_from!(item: &protowire::GetBlockTemplateRequestMessage, cryptix_rpc_core::GetBlockTemplateRequest, {
    Self { pay_address: item.pay_address.clone().try_into()?, extra_data: RpcExtraData::from_iter(item.extra_data.bytes()) }
});
try_from!(item: &protowire::GetBlockTemplateResponseMessage, RpcResult<cryptix_rpc_core::GetBlockTemplateResponse>, {
    Self {
        block: item
            .block
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetBlockTemplateResponseMessage".to_string(), "block".to_string()))?
            .try_into()?,
        is_synced: item.is_synced,
    }
});

try_from!(item: &protowire::GetBlockRequestMessage, cryptix_rpc_core::GetBlockRequest, {
    Self { hash: RpcHash::from_str(&item.hash)?, include_transactions: item.include_transactions }
});
try_from!(item: &protowire::GetBlockResponseMessage, RpcResult<cryptix_rpc_core::GetBlockResponse>, {
    Self {
        block: item
            .block
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetBlockResponseMessage".to_string(), "block".to_string()))?
            .try_into()?,
    }
});

try_from!(item: &protowire::NotifyBlockAddedRequestMessage, cryptix_rpc_core::NotifyBlockAddedRequest, {
    Self { command: item.command.into() }
});
try_from!(&protowire::NotifyBlockAddedResponseMessage, RpcResult<cryptix_rpc_core::NotifyBlockAddedResponse>);

try_from!(&protowire::GetInfoRequestMessage, cryptix_rpc_core::GetInfoRequest);
try_from!(item: &protowire::GetInfoResponseMessage, RpcResult<cryptix_rpc_core::GetInfoResponse>, {
    Self {
        p2p_id: item.p2p_id.clone(),
        mempool_size: item.mempool_size,
        server_version: item.server_version.clone(),
        is_utxo_indexed: item.is_utxo_indexed,
        is_synced: item.is_synced,
        has_notify_command: item.has_notify_command,
        has_message_id: item.has_message_id,
    }
});

try_from!(item: &protowire::NotifyNewBlockTemplateRequestMessage, cryptix_rpc_core::NotifyNewBlockTemplateRequest, {
    Self { command: item.command.into() }
});
try_from!(&protowire::NotifyNewBlockTemplateResponseMessage, RpcResult<cryptix_rpc_core::NotifyNewBlockTemplateResponse>);

// ~~~

try_from!(&protowire::GetCurrentNetworkRequestMessage, cryptix_rpc_core::GetCurrentNetworkRequest);
try_from!(item: &protowire::GetCurrentNetworkResponseMessage, RpcResult<cryptix_rpc_core::GetCurrentNetworkResponse>, {
    // Note that current_network is first converted to lowercase because the golang implementation
    // returns a "human readable" version with a capital first letter while the rusty version
    // is fully lowercase.
    Self { network: RpcNetworkType::from_str(&item.current_network.to_lowercase())? }
});

try_from!(&protowire::GetPeerAddressesRequestMessage, cryptix_rpc_core::GetPeerAddressesRequest);
try_from!(item: &protowire::GetPeerAddressesResponseMessage, RpcResult<cryptix_rpc_core::GetPeerAddressesResponse>, {
    Self {
        known_addresses: item.addresses.iter().map(RpcPeerAddress::try_from).collect::<Result<Vec<_>, _>>()?,
        banned_addresses: item.banned_addresses.iter().map(RpcIpAddress::try_from).collect::<Result<Vec<_>, _>>()?,
    }
});

try_from!(&protowire::GetSinkRequestMessage, cryptix_rpc_core::GetSinkRequest);
try_from!(item: &protowire::GetSinkResponseMessage, RpcResult<cryptix_rpc_core::GetSinkResponse>, {
    Self { sink: RpcHash::from_str(&item.sink)? }
});

try_from!(item: &protowire::GetMempoolEntryRequestMessage, cryptix_rpc_core::GetMempoolEntryRequest, {
    Self {
        transaction_id: cryptix_rpc_core::RpcTransactionId::from_str(&item.tx_id)?,
        include_orphan_pool: item.include_orphan_pool,
        filter_transaction_pool: item.filter_transaction_pool,
    }
});
try_from!(item: &protowire::GetMempoolEntryResponseMessage, RpcResult<cryptix_rpc_core::GetMempoolEntryResponse>, {
    Self {
        mempool_entry: item
            .entry
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetMempoolEntryResponseMessage".to_string(), "entry".to_string()))?
            .try_into()?,
    }
});

try_from!(item: &protowire::GetMempoolEntriesRequestMessage, cryptix_rpc_core::GetMempoolEntriesRequest, {
    Self { include_orphan_pool: item.include_orphan_pool, filter_transaction_pool: item.filter_transaction_pool }
});
try_from!(item: &protowire::GetMempoolEntriesResponseMessage, RpcResult<cryptix_rpc_core::GetMempoolEntriesResponse>, {
    Self { mempool_entries: item.entries.iter().map(cryptix_rpc_core::RpcMempoolEntry::try_from).collect::<Result<Vec<_>, _>>()? }
});

try_from!(&protowire::GetConnectedPeerInfoRequestMessage, cryptix_rpc_core::GetConnectedPeerInfoRequest);
try_from!(item: &protowire::GetConnectedPeerInfoResponseMessage, RpcResult<cryptix_rpc_core::GetConnectedPeerInfoResponse>, {
    Self { peer_info: item.infos.iter().map(cryptix_rpc_core::RpcPeerInfo::try_from).collect::<Result<Vec<_>, _>>()? }
});

try_from!(item: &protowire::AddPeerRequestMessage, cryptix_rpc_core::AddPeerRequest, {
    Self { peer_address: RpcContextualPeerAddress::from_str(&item.address)?, is_permanent: item.is_permanent }
});
try_from!(&protowire::AddPeerResponseMessage, RpcResult<cryptix_rpc_core::AddPeerResponse>);

try_from!(item: &protowire::SubmitTransactionRequestMessage, cryptix_rpc_core::SubmitTransactionRequest, {
    Self {
        transaction: item
            .transaction
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("SubmitTransactionRequestMessage".to_string(), "transaction".to_string()))?
            .try_into()?,
        allow_orphan: item.allow_orphan,
    }
});
try_from!(item: &protowire::SubmitTransactionResponseMessage, RpcResult<cryptix_rpc_core::SubmitTransactionResponse>, {
    Self { transaction_id: RpcHash::from_str(&item.transaction_id)? }
});

try_from!(item: &protowire::SubmitTransactionReplacementRequestMessage, cryptix_rpc_core::SubmitTransactionReplacementRequest, {
    Self {
        transaction: item
            .transaction
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("SubmitTransactionReplacementRequestMessage".to_string(), "transaction".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::SubmitTransactionReplacementResponseMessage, RpcResult<cryptix_rpc_core::SubmitTransactionReplacementResponse>, {
    Self {
        transaction_id: RpcHash::from_str(&item.transaction_id)?,
        replaced_transaction: item
            .replaced_transaction
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("SubmitTransactionReplacementRequestMessage".to_string(), "replaced_transaction".to_string()))?
            .try_into()?,
    }
});

try_from!(item: &protowire::GetSubnetworkRequestMessage, cryptix_rpc_core::GetSubnetworkRequest, {
    Self { subnetwork_id: cryptix_rpc_core::RpcSubnetworkId::from_str(&item.subnetwork_id)? }
});
try_from!(item: &protowire::GetSubnetworkResponseMessage, RpcResult<cryptix_rpc_core::GetSubnetworkResponse>, {
    Self { gas_limit: item.gas_limit }
});

try_from!(item: &protowire::GetVirtualChainFromBlockRequestMessage, cryptix_rpc_core::GetVirtualChainFromBlockRequest, {
    Self { start_hash: RpcHash::from_str(&item.start_hash)?, include_accepted_transaction_ids: item.include_accepted_transaction_ids }
});
try_from!(item: &protowire::GetVirtualChainFromBlockResponseMessage, RpcResult<cryptix_rpc_core::GetVirtualChainFromBlockResponse>, {
    Self {
        removed_chain_block_hashes: item
            .removed_chain_block_hashes
            .iter()
            .map(|x| RpcHash::from_str(x))
            .collect::<Result<Vec<_>, _>>()?,
        added_chain_block_hashes: item.added_chain_block_hashes.iter().map(|x| RpcHash::from_str(x)).collect::<Result<Vec<_>, _>>()?,
        accepted_transaction_ids: item.accepted_transaction_ids.iter().map(|x| x.try_into()).collect::<Result<Vec<_>, _>>()?,
    }
});

try_from!(item: &protowire::GetBlocksRequestMessage, cryptix_rpc_core::GetBlocksRequest, {
    Self {
        low_hash: if item.low_hash.is_empty() { None } else { Some(RpcHash::from_str(&item.low_hash)?) },
        include_blocks: item.include_blocks,
        include_transactions: item.include_transactions,
    }
});
try_from!(item: &protowire::GetBlocksResponseMessage, RpcResult<cryptix_rpc_core::GetBlocksResponse>, {
    Self {
        block_hashes: item.block_hashes.iter().map(|x| RpcHash::from_str(x)).collect::<Result<Vec<_>, _>>()?,
        blocks: item.blocks.iter().map(|x| x.try_into()).collect::<Result<Vec<_>, _>>()?,
    }
});

try_from!(&protowire::GetBlockCountRequestMessage, cryptix_rpc_core::GetBlockCountRequest);
try_from!(item: &protowire::GetBlockCountResponseMessage, RpcResult<cryptix_rpc_core::GetBlockCountResponse>, {
    Self { header_count: item.header_count, block_count: item.block_count }
});

try_from!(&protowire::GetBlockDagInfoRequestMessage, cryptix_rpc_core::GetBlockDagInfoRequest);
try_from!(item: &protowire::GetBlockDagInfoResponseMessage, RpcResult<cryptix_rpc_core::GetBlockDagInfoResponse>, {
    Self {
        network: cryptix_rpc_core::RpcNetworkId::from_prefixed(&item.network_name)?,
        block_count: item.block_count,
        header_count: item.header_count,
        tip_hashes: item.tip_hashes.iter().map(|x| RpcHash::from_str(x)).collect::<Result<Vec<_>, _>>()?,
        difficulty: item.difficulty,
        past_median_time: item.past_median_time as u64,
        virtual_parent_hashes: item.virtual_parent_hashes.iter().map(|x| RpcHash::from_str(x)).collect::<Result<Vec<_>, _>>()?,
        pruning_point_hash: RpcHash::from_str(&item.pruning_point_hash)?,
        virtual_daa_score: item.virtual_daa_score,
        sink: item.sink.parse()?,
    }
});

try_from!(item: &protowire::ResolveFinalityConflictRequestMessage, cryptix_rpc_core::ResolveFinalityConflictRequest, {
    Self { finality_block_hash: RpcHash::from_str(&item.finality_block_hash)? }
});
try_from!(&protowire::ResolveFinalityConflictResponseMessage, RpcResult<cryptix_rpc_core::ResolveFinalityConflictResponse>);

try_from!(&protowire::ShutdownRequestMessage, cryptix_rpc_core::ShutdownRequest);
try_from!(&protowire::ShutdownResponseMessage, RpcResult<cryptix_rpc_core::ShutdownResponse>);

try_from!(item: &protowire::GetHeadersRequestMessage, cryptix_rpc_core::GetHeadersRequest, {
    Self { start_hash: RpcHash::from_str(&item.start_hash)?, limit: item.limit, is_ascending: item.is_ascending }
});
try_from!(item: &protowire::GetHeadersResponseMessage, RpcResult<cryptix_rpc_core::GetHeadersResponse>, {
    // TODO
    Self { headers: vec![] }
});

try_from!(item: &protowire::GetUtxosByAddressesRequestMessage, cryptix_rpc_core::GetUtxosByAddressesRequest, {
    Self { addresses: item.addresses.iter().map(|x| x.as_str().try_into()).collect::<Result<Vec<_>, _>>()? }
});
try_from!(item: &protowire::GetUtxosByAddressesResponseMessage, RpcResult<cryptix_rpc_core::GetUtxosByAddressesResponse>, {
    Self { entries: item.entries.iter().map(|x| x.try_into()).collect::<Result<Vec<_>, _>>()? }
});

try_from!(item: &protowire::GetBalanceByAddressRequestMessage, cryptix_rpc_core::GetBalanceByAddressRequest, {
    Self { address: item.address.as_str().try_into()? }
});
try_from!(item: &protowire::GetBalanceByAddressResponseMessage, RpcResult<cryptix_rpc_core::GetBalanceByAddressResponse>, {
    Self { balance: item.balance }
});

try_from!(item: &protowire::GetBalancesByAddressesRequestMessage, cryptix_rpc_core::GetBalancesByAddressesRequest, {
    Self { addresses: item.addresses.iter().map(|x| x.as_str().try_into()).collect::<Result<Vec<_>, _>>()? }
});
try_from!(item: &protowire::GetBalancesByAddressesResponseMessage, RpcResult<cryptix_rpc_core::GetBalancesByAddressesResponse>, {
    Self { entries: item.entries.iter().map(|x| x.try_into()).collect::<Result<Vec<_>, _>>()? }
});

try_from!(&protowire::GetSinkBlueScoreRequestMessage, cryptix_rpc_core::GetSinkBlueScoreRequest);
try_from!(item: &protowire::GetSinkBlueScoreResponseMessage, RpcResult<cryptix_rpc_core::GetSinkBlueScoreResponse>, {
    Self { blue_score: item.blue_score }
});

try_from!(item: &protowire::BanRequestMessage, cryptix_rpc_core::BanRequest, { Self { ip: RpcIpAddress::from_str(&item.ip)? } });
try_from!(&protowire::BanResponseMessage, RpcResult<cryptix_rpc_core::BanResponse>);

try_from!(item: &protowire::UnbanRequestMessage, cryptix_rpc_core::UnbanRequest, { Self { ip: RpcIpAddress::from_str(&item.ip)? } });
try_from!(&protowire::UnbanResponseMessage, RpcResult<cryptix_rpc_core::UnbanResponse>);

try_from!(item: &protowire::EstimateNetworkHashesPerSecondRequestMessage, cryptix_rpc_core::EstimateNetworkHashesPerSecondRequest, {
    Self {
        window_size: item.window_size,
        start_hash: if item.start_hash.is_empty() { None } else { Some(RpcHash::from_str(&item.start_hash)?) },
    }
});
try_from!(
    item: &protowire::EstimateNetworkHashesPerSecondResponseMessage,
    RpcResult<cryptix_rpc_core::EstimateNetworkHashesPerSecondResponse>,
    { Self { network_hashes_per_second: item.network_hashes_per_second } }
);

try_from!(item: &protowire::GetMempoolEntriesByAddressesRequestMessage, cryptix_rpc_core::GetMempoolEntriesByAddressesRequest, {
    Self {
        addresses: item.addresses.iter().map(|x| x.as_str().try_into()).collect::<Result<Vec<_>, _>>()?,
        include_orphan_pool: item.include_orphan_pool,
        filter_transaction_pool: item.filter_transaction_pool,
    }
});
try_from!(
    item: &protowire::GetMempoolEntriesByAddressesResponseMessage,
    RpcResult<cryptix_rpc_core::GetMempoolEntriesByAddressesResponse>,
    { Self { entries: item.entries.iter().map(|x| x.try_into()).collect::<Result<Vec<_>, _>>()? } }
);

try_from!(&protowire::GetCoinSupplyRequestMessage, cryptix_rpc_core::GetCoinSupplyRequest);
try_from!(item: &protowire::GetCoinSupplyResponseMessage, RpcResult<cryptix_rpc_core::GetCoinSupplyResponse>, {
    Self { max_sompi: item.max_sompi, circulating_sompi: item.circulating_sompi }
});

try_from!(item: &protowire::GetDaaScoreTimestampEstimateRequestMessage, cryptix_rpc_core::GetDaaScoreTimestampEstimateRequest , {
    Self {
        daa_scores: item.daa_scores.clone()
    }
});
try_from!(item: &protowire::GetDaaScoreTimestampEstimateResponseMessage, RpcResult<cryptix_rpc_core::GetDaaScoreTimestampEstimateResponse>, {
    Self { timestamps: item.timestamps.clone() }
});

try_from!(&protowire::GetFeeEstimateRequestMessage, cryptix_rpc_core::GetFeeEstimateRequest);
try_from!(item: &protowire::GetFeeEstimateResponseMessage, RpcResult<cryptix_rpc_core::GetFeeEstimateResponse>, {
    Self {
        estimate: item.estimate
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetFeeEstimateResponseMessage".to_string(), "estimate".to_string()))?
            .try_into()?
    }
});
try_from!(item: &protowire::GetFeeEstimateExperimentalRequestMessage, cryptix_rpc_core::GetFeeEstimateExperimentalRequest, {
    Self {
        verbose: item.verbose
    }
});
try_from!(item: &protowire::GetFeeEstimateExperimentalResponseMessage, RpcResult<cryptix_rpc_core::GetFeeEstimateExperimentalResponse>, {
    Self {
        estimate: item.estimate
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetFeeEstimateExperimentalResponseMessage".to_string(), "estimate".to_string()))?
            .try_into()?,
        verbose: item.verbose.as_ref().map(|x| x.try_into()).transpose()?
    }
});

try_from!(item: &protowire::GetCurrentBlockColorRequestMessage, cryptix_rpc_core::GetCurrentBlockColorRequest, {
    Self {
        hash: RpcHash::from_str(&item.hash)?
    }
});
try_from!(item: &protowire::GetCurrentBlockColorResponseMessage, RpcResult<cryptix_rpc_core::GetCurrentBlockColorResponse>, {
    Self {
        blue: item.blue
    }
});

try_from!(item: &protowire::SubmitFastIntentRequestMessage, cryptix_rpc_core::SubmitFastIntentRequest, {
    Self {
        base_tx: item
            .base_tx
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("SubmitFastIntentRequestMessage".to_string(), "base_tx".to_string()))?
            .try_into()?,
        intent_nonce: item.intent_nonce,
        client_created_at_ms: item.client_created_at_ms,
        max_fee: item.max_fee,
    }
});
try_from!(item: &protowire::SubmitFastIntentResponseMessage, RpcResult<cryptix_rpc_core::SubmitFastIntentResponse>, {
    Self {
        intent_id: RpcHash::from_str(&item.intent_id)?,
        status: fast_intent_status_from_proto(&item.status)?,
        reason: (!item.reason.is_empty()).then(|| item.reason.clone()),
        base_tx_id: (!item.base_tx_id.is_empty()).then(|| RpcHash::from_str(&item.base_tx_id)).transpose()?,
        node_epoch: item.node_epoch,
        expires_at_ms: (item.expires_at_ms != 0).then_some(item.expires_at_ms),
        retention_until_ms: (item.retention_until_ms != 0).then_some(item.retention_until_ms),
        cancel_token: (!item.cancel_token.is_empty()).then(|| item.cancel_token.clone()),
        basechain_submitted: item.basechain_submitted,
    }
});

try_from!(item: &protowire::GetFastIntentStatusRequestMessage, cryptix_rpc_core::GetFastIntentStatusRequest, {
    Self {
        intent_id: RpcHash::from_str(&item.intent_id)?,
        client_last_node_epoch: (item.client_last_node_epoch != 0).then_some(item.client_last_node_epoch),
    }
});
try_from!(item: &protowire::GetFastIntentStatusResponseMessage, RpcResult<cryptix_rpc_core::GetFastIntentStatusResponse>, {
    Self {
        status: fast_intent_status_from_proto(&item.status)?,
        reason: (!item.reason.is_empty()).then(|| item.reason.clone()),
        base_tx_id: (!item.base_tx_id.is_empty()).then(|| RpcHash::from_str(&item.base_tx_id)).transpose()?,
        node_epoch: item.node_epoch,
        expires_at_ms: (item.expires_at_ms != 0).then_some(item.expires_at_ms),
        retention_until_ms: (item.retention_until_ms != 0).then_some(item.retention_until_ms),
        cancel_token: (!item.cancel_token.is_empty()).then(|| item.cancel_token.clone()),
        epoch_changed: item.has_epoch_changed.then_some(item.epoch_changed),
    }
});

try_from!(item: &protowire::CancelFastIntentRequestMessage, cryptix_rpc_core::CancelFastIntentRequest, {
    Self {
        intent_id: RpcHash::from_str(&item.intent_id)?,
        cancel_token: item.cancel_token.clone(),
        node_epoch: item.node_epoch,
    }
});
try_from!(item: &protowire::CancelFastIntentResponseMessage, RpcResult<cryptix_rpc_core::CancelFastIntentResponse>, {
    Self {
        status: fast_intent_status_from_proto(&item.status)?,
        reason: (!item.reason.is_empty()).then(|| item.reason.clone()),
        node_epoch: item.node_epoch,
        retention_until_ms: (item.retention_until_ms != 0).then_some(item.retention_until_ms),
        epoch_changed: item.has_epoch_changed.then_some(item.epoch_changed),
    }
});

try_from!(&protowire::PingRequestMessage, cryptix_rpc_core::PingRequest);
try_from!(&protowire::PingResponseMessage, RpcResult<cryptix_rpc_core::PingResponse>);

try_from!(item: &protowire::GetMetricsRequestMessage, cryptix_rpc_core::GetMetricsRequest, {
    Self {
        process_metrics: item.process_metrics,
        connection_metrics: item.connection_metrics,
        bandwidth_metrics:item.bandwidth_metrics,
        consensus_metrics: item.consensus_metrics,
        storage_metrics: item.storage_metrics,
        custom_metrics : item.custom_metrics,
    }
});
try_from!(item: &protowire::GetMetricsResponseMessage, RpcResult<cryptix_rpc_core::GetMetricsResponse>, {
    Self {
        server_time: item.server_time,
        process_metrics: item.process_metrics.as_ref().map(|x| x.try_into()).transpose()?,
        connection_metrics: item.connection_metrics.as_ref().map(|x| x.try_into()).transpose()?,
        bandwidth_metrics: item.bandwidth_metrics.as_ref().map(|x| x.try_into()).transpose()?,
        consensus_metrics: item.consensus_metrics.as_ref().map(|x| x.try_into()).transpose()?,
        storage_metrics: item.storage_metrics.as_ref().map(|x| x.try_into()).transpose()?,
        custom_metrics: if item.custom_metrics.is_empty() {
            None
        } else {
            Some(
                item.custom_metrics
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), v.try_into()?)))
                    .collect::<RpcResult<HashMap<String, cryptix_rpc_core::CustomMetricValue>>>()?,
            )
        },
    }
});

try_from!(item: &protowire::GetConnectionsRequestMessage, cryptix_rpc_core::GetConnectionsRequest, {
    Self { include_profile_data : item.include_profile_data }
});
try_from!(item: &protowire::GetConnectionsResponseMessage, RpcResult<cryptix_rpc_core::GetConnectionsResponse>, {
    Self {
        clients: item.clients,
        peers: item.peers as u16,
        profile_data: item.profile_data.as_ref().map(|x| x.try_into()).transpose()?,
    }
});

try_from!(&protowire::GetSystemInfoRequestMessage, cryptix_rpc_core::GetSystemInfoRequest);
try_from!(item: &protowire::GetSystemInfoResponseMessage, RpcResult<cryptix_rpc_core::GetSystemInfoResponse>, {
    Self {
        version: item.version.clone(),
        system_id: (!item.system_id.is_empty()).then(|| FromHex::from_hex(&item.system_id)).transpose()?,
        git_hash: (!item.git_hash.is_empty()).then(|| FromHex::from_hex(&item.git_hash)).transpose()?,
        total_memory: item.total_memory,
        cpu_physical_cores: item.core_num as u16,
        fd_limit: item.fd_limit,
        proxy_socket_limit_per_cpu_core : (item.proxy_socket_limit_per_cpu_core > 0).then_some(item.proxy_socket_limit_per_cpu_core),
    }
});

try_from!(&protowire::GetServerInfoRequestMessage, cryptix_rpc_core::GetServerInfoRequest);
try_from!(item: &protowire::GetServerInfoResponseMessage, RpcResult<cryptix_rpc_core::GetServerInfoResponse>, {
    Self {
        rpc_api_version: item.rpc_api_version as u16,
        rpc_api_revision: item.rpc_api_revision as u16,
        server_version: item.server_version.clone(),
        network_id: NetworkId::from_str(&item.network_id)?,
        has_utxo_index: item.has_utxo_index,
        is_synced: item.is_synced,
        virtual_daa_score: item.virtual_daa_score,
    }
});

try_from!(&protowire::GetSyncStatusRequestMessage, cryptix_rpc_core::GetSyncStatusRequest);
try_from!(item: &protowire::GetSyncStatusResponseMessage, RpcResult<cryptix_rpc_core::GetSyncStatusResponse>, {
    Self {
        is_synced: item.is_synced,
    }
});
try_from!(&protowire::GetStrongNodesRequestMessage, cryptix_rpc_core::GetStrongNodesRequest);
try_from!(item: &protowire::RpcStrongNodeEntry, cryptix_rpc_core::RpcStrongNodeEntry, {
    Self {
        node_id: item.node_id.clone(),
        public_key_xonly: item.public_key_xonly.clone(),
        source: item.source.clone(),
        claimed_blocks: item.claimed_blocks,
        share_bps: item.share_bps,
        last_claim_block_hash: item.last_claim_block_hash.clone(),
        last_claim_time_ms: item.last_claim_time_ms,
    }
});
try_from!(item: &protowire::GetStrongNodesResponseMessage, RpcResult<cryptix_rpc_core::GetStrongNodesResponse>, {
    Self {
        enabled_by_config: item.enabled_by_config,
        hardfork_active: item.hardfork_active,
        runtime_available: item.runtime_available,
        disabled_reason_code: item.disabled_reason_code.clone(),
        disabled_reason_message: item.disabled_reason_message.clone(),
        conflict_total: item.conflict_total,
        window_size: item.window_size,
        entries: item.entries.iter().map(|entry| entry.try_into()).collect::<RpcResult<Vec<_>>>()?,
    }
});
try_from!(item: &protowire::RpcTokenContextMessage, cryptix_rpc_core::RpcTokenContext, {
    Self {
        at_block_hash: RpcHash::from_str(&item.at_block_hash)?,
        at_daa_score: item.at_daa_score,
        state_hash: item.state_hash.clone(),
        is_degraded: item.is_degraded,
    }
});
try_from!(item: &protowire::RpcTokenAssetMessage, cryptix_rpc_core::RpcTokenAsset, {
    Self {
        asset_id: item.asset_id.clone(),
        creator_owner_id: item.creator_owner_id.clone(),
        mint_authority_owner_id: item.mint_authority_owner_id.clone(),
        decimals: item.decimals,
        supply_mode: item.supply_mode,
        max_supply: item.max_supply.clone(),
        total_supply: item.total_supply.clone(),
        name: item.name.clone(),
        symbol: item.symbol.clone(),
        metadata_hex: item.metadata_hex.clone(),
        created_block_hash: item
            .created_block_hash
            .as_ref()
            .map(|hash| RpcHash::from_str(hash))
            .transpose()?,
        created_daa_score: item.created_daa_score,
        created_at: item.created_at,
    }
});
try_from!(item: &protowire::RpcTokenEventMessage, cryptix_rpc_core::RpcTokenEvent, {
    Self {
        event_id: item.event_id.clone(),
        sequence: item.sequence,
        accepting_block_hash: RpcHash::from_str(&item.accepting_block_hash)?,
        txid: RpcHash::from_str(&item.txid)?,
        event_type: item.event_type,
        apply_status: item.apply_status,
        noop_reason: item.noop_reason,
        ordinal: item.ordinal,
        reorg_of_event_id: item.reorg_of_event_id.clone(),
        op_type: item.op_type,
        asset_id: item.asset_id.clone(),
        from_owner_id: item.from_owner_id.clone(),
        to_owner_id: item.to_owner_id.clone(),
        amount: item.amount.clone(),
    }
});
try_from!(item: &protowire::RpcTokenOwnerBalanceMessage, cryptix_rpc_core::RpcTokenOwnerBalance, {
    Self { asset_id: item.asset_id.clone(), balance: item.balance.clone(), asset: item.asset.as_ref().map(|a| a.try_into()).transpose()? }
});
try_from!(item: &protowire::RpcTokenHolderMessage, cryptix_rpc_core::RpcTokenHolder, {
    Self { owner_id: item.owner_id.clone(), balance: item.balance.clone() }
});
try_from!(item: &protowire::RpcLiquidityFeeRecipientMessage, cryptix_rpc_core::RpcLiquidityFeeRecipient, {
    Self { owner_id: item.owner_id.clone(), address: item.address.clone(), unclaimed_sompi: item.unclaimed_sompi.clone() }
});
try_from!(item: &protowire::RpcLiquidityPoolStateMessage, cryptix_rpc_core::RpcLiquidityPoolState, {
    Self {
        asset_id: item.asset_id.clone(),
        pool_nonce: item.pool_nonce,
        fee_bps: item.fee_bps,
        max_supply: item.max_supply.clone(),
        total_supply: item.total_supply.clone(),
        circulating_supply: item.circulating_supply.clone(),
        remaining_pool_supply: item.remaining_pool_supply.clone(),
        curve_reserve_sompi: item.curve_reserve_sompi.clone(),
        unclaimed_fee_total_sompi: item.unclaimed_fee_total_sompi.clone(),
        vault_value_sompi: item.vault_value_sompi.clone(),
        vault_txid: RpcHash::from_str(&item.vault_txid)?,
        vault_output_index: item.vault_output_index,
        fee_recipients: item
            .fee_recipients
            .iter()
            .map(|recipient| recipient.try_into())
            .collect::<RpcResult<Vec<_>>>()?,
    }
});
try_from!(item: &protowire::RpcLiquidityHolderMessage, cryptix_rpc_core::RpcLiquidityHolder, {
    Self { address: item.address.clone(), owner_id: item.owner_id.clone(), balance: item.balance.clone() }
});
try_from!(item: &protowire::SimulateTokenOpRequestMessage, cryptix_rpc_core::SimulateTokenOpRequest, {
    Self {
        payload_hex: item.payload_hex.clone(),
        owner_id: item.owner_id.clone(),
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::SimulateTokenOpResponseMessage, RpcResult<cryptix_rpc_core::SimulateTokenOpResponse>, {
    Self {
        result: item.result.clone(),
        noop_reason: item.noop_reason,
        expected_next_nonce: item.expected_next_nonce,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("SimulateTokenOpResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenBalanceRequestMessage, cryptix_rpc_core::GetTokenBalanceRequest, {
    Self {
        asset_id: item.asset_id.clone(),
        owner_id: item.owner_id.clone(),
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetTokenBalanceResponseMessage, RpcResult<cryptix_rpc_core::GetTokenBalanceResponse>, {
    Self {
        balance: item.balance.clone(),
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenBalanceResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenNonceRequestMessage, cryptix_rpc_core::GetTokenNonceRequest, {
    Self { owner_id: item.owner_id.clone(), at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(item: &protowire::GetTokenNonceResponseMessage, RpcResult<cryptix_rpc_core::GetTokenNonceResponse>, {
    Self {
        expected_next_nonce: item.expected_next_nonce,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenNonceResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenAssetRequestMessage, cryptix_rpc_core::GetTokenAssetRequest, {
    Self { asset_id: item.asset_id.clone(), at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(item: &protowire::GetTokenAssetResponseMessage, RpcResult<cryptix_rpc_core::GetTokenAssetResponse>, {
    Self {
        asset: item.asset.as_ref().map(|asset| asset.try_into()).transpose()?,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenAssetResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenOpStatusRequestMessage, cryptix_rpc_core::GetTokenOpStatusRequest, {
    Self {
        txid: RpcHash::from_str(&item.txid)?,
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetTokenOpStatusResponseMessage, RpcResult<cryptix_rpc_core::GetTokenOpStatusResponse>, {
    Self {
        accepting_block_hash: item.accepting_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
        apply_status: item.apply_status,
        noop_reason: item.noop_reason,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenOpStatusResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenStateHashRequestMessage, cryptix_rpc_core::GetTokenStateHashRequest, {
    Self { at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(item: &protowire::GetTokenStateHashResponseMessage, RpcResult<cryptix_rpc_core::GetTokenStateHashResponse>, {
    Self {
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenStateHashResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenSpendabilityRequestMessage, cryptix_rpc_core::GetTokenSpendabilityRequest, {
    Self {
        asset_id: item.asset_id.clone(),
        owner_id: item.owner_id.clone(),
        min_daa_for_spend: item.min_daa_for_spend,
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(
    item: &protowire::GetTokenSpendabilityResponseMessage,
    RpcResult<cryptix_rpc_core::GetTokenSpendabilityResponse>,
    {
        Self {
            can_spend: item.can_spend,
            reason: item.reason.clone(),
            balance: item.balance.clone(),
            expected_next_nonce: item.expected_next_nonce,
            min_daa_for_spend: item.min_daa_for_spend,
            context: item
                .context
                .as_ref()
                .ok_or_else(|| {
                    RpcError::MissingRpcFieldError("GetTokenSpendabilityResponseMessage".to_string(), "context".to_string())
                })?
                .try_into()?,
        }
    }
);
try_from!(item: &protowire::GetTokenEventsRequestMessage, cryptix_rpc_core::GetTokenEventsRequest, {
    Self {
        after_sequence: item.after_sequence,
        limit: item.limit,
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetTokenEventsResponseMessage, RpcResult<cryptix_rpc_core::GetTokenEventsResponse>, {
    Self {
        events: item.events.iter().map(|event| event.try_into()).collect::<RpcResult<Vec<_>>>()?,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenEventsResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenAssetsRequestMessage, cryptix_rpc_core::GetTokenAssetsRequest, {
    Self {
        offset: item.offset,
        limit: item.limit,
        query: item.query.clone(),
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetTokenAssetsResponseMessage, RpcResult<cryptix_rpc_core::GetTokenAssetsResponse>, {
    Self {
        assets: item.assets.iter().map(|asset| asset.try_into()).collect::<RpcResult<Vec<_>>>()?,
        total: item.total,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenAssetsResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenBalancesByOwnerRequestMessage, cryptix_rpc_core::GetTokenBalancesByOwnerRequest, {
    Self {
        owner_id: item.owner_id.clone(),
        offset: item.offset,
        limit: item.limit,
        include_assets: item.include_assets,
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(
    item: &protowire::GetTokenBalancesByOwnerResponseMessage,
    RpcResult<cryptix_rpc_core::GetTokenBalancesByOwnerResponse>,
    {
        Self {
            balances: item.balances.iter().map(|balance| balance.try_into()).collect::<RpcResult<Vec<_>>>()?,
            total: item.total,
            context: item
                .context
                .as_ref()
                .ok_or_else(|| {
                    RpcError::MissingRpcFieldError("GetTokenBalancesByOwnerResponseMessage".to_string(), "context".to_string())
                })?
                .try_into()?,
        }
    }
);
try_from!(item: &protowire::GetTokenHoldersRequestMessage, cryptix_rpc_core::GetTokenHoldersRequest, {
    Self {
        asset_id: item.asset_id.clone(),
        offset: item.offset,
        limit: item.limit,
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetTokenHoldersResponseMessage, RpcResult<cryptix_rpc_core::GetTokenHoldersResponse>, {
    Self {
        holders: item.holders.iter().map(|holder| holder.try_into()).collect::<RpcResult<Vec<_>>>()?,
        total: item.total,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenHoldersResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetTokenOwnerIdByAddressRequestMessage, cryptix_rpc_core::GetTokenOwnerIdByAddressRequest, {
    Self { address: item.address.clone(), at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(
    item: &protowire::GetTokenOwnerIdByAddressResponseMessage,
    RpcResult<cryptix_rpc_core::GetTokenOwnerIdByAddressResponse>,
    {
        Self {
            owner_id: item.owner_id.clone(),
            reason: item.reason.clone(),
            context: item
                .context
                .as_ref()
                .ok_or_else(|| {
                    RpcError::MissingRpcFieldError("GetTokenOwnerIdByAddressResponseMessage".to_string(), "context".to_string())
                })?
                .try_into()?,
        }
    }
);
try_from!(item: &protowire::GetLiquidityPoolStateRequestMessage, cryptix_rpc_core::GetLiquidityPoolStateRequest, {
    Self { asset_id: item.asset_id.clone(), at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(item: &protowire::GetLiquidityPoolStateResponseMessage, RpcResult<cryptix_rpc_core::GetLiquidityPoolStateResponse>, {
    Self {
        pool: item.pool.as_ref().map(|pool| pool.try_into()).transpose()?,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetLiquidityPoolStateResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetLiquidityQuoteRequestMessage, cryptix_rpc_core::GetLiquidityQuoteRequest, {
    Self {
        asset_id: item.asset_id.clone(),
        side: item.side,
        exact_in_amount: item.exact_in_amount.clone(),
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetLiquidityQuoteResponseMessage, RpcResult<cryptix_rpc_core::GetLiquidityQuoteResponse>, {
    Self {
        side: item.side,
        exact_in_amount: item.exact_in_amount.clone(),
        fee_amount_sompi: item.fee_amount_sompi.clone(),
        net_in_amount: item.net_in_amount.clone(),
        amount_out: item.amount_out.clone(),
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetLiquidityQuoteResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetLiquidityFeeStateRequestMessage, cryptix_rpc_core::GetLiquidityFeeStateRequest, {
    Self { asset_id: item.asset_id.clone(), at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(item: &protowire::GetLiquidityFeeStateResponseMessage, RpcResult<cryptix_rpc_core::GetLiquidityFeeStateResponse>, {
    Self {
        asset_id: item.asset_id.clone(),
        fee_bps: item.fee_bps,
        total_unclaimed_sompi: item.total_unclaimed_sompi.clone(),
        recipients: item
            .recipients
            .iter()
            .map(|recipient| recipient.try_into())
            .collect::<RpcResult<Vec<_>>>()?,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetLiquidityFeeStateResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetLiquidityClaimPreviewRequestMessage, cryptix_rpc_core::GetLiquidityClaimPreviewRequest, {
    Self {
        asset_id: item.asset_id.clone(),
        recipient_address: item.recipient_address.clone(),
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(
    item: &protowire::GetLiquidityClaimPreviewResponseMessage,
    RpcResult<cryptix_rpc_core::GetLiquidityClaimPreviewResponse>,
    {
        Self {
            recipient_address: item.recipient_address.clone(),
            owner_id: item.owner_id.clone(),
            claimable_amount_sompi: item.claimable_amount_sompi.clone(),
            min_payout_sompi: item.min_payout_sompi.clone(),
            claimable_now: item.claimable_now,
            reason: item.reason.clone(),
            context: item
                .context
                .as_ref()
                .ok_or_else(|| {
                    RpcError::MissingRpcFieldError("GetLiquidityClaimPreviewResponseMessage".to_string(), "context".to_string())
                })?
                .try_into()?,
        }
    }
);
try_from!(item: &protowire::GetLiquidityHoldersRequestMessage, cryptix_rpc_core::GetLiquidityHoldersRequest, {
    Self {
        asset_id: item.asset_id.clone(),
        offset: item.offset,
        limit: item.limit,
        at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
    }
});
try_from!(item: &protowire::GetLiquidityHoldersResponseMessage, RpcResult<cryptix_rpc_core::GetLiquidityHoldersResponse>, {
    Self {
        holders: item.holders.iter().map(|holder| holder.try_into()).collect::<RpcResult<Vec<_>>>()?,
        total: item.total,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetLiquidityHoldersResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::ExportTokenSnapshotRequestMessage, cryptix_rpc_core::ExportTokenSnapshotRequest, {
    Self { path: item.path.clone() }
});
try_from!(
    item: &protowire::ExportTokenSnapshotResponseMessage,
    RpcResult<cryptix_rpc_core::ExportTokenSnapshotResponse>,
    {
        Self {
            exported: item.exported,
            context: item
                .context
                .as_ref()
                .ok_or_else(|| {
                    RpcError::MissingRpcFieldError("ExportTokenSnapshotResponseMessage".to_string(), "context".to_string())
                })?
                .try_into()?,
        }
    }
);
try_from!(item: &protowire::ImportTokenSnapshotRequestMessage, cryptix_rpc_core::ImportTokenSnapshotRequest, {
    Self { path: item.path.clone() }
});
try_from!(
    item: &protowire::ImportTokenSnapshotResponseMessage,
    RpcResult<cryptix_rpc_core::ImportTokenSnapshotResponse>,
    {
        Self {
            imported: item.imported,
            context: item
                .context
                .as_ref()
                .ok_or_else(|| {
                    RpcError::MissingRpcFieldError("ImportTokenSnapshotResponseMessage".to_string(), "context".to_string())
                })?
                .try_into()?,
        }
    }
);
try_from!(item: &protowire::GetTokenHealthRequestMessage, cryptix_rpc_core::GetTokenHealthRequest, {
    Self { at_block_hash: item.at_block_hash.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()? }
});
try_from!(item: &protowire::GetTokenHealthResponseMessage, RpcResult<cryptix_rpc_core::GetTokenHealthResponse>, {
    Self {
        is_degraded: item.is_degraded,
        bootstrap_in_progress: item.bootstrap_in_progress,
        live_correct: item.live_correct,
        token_state: if item.token_state.is_empty() {
            if item.is_degraded {
                "degraded".to_string()
            } else if item.bootstrap_in_progress {
                "recovering".to_string()
            } else if item.live_correct {
                "healthy".to_string()
            } else {
                "not_ready".to_string()
            }
        } else {
            item.token_state.clone()
        },
        last_applied_block: item.last_applied_block.as_ref().map(|hash| RpcHash::from_str(hash)).transpose()?,
        last_sequence: item.last_sequence,
        state_hash: item.state_hash.clone(),
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetTokenHealthResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::RpcScBootstrapSourceMessage, cryptix_rpc_core::RpcScBootstrapSource, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        protocol_version: item.protocol_version,
        network_id: item.network_id.clone(),
        node_identity: item.node_identity.clone(),
        at_block_hash: RpcHash::from_str(&item.at_block_hash)?,
        at_daa_score: item.at_daa_score,
        state_hash_at_fp: item.state_hash_at_fp.clone(),
        window_start_block_hash: RpcHash::from_str(&item.window_start_block_hash)?,
        window_end_block_hash: RpcHash::from_str(&item.window_end_block_hash)?,
    }
});
try_from!(item: &protowire::RpcScManifestSignatureMessage, cryptix_rpc_core::RpcScManifestSignature, {
    Self { signer_pubkey_hex: item.signer_pubkey_hex.clone(), signature_hex: item.signature_hex.clone() }
});
try_from!(_item: &protowire::GetScBootstrapSourcesRequestMessage, cryptix_rpc_core::GetScBootstrapSourcesRequest, { Self {} });
try_from!(item: &protowire::GetScBootstrapSourcesResponseMessage, RpcResult<cryptix_rpc_core::GetScBootstrapSourcesResponse>, {
    Self {
        sources: item.sources.iter().map(|source| source.try_into()).collect::<RpcResult<Vec<_>>>()?,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetScBootstrapSourcesResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetScSnapshotManifestRequestMessage, cryptix_rpc_core::GetScSnapshotManifestRequest, {
    Self { snapshot_id: item.snapshot_id.clone() }
});
try_from!(item: &protowire::GetScSnapshotManifestResponseMessage, RpcResult<cryptix_rpc_core::GetScSnapshotManifestResponse>, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        manifest_hex: item.manifest_hex.clone(),
        manifest_signatures: item.manifest_signatures.iter().map(|signature| signature.try_into()).collect::<RpcResult<Vec<_>>>()?,
    }
});
try_from!(item: &protowire::GetScSnapshotChunkRequestMessage, cryptix_rpc_core::GetScSnapshotChunkRequest, {
    Self { snapshot_id: item.snapshot_id.clone(), chunk_index: item.chunk_index, chunk_size: item.chunk_size }
});
try_from!(item: &protowire::GetScSnapshotChunkResponseMessage, RpcResult<cryptix_rpc_core::GetScSnapshotChunkResponse>, {
    Self {
        snapshot_id: item.snapshot_id.clone(),
        chunk_index: item.chunk_index,
        total_chunks: item.total_chunks,
        file_size: item.file_size,
        chunk_hex: item.chunk_hex.clone(),
    }
});
try_from!(item: &protowire::GetScReplayWindowChunkRequestMessage, cryptix_rpc_core::GetScReplayWindowChunkRequest, {
    Self { snapshot_id: item.snapshot_id.clone(), chunk_index: item.chunk_index, chunk_size: item.chunk_size }
});
try_from!(
    item: &protowire::GetScReplayWindowChunkResponseMessage,
    RpcResult<cryptix_rpc_core::GetScReplayWindowChunkResponse>,
    {
        Self {
            snapshot_id: item.snapshot_id.clone(),
            chunk_index: item.chunk_index,
            total_chunks: item.total_chunks,
            file_size: item.file_size,
            chunk_hex: item.chunk_hex.clone(),
        }
    }
);
try_from!(_item: &protowire::GetScSnapshotHeadRequestMessage, cryptix_rpc_core::GetScSnapshotHeadRequest, { Self {} });
try_from!(item: &protowire::GetScSnapshotHeadResponseMessage, RpcResult<cryptix_rpc_core::GetScSnapshotHeadResponse>, {
    Self {
        head: item.head.as_ref().map(|head| head.try_into()).transpose()?,
        context: item
            .context
            .as_ref()
            .ok_or_else(|| RpcError::MissingRpcFieldError("GetScSnapshotHeadResponseMessage".to_string(), "context".to_string()))?
            .try_into()?,
    }
});
try_from!(item: &protowire::GetConsensusAtomicStateHashRequestMessage, cryptix_rpc_core::GetConsensusAtomicStateHashRequest, {
    Self { block_hash: RpcHash::from_str(&item.block_hash)? }
});
try_from!(
    item: &protowire::GetConsensusAtomicStateHashResponseMessage,
    RpcResult<cryptix_rpc_core::GetConsensusAtomicStateHashResponse>,
    { Self { state_hash: item.state_hash.clone() } }
);

try_from!(item: &protowire::NotifyUtxosChangedRequestMessage, cryptix_rpc_core::NotifyUtxosChangedRequest, {
    Self {
        addresses: item.addresses.iter().map(|x| x.as_str().try_into()).collect::<Result<Vec<_>, _>>()?,
        command: item.command.into(),
    }
});
try_from!(item: &protowire::StopNotifyingUtxosChangedRequestMessage, cryptix_rpc_core::NotifyUtxosChangedRequest, {
    Self {
        addresses: item.addresses.iter().map(|x| x.as_str().try_into()).collect::<Result<Vec<_>, _>>()?,
        command: Command::Stop,
    }
});
try_from!(&protowire::NotifyUtxosChangedResponseMessage, RpcResult<cryptix_rpc_core::NotifyUtxosChangedResponse>);
try_from!(&protowire::StopNotifyingUtxosChangedResponseMessage, RpcResult<cryptix_rpc_core::NotifyUtxosChangedResponse>);

try_from!(
    item: &protowire::NotifyPruningPointUtxoSetOverrideRequestMessage,
    cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideRequest,
    { Self { command: item.command.into() } }
);
try_from!(
    _item: &protowire::StopNotifyingPruningPointUtxoSetOverrideRequestMessage,
    cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideRequest,
    { Self { command: Command::Stop } }
);
try_from!(
    &protowire::NotifyPruningPointUtxoSetOverrideResponseMessage,
    RpcResult<cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideResponse>
);
try_from!(
    &protowire::StopNotifyingPruningPointUtxoSetOverrideResponseMessage,
    RpcResult<cryptix_rpc_core::NotifyPruningPointUtxoSetOverrideResponse>
);

try_from!(item: &protowire::NotifyFinalityConflictRequestMessage, cryptix_rpc_core::NotifyFinalityConflictRequest, {
    Self { command: item.command.into() }
});
try_from!(&protowire::NotifyFinalityConflictResponseMessage, RpcResult<cryptix_rpc_core::NotifyFinalityConflictResponse>);

try_from!(item: &protowire::NotifyVirtualDaaScoreChangedRequestMessage, cryptix_rpc_core::NotifyVirtualDaaScoreChangedRequest, {
    Self { command: item.command.into() }
});
try_from!(&protowire::NotifyVirtualDaaScoreChangedResponseMessage, RpcResult<cryptix_rpc_core::NotifyVirtualDaaScoreChangedResponse>);

try_from!(item: &protowire::NotifyVirtualChainChangedRequestMessage, cryptix_rpc_core::NotifyVirtualChainChangedRequest, {
    Self { include_accepted_transaction_ids: item.include_accepted_transaction_ids, command: item.command.into() }
});
try_from!(&protowire::NotifyVirtualChainChangedResponseMessage, RpcResult<cryptix_rpc_core::NotifyVirtualChainChangedResponse>);

try_from!(item: &protowire::NotifySinkBlueScoreChangedRequestMessage, cryptix_rpc_core::NotifySinkBlueScoreChangedRequest, {
    Self { command: item.command.into() }
});
try_from!(&protowire::NotifySinkBlueScoreChangedResponseMessage, RpcResult<cryptix_rpc_core::NotifySinkBlueScoreChangedResponse>);

try_from!(item: &protowire::NotifyTokenEventsRequestMessage, cryptix_rpc_core::NotifyTokenEventsRequest, {
    Self { command: item.command.into() }
});
try_from!(&protowire::NotifyTokenEventsResponseMessage, RpcResult<cryptix_rpc_core::NotifyTokenEventsResponse>);

// ----------------------------------------------------------------------------
// Unit tests
// ----------------------------------------------------------------------------

// TODO: tests

#[cfg(test)]
mod tests {
    use cryptix_rpc_core::{RpcError, RpcResult, SubmitBlockRejectReason, SubmitBlockReport, SubmitBlockResponse};

    use crate::protowire::{self, submit_block_response_message::RejectReason, SubmitBlockResponseMessage};

    #[test]
    fn test_submit_block_response() {
        struct Test {
            rpc_core: RpcResult<cryptix_rpc_core::SubmitBlockResponse>,
            protowire: protowire::SubmitBlockResponseMessage,
        }
        impl Test {
            fn new(
                rpc_core: RpcResult<cryptix_rpc_core::SubmitBlockResponse>,
                protowire: protowire::SubmitBlockResponseMessage,
            ) -> Self {
                Self { rpc_core, protowire }
            }
        }
        let tests = vec![
            Test::new(
                Ok(SubmitBlockResponse { report: SubmitBlockReport::Success }),
                SubmitBlockResponseMessage { reject_reason: RejectReason::None as i32, error: None },
            ),
            Test::new(
                Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::BlockInvalid) }),
                SubmitBlockResponseMessage {
                    reject_reason: RejectReason::BlockInvalid as i32,
                    error: Some(protowire::RpcError {
                        message: RpcError::SubmitBlockError(SubmitBlockRejectReason::BlockInvalid).to_string(),
                    }),
                },
            ),
            Test::new(
                Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::IsInIBD) }),
                SubmitBlockResponseMessage {
                    reject_reason: RejectReason::IsInIbd as i32,
                    error: Some(protowire::RpcError {
                        message: RpcError::SubmitBlockError(SubmitBlockRejectReason::IsInIBD).to_string(),
                    }),
                },
            ),
            Test::new(
                Ok(SubmitBlockResponse { report: SubmitBlockReport::Reject(SubmitBlockRejectReason::RouteIsFull) }),
                SubmitBlockResponseMessage {
                    reject_reason: RejectReason::None as i32, // This rpc core reject reason has no matching protowire variant
                    error: Some(protowire::RpcError {
                        message: RpcError::SubmitBlockError(SubmitBlockRejectReason::RouteIsFull).to_string(),
                    }),
                },
            ),
        ];

        for test in tests {
            let cnv_protowire: SubmitBlockResponseMessage = test.rpc_core.as_ref().map_err(|x| x.clone()).into();
            assert_eq!(cnv_protowire.reject_reason, test.protowire.reject_reason);
            assert_eq!(cnv_protowire.error.is_some(), test.protowire.error.is_some());
            assert_eq!(cnv_protowire.error, test.protowire.error);

            let cnv_rpc_core: RpcResult<SubmitBlockResponse> = (&test.protowire).try_into();
            assert_eq!(cnv_rpc_core.is_ok(), test.rpc_core.is_ok());
            match cnv_rpc_core {
                Ok(ref cnv_response) => {
                    let Ok(ref response) = test.rpc_core else { panic!() };
                    assert_eq!(cnv_response.report, response.report);
                }
                Err(ref cnv_err) => {
                    let Err(ref err) = test.rpc_core else { panic!() };
                    assert_eq!(cnv_err.to_string(), err.to_string());
                }
            }
        }
    }
}
