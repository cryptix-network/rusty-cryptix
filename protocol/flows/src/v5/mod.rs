use self::{
    address::{ReceiveAddressesFlow, SendAddressesFlow},
    blockrelay::{flow::HandleRelayInvsFlow, handle_requests::HandleRelayBlockRequests},
    ibd::IbdFlow,
    ping::{ReceivePingsFlow, SendPingsFlow},
    request_antipast::HandleAntipastRequests,
    request_block_locator::RequestBlockLocatorFlow,
    request_headers::RequestHeadersFlow,
    request_ibd_blocks::HandleIbdBlockRequests,
    request_ibd_chain_block_locator::RequestIbdChainBlockLocatorFlow,
    request_pp_proof::RequestPruningPointProofFlow,
    request_pruning_point_and_anticone::PruningPointAndItsAnticoneRequestsFlow,
    request_pruning_point_utxo_set::RequestPruningPointUtxoSetFlow,
    txrelay::flow::{RelayTransactionsFlow, RequestTransactionsFlow},
};
use crate::{flow_context::FlowContext, flow_trait::Flow};

use cryptix_p2p_lib::{CryptixdMessagePayloadType, Router, SharedIncomingRoute};
use cryptix_utils::channel;
use std::sync::Arc;

pub(crate) mod address;
pub(crate) mod blockrelay;
pub(crate) mod ibd;
pub(crate) mod ping;
pub(crate) mod request_antipast;
pub(crate) mod request_block_locator;
pub(crate) mod request_headers;
pub(crate) mod request_ibd_blocks;
pub(crate) mod request_ibd_chain_block_locator;
pub(crate) mod request_pp_proof;
pub(crate) mod request_pruning_point_and_anticone;
pub(crate) mod request_pruning_point_utxo_set;
pub(crate) mod txrelay;

pub fn register(ctx: FlowContext, router: Arc<Router>) -> Vec<Box<dyn Flow>> {
    // IBD flow <-> invs flow communication uses a job channel in order to always
    // maintain at most a single pending job which can be updated
    let (ibd_sender, relay_receiver) = channel::job();
    let flows: Vec<Box<dyn Flow>> = vec![
        Box::new(IbdFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                CryptixdMessagePayloadType::BlockHeaders,
                CryptixdMessagePayloadType::DoneHeaders,
                CryptixdMessagePayloadType::IbdBlockLocatorHighestHash,
                CryptixdMessagePayloadType::IbdBlockLocatorHighestHashNotFound,
                CryptixdMessagePayloadType::BlockWithTrustedDataV4,
                CryptixdMessagePayloadType::DoneBlocksWithTrustedData,
                CryptixdMessagePayloadType::IbdChainBlockLocator,
                CryptixdMessagePayloadType::IbdBlock,
                CryptixdMessagePayloadType::TrustedData,
                CryptixdMessagePayloadType::PruningPoints,
                CryptixdMessagePayloadType::PruningPointProof,
                CryptixdMessagePayloadType::UnexpectedPruningPoint,
                CryptixdMessagePayloadType::PruningPointUtxoSetChunk,
                CryptixdMessagePayloadType::DonePruningPointUtxoSetChunks,
            ]),
            relay_receiver,
        )),
        Box::new(HandleRelayInvsFlow::new(
            ctx.clone(),
            router.clone(),
            SharedIncomingRoute::new(
                router.subscribe_with_capacity(vec![CryptixdMessagePayloadType::InvRelayBlock], ctx.block_invs_channel_size()),
            ),
            router.subscribe(vec![CryptixdMessagePayloadType::Block, CryptixdMessagePayloadType::BlockLocator]),
            ibd_sender,
        )),
        Box::new(HandleRelayBlockRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestRelayBlocks]),
        )),
        Box::new(ReceivePingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![CryptixdMessagePayloadType::Ping]))),
        Box::new(SendPingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![CryptixdMessagePayloadType::Pong]))),
        Box::new(RequestHeadersFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestHeaders, CryptixdMessagePayloadType::RequestNextHeaders]),
        )),
        Box::new(RequestPruningPointProofFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestPruningPointProof]),
        )),
        Box::new(RequestIbdChainBlockLocatorFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestIbdChainBlockLocator]),
        )),
        Box::new(PruningPointAndItsAnticoneRequestsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                CryptixdMessagePayloadType::RequestPruningPointAndItsAnticone,
                CryptixdMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks,
            ]),
        )),
        Box::new(RequestPruningPointUtxoSetFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                CryptixdMessagePayloadType::RequestPruningPointUtxoSet,
                CryptixdMessagePayloadType::RequestNextPruningPointUtxoSetChunk,
            ]),
        )),
        Box::new(HandleIbdBlockRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestIbdBlocks]),
        )),
        Box::new(HandleAntipastRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestAntipast]),
        )),
        Box::new(RelayTransactionsFlow::new(
            ctx.clone(),
            router.clone(),
            router
                .subscribe_with_capacity(vec![CryptixdMessagePayloadType::InvTransactions], RelayTransactionsFlow::invs_channel_size()),
            router.subscribe_with_capacity(
                vec![CryptixdMessagePayloadType::Transaction, CryptixdMessagePayloadType::TransactionNotFound],
                RelayTransactionsFlow::txs_channel_size(),
            ),
        )),
        Box::new(RequestTransactionsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestTransactions]),
        )),
        Box::new(ReceiveAddressesFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![CryptixdMessagePayloadType::Addresses]))),
        Box::new(SendAddressesFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestAddresses]),
        )),
        Box::new(RequestBlockLocatorFlow::new(
            ctx,
            router.clone(),
            router.subscribe(vec![CryptixdMessagePayloadType::RequestBlockLocator]),
        )),
    ];

    // The reject message is handled as a special case by the router
    // CryptixdMessagePayloadType::Reject,

    // We do not register the below two messages since they are deprecated also in go-cryptix
    // CryptixdMessagePayloadType::BlockWithTrustedData,
    // CryptixdMessagePayloadType::IbdBlockLocator,

    flows
}
