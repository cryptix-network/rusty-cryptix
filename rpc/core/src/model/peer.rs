use borsh::{BorshDeserialize, BorshSerialize};
use cryptix_utils::networking::{ContextualNetAddress, IpAddress, NetAddress, PeerId};
use serde::{Deserialize, Serialize};

pub type RpcNodeId = PeerId;
pub type RpcIpAddress = IpAddress;
pub type RpcPeerAddress = NetAddress;
pub type RpcContextualPeerAddress = ContextualNetAddress;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RpcPeerInfo {
    pub id: RpcNodeId,
    pub address: RpcPeerAddress,
    pub last_ping_duration: u64, // NOTE: i64 in gRPC protowire

    pub is_outbound: bool,
    pub time_offset: i64,
    pub user_agent: String,

    pub advertised_protocol_version: u32,
    pub advertised_services: u64,
    pub is_hfa_fastchain: bool,
    pub is_cryptix_atomic: bool,
    pub is_strong_node_claims: bool,
    pub is_archival: bool,
    pub time_connected: u64, // NOTE: i64 in gRPC protowire
    pub is_ibd_peer: bool,
    pub unified_node_id: Option<String>,
}
