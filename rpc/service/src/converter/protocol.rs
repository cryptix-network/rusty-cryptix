use std::sync::Arc;

use cryptix_p2p_flows::flow_context::FlowContext;
use cryptix_p2p_lib::{Peer, PeerKey};
use cryptix_rpc_core::RpcPeerInfo;
use cryptix_utils::hex::ToHex;

pub struct ProtocolConverter {
    flow_context: Arc<FlowContext>,
}

impl ProtocolConverter {
    pub fn new(flow_context: Arc<FlowContext>) -> Self {
        Self { flow_context }
    }

    fn get_peer_info(&self, peer: &Peer, ibd_peer_key: &Option<PeerKey>) -> RpcPeerInfo {
        let properties = peer.properties();
        RpcPeerInfo {
            id: peer.identity(),
            address: peer.net_address().into(),
            is_outbound: peer.is_outbound(),
            is_ibd_peer: ibd_peer_key.is_some() && peer.key() == *ibd_peer_key.as_ref().unwrap(),
            last_ping_duration: peer.last_ping_duration(),
            time_offset: properties.time_offset,
            user_agent: properties.user_agent.clone(),
            advertised_protocol_version: properties.advertised_protocol_version,
            advertised_services: properties.services,
            is_hfa_fastchain: properties.hfa_enabled,
            is_cryptix_atomic: properties.atomic_enabled,
            is_strong_node_claims: properties.strong_node_claims_enabled,
            is_archival: properties.archival_node,
            time_connected: peer.time_connected(),
            unified_node_id: properties.unified_node_id.map(|id| id.as_slice().to_hex()),
        }
    }

    pub fn get_peers_info(&self, peers: &[Peer]) -> Vec<RpcPeerInfo> {
        let ibd_peer_key = self.flow_context.ibd_peer_key();
        peers.iter().map(|x| self.get_peer_info(x, &ibd_peer_key)).collect()
    }
}
