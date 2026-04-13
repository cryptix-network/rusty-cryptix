use crate::{flow_context::FlowContext, flow_trait::Flow};
use cryptix_addressmanager::NetAddress;
use cryptix_p2p_lib::{
    common::ProtocolError,
    dequeue, dequeue_with_timeout, make_message,
    pb::{cryptixd_message::Payload, AddressesMessage, RequestAddressesMessage},
    IncomingRoute, Router,
};
use cryptix_utils::networking::IpAddress;
use itertools::Itertools;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::sync::Arc;

/// The maximum number of addresses that are sent in a single cryptix Addresses message.
const MAX_ADDRESSES_SEND: usize = 1000;

/// The maximum number of addresses that can be received in a single cryptix Addresses response.
/// If a peer exceeds this value we consider it a protocol error.
const MAX_ADDRESSES_RECEIVE: usize = 2500;

/// The maximum number of unique addresses we accept from a single peer response.
const MAX_UNIQUE_ADDRESSES_ACCEPTED: usize = 1024;

pub struct ReceiveAddressesFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for ReceiveAddressesFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl ReceiveAddressesFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        let anti_fraud_runtime_enabled = self.ctx.connection_manager().map(|cm| cm.is_antifraud_runtime_enabled()).unwrap_or(false);
        let enforce_anti_fraud = self.ctx.is_payload_hf_active() && anti_fraud_runtime_enabled;
        if enforce_anti_fraud && self.router.properties().unified_node_id.is_none() {
            return Err(ProtocolError::OtherOwned(
                "received addresses from peer without verified unified node ID after hardfork".to_string(),
            ));
        }

        self.router
            .enqueue(make_message!(
                Payload::RequestAddresses,
                RequestAddressesMessage { include_all_subnetworks: false, subnetwork_id: None }
            ))
            .await?;

        let msg = dequeue_with_timeout!(self.incoming_route, Payload::Addresses)?;
        let address_list: Vec<(IpAddress, u16)> = msg.try_into()?;
        if address_list.len() > MAX_ADDRESSES_RECEIVE {
            return Err(ProtocolError::OtherOwned(format!("address count {} exceeded {}", address_list.len(), MAX_ADDRESSES_RECEIVE)));
        }
        let mut unique = HashSet::with_capacity(address_list.len());
        let mut amgr_lock = self.ctx.address_manager.lock();
        for (ip, port) in address_list {
            let net_address = NetAddress::new(ip, port);
            if !unique.insert(net_address) {
                continue;
            }
            if unique.len() > MAX_UNIQUE_ADDRESSES_ACCEPTED {
                return Err(ProtocolError::OtherOwned(format!(
                    "unique address count {} exceeded {}",
                    unique.len(),
                    MAX_UNIQUE_ADDRESSES_ACCEPTED
                )));
            }
            amgr_lock.add_address(net_address)
        }

        Ok(())
    }
}

pub struct SendAddressesFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for SendAddressesFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl SendAddressesFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            dequeue!(self.incoming_route, Payload::RequestAddresses)?;
            let anti_fraud_runtime_enabled =
                self.ctx.connection_manager().map(|cm| cm.is_antifraud_runtime_enabled()).unwrap_or(false);
            let require_verified = self.ctx.is_payload_hf_active() && anti_fraud_runtime_enabled;
            let addresses = {
                let amgr = self.ctx.address_manager.lock();
                if require_verified {
                    amgr.iterate_verified_addresses().collect_vec()
                } else {
                    amgr.iterate_addresses().collect_vec()
                }
            };
            let address_list = addresses
                .choose_multiple(&mut rand::thread_rng(), MAX_ADDRESSES_SEND)
                .map(|addr| (addr.ip, addr.port).into())
                .collect();
            self.router.enqueue(make_message!(Payload::Addresses, AddressesMessage { address_list })).await?;
        }
    }
}
