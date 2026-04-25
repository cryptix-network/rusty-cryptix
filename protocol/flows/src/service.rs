use std::path::PathBuf;
use std::sync::Arc;

use cryptix_addressmanager::NetAddress;
use cryptix_connectionmanager::ConnectionManager;
use cryptix_core::{
    task::service::{AsyncService, AsyncServiceFuture},
    trace,
};
use cryptix_p2p_lib::{Adaptor, P2P_SERVICE_BIT_ARCHIVAL, P2P_SERVICE_BIT_HFA};
use cryptix_utils::triggers::SingleTrigger;
use cryptix_utils_tower::counters::TowerConnectionCounters;

use crate::flow_context::FlowContext;

const P2P_CORE_SERVICE: &str = "p2p-service";

pub struct P2pService {
    flow_context: Arc<FlowContext>,
    connect_peers: Vec<NetAddress>,
    add_peers: Vec<NetAddress>,
    listen: NetAddress,
    outbound_target: usize,
    inbound_limit: usize,
    dns_seeders: &'static [&'static str],
    default_port: u16,
    banserver_enabled: bool,
    anti_fraud_allow_peer_fallback: bool,
    anti_fraud_persist_base_dir: Option<PathBuf>,
    shutdown: SingleTrigger,
    counters: Arc<TowerConnectionCounters>,
}

impl P2pService {
    pub fn new(
        flow_context: Arc<FlowContext>,
        connect_peers: Vec<NetAddress>,
        add_peers: Vec<NetAddress>,
        listen: NetAddress,
        outbound_target: usize,
        inbound_limit: usize,
        dns_seeders: &'static [&'static str],
        default_port: u16,
        banserver_enabled: bool,
        anti_fraud_allow_peer_fallback: bool,
        anti_fraud_persist_base_dir: Option<PathBuf>,
        counters: Arc<TowerConnectionCounters>,
    ) -> Self {
        Self {
            flow_context,
            connect_peers,
            add_peers,
            shutdown: SingleTrigger::default(),
            listen,
            outbound_target,
            inbound_limit,
            dns_seeders,
            default_port,
            banserver_enabled,
            anti_fraud_allow_peer_fallback,
            anti_fraud_persist_base_dir,
            counters,
        }
    }
}

impl AsyncService for P2pService {
    fn ident(self: Arc<Self>) -> &'static str {
        P2P_CORE_SERVICE
    }

    fn start(self: Arc<Self>) -> AsyncServiceFuture {
        trace!("{} starting", P2P_CORE_SERVICE);

        // Prepare a shutdown signal receiver
        let shutdown_signal = self.shutdown.listener.clone();

        let p2p_adaptor =
            Adaptor::bidirectional(self.listen, self.flow_context.hub().clone(), self.flow_context.clone(), self.counters.clone())
                .unwrap();
        let mut preferred_service_mask = 0u64;
        if !self.flow_context.config.is_archival {
            preferred_service_mask |= P2P_SERVICE_BIT_ARCHIVAL;
        }
        if self.flow_context.is_hfa_p2p_enabled() {
            preferred_service_mask |= P2P_SERVICE_BIT_HFA;
        }
        let connection_manager = ConnectionManager::new(
            p2p_adaptor.clone(),
            self.outbound_target,
            self.inbound_limit,
            preferred_service_mask,
            self.dns_seeders,
            self.default_port,
            self.flow_context.address_manager.clone(),
            self.banserver_enabled,
            self.anti_fraud_allow_peer_fallback,
            self.flow_context.config.network_name(),
            self.anti_fraud_persist_base_dir.clone(),
        );

        self.flow_context.set_connection_manager(connection_manager.clone());
        self.flow_context.start_async_services();

        // Launch the service and wait for a shutdown signal
        Box::pin(async move {
            for peer_address in self.connect_peers.iter().cloned().chain(self.add_peers.iter().cloned()) {
                connection_manager.add_connection_request(peer_address.into(), true).await;
            }

            // Keep the P2P server running until a service shutdown signal is received
            shutdown_signal.await;
            // Important for cleanup of the P2P adaptor since we have a reference cycle:
            // flow ctx -> conn manager -> p2p adaptor -> flow ctx (as ConnectionInitializer)
            self.flow_context.drop_connection_manager();
            p2p_adaptor.terminate_all_peers().await;
            connection_manager.stop().await;
            Ok(())
        })
    }

    fn signal_exit(self: Arc<Self>) {
        trace!("sending an exit signal to {}", P2P_CORE_SERVICE);
        self.shutdown.trigger.trigger();
    }

    fn stop(self: Arc<Self>) -> AsyncServiceFuture {
        Box::pin(async move {
            trace!("{} stopped", P2P_CORE_SERVICE);
            Ok(())
        })
    }
}
