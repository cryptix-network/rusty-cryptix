use cryptix_core::debug;
use cryptix_p2p_lib::echo::EchoFlowInitializer;
use cryptix_utils::networking::NetAddress;
use std::{str::FromStr, sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    // [-] - init logger
    cryptix_core::log::init_logger(None, "debug");
    // [0] - init p2p-adaptor - server side
    let ip_port = NetAddress::from_str("[::1]:50051").unwrap();
    let initializer = Arc::new(EchoFlowInitializer::new());
    let adaptor = cryptix_p2p_lib::Adaptor::bidirectional(ip_port, cryptix_p2p_lib::Hub::new(), initializer, Default::default()).unwrap();
    // [1] - connect to a few peers
    let ip_port = String::from("[::1]:19101");
    for i in 0..1 {
        debug!("P2P, p2p_client::main - starting peer:{}", i);
        let _peer_key = adaptor.connect_peer_with_retries(ip_port.clone(), 16, Duration::from_secs(1)).await;
    }
    // [2] - wait for ~60 sec and terminate
    tokio::time::sleep(Duration::from_secs(64)).await;
    debug!("P2P,p2p_client::main - TERMINATE");
    adaptor.terminate_all_peers().await;
    debug!("P2P,p2p_client::main - FINISH");
    tokio::time::sleep(Duration::from_secs(10)).await;
    debug!("P2P,p2p_client::main - EXIT");
}
