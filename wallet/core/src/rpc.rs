//!
//! RPC adaptor struct use by the Wallet framework.
//!

use std::sync::Arc;

pub use cryptix_rpc_core::api::ctl::RpcCtl;
pub use cryptix_rpc_core::api::rpc::RpcApi;
pub type DynRpcApi = dyn RpcApi;
pub type NotificationChannel = cryptix_utils::channel::Channel<cryptix_rpc_core::Notification>;
pub use cryptix_rpc_core::notify::mode::NotificationMode;
pub use cryptix_wrpc_client::client::{ConnectOptions, ConnectStrategy};
pub use cryptix_wrpc_client::Resolver;
pub use cryptix_wrpc_client::WrpcEncoding;

/// RPC adaptor class that holds the [`RpcApi`]
/// and [`RpcCtl`] instances.
#[derive(Clone)]
pub struct Rpc {
    pub rpc_api: Arc<DynRpcApi>,
    pub rpc_ctl: RpcCtl,
}

impl Rpc {
    pub fn new(rpc_api: Arc<DynRpcApi>, rpc_ctl: RpcCtl) -> Self {
        Rpc { rpc_api, rpc_ctl }
    }

    pub fn rpc_api(&self) -> &Arc<DynRpcApi> {
        &self.rpc_api
    }

    pub fn rpc_ctl(&self) -> &RpcCtl {
        &self.rpc_ctl
    }
}
