use super::error::Result;
use core::fmt::Debug;
use cryptix_grpc_core::{
    ops::CryptixdPayloadOps,
    protowire::{CryptixdRequest, CryptixdResponse},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;

pub(crate) mod id;
pub(crate) mod matcher;
pub(crate) mod queue;

pub(crate) trait Resolver: Send + Sync + Debug {
    fn register_request(&self, op: CryptixdPayloadOps, request: &CryptixdRequest) -> CryptixdResponseReceiver;
    fn handle_response(&self, response: CryptixdResponse);
    fn remove_expired_requests(&self, timeout: Duration);
}

pub(crate) type DynResolver = Arc<dyn Resolver>;

pub(crate) type CryptixdResponseSender = oneshot::Sender<Result<CryptixdResponse>>;
pub(crate) type CryptixdResponseReceiver = oneshot::Receiver<Result<CryptixdResponse>>;
