use cryptix_core::warn;
use cryptix_p2p_lib::{common::ProtocolError, Router};
use cryptix_utils::any::type_name_short;
use std::sync::Arc;

#[async_trait::async_trait]
pub trait Flow
where
    Self: 'static + Send + Sync,
{
    fn name(&self) -> &'static str {
        type_name_short::<Self>()
    }

    fn router(&self) -> Option<Arc<Router>>;

    async fn start(&mut self) -> Result<(), ProtocolError>;

    /// Called before the router is closed due to a flow error.
    /// Flows may override this in order to report peer-level penalties.
    async fn on_error(&self, _err: &ProtocolError) {}

    fn launch(mut self: Box<Self>) {
        tokio::spawn(async move {
            let res = self.start().await;
            if let Err(err) = res {
                self.on_error(&err).await;
                if let Some(router) = self.router() {
                    router.try_sending_reject_message(&err).await;
                    if router.close().await || !err.is_connection_closed_error() {
                        warn!("{} flow error: {}, disconnecting from peer {}.", self.name(), err, router);
                    }
                }
            }
        });
    }
}
