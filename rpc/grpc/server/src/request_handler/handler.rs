use super::{
    handler_trait::Handler,
    interface::{DynCryptixdMethod, Interface},
};
use crate::{
    connection::{Connection, IncomingRoute},
    connection_handler::ServerContext,
    error::GrpcServerResult,
};
use cryptix_core::debug;
use cryptix_grpc_core::{
    ops::CryptixdPayloadOps,
    protowire::{CryptixdRequest, CryptixdResponse},
};

pub struct RequestHandler {
    rpc_op: CryptixdPayloadOps,
    incoming_route: IncomingRoute,
    server_ctx: ServerContext,
    method: DynCryptixdMethod,
    connection: Connection,
}

impl RequestHandler {
    pub fn new(
        rpc_op: CryptixdPayloadOps,
        incoming_route: IncomingRoute,
        server_context: ServerContext,
        interface: &Interface,
        connection: Connection,
    ) -> Self {
        let method = interface.get_method(&rpc_op);
        Self { rpc_op, incoming_route, server_ctx: server_context, method, connection }
    }

    pub async fn handle_request(&self, request: CryptixdRequest) -> GrpcServerResult<CryptixdResponse> {
        let id = request.id;
        let started = self.server_ctx.rpc_diagnostics_started();
        let result = self.method.call(self.server_ctx.clone(), self.connection.clone(), request).await;
        if started.is_some() {
            let detail = result.as_ref().err().map(|err| err.to_string());
            self.server_ctx.record_rpc_diagnostics(&format!("{:?}", self.rpc_op), started, result.is_ok(), detail.as_deref()).await;
        }
        let mut response = result?;
        response.id = id;
        Ok(response)
    }
}

#[async_trait::async_trait]
impl Handler for RequestHandler {
    async fn start(&mut self) {
        debug!("GRPC, Starting request handler {:?} for client {}", self.rpc_op, self.connection);
        while let Ok(request) = self.incoming_route.recv().await {
            let response = self.handle_request(request).await;
            match response {
                Ok(response) => {
                    if self.connection.enqueue(response).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("GRPC, Request handling error {} for client {}", e, self.connection);
                }
            }
        }
        debug!("GRPC, Exiting request handler {:?} for client {}", self.rpc_op, self.connection);
    }
}
