use super::method::{DropFn, Method, MethodTrait, RoutingPolicy};
use crate::{
    connection::Connection,
    connection_handler::ServerContext,
    error::{GrpcServerError, GrpcServerResult},
};
use cryptix_grpc_core::{
    ops::CryptixdPayloadOps,
    protowire::{CryptixdRequest, CryptixdResponse},
};
use std::fmt::Debug;
use std::{collections::HashMap, sync::Arc};

pub type CryptixdMethod = Method<ServerContext, Connection, CryptixdRequest, CryptixdResponse>;
pub type DynCryptixdMethod = Arc<dyn MethodTrait<ServerContext, Connection, CryptixdRequest, CryptixdResponse>>;
pub type CryptixdDropFn = DropFn<CryptixdRequest, CryptixdResponse>;
pub type CryptixdRoutingPolicy = RoutingPolicy<CryptixdRequest, CryptixdResponse>;

/// An interface providing methods implementations and a fallback "not implemented" method
/// actually returning a message with a "not implemented" error.
///
/// The interface can provide a method clone for every [`CryptixdPayloadOps`] variant for later
/// processing of related requests.
///
/// It is also possible to directly let the interface itself process a request by invoking
/// the `call()` method.
pub struct Interface {
    server_ctx: ServerContext,
    methods: HashMap<CryptixdPayloadOps, DynCryptixdMethod>,
    method_not_implemented: DynCryptixdMethod,
}

impl Interface {
    pub fn new(server_ctx: ServerContext) -> Self {
        let method_not_implemented = Arc::new(Method::new(|_, _, cryptixd_request: CryptixdRequest| {
            Box::pin(async move {
                match cryptixd_request.payload {
                    Some(ref request) => Ok(CryptixdResponse {
                        id: cryptixd_request.id,
                        payload: Some(CryptixdPayloadOps::from(request).to_error_response(GrpcServerError::MethodNotImplemented.into())),
                    }),
                    None => Err(GrpcServerError::InvalidRequestPayload),
                }
            })
        }));
        Self { server_ctx, methods: Default::default(), method_not_implemented }
    }

    pub fn method(&mut self, op: CryptixdPayloadOps, method: CryptixdMethod) {
        let method: DynCryptixdMethod = Arc::new(method);
        if self.methods.insert(op, method).is_some() {
            panic!("RPC method {op:?} is declared multiple times")
        }
    }

    pub fn replace_method(&mut self, op: CryptixdPayloadOps, method: CryptixdMethod) {
        let method: DynCryptixdMethod = Arc::new(method);
        let _ = self.methods.insert(op, method);
    }

    pub fn set_method_properties(
        &mut self,
        op: CryptixdPayloadOps,
        tasks: usize,
        queue_size: usize,
        routing_policy: CryptixdRoutingPolicy,
    ) {
        self.methods.entry(op).and_modify(|x| {
            let method: Method<ServerContext, Connection, CryptixdRequest, CryptixdResponse> =
                Method::with_properties(x.method_fn(), tasks, queue_size, routing_policy);
            let method: Arc<dyn MethodTrait<ServerContext, Connection, CryptixdRequest, CryptixdResponse>> = Arc::new(method);
            *x = method;
        });
    }

    pub async fn call(
        &self,
        op: &CryptixdPayloadOps,
        connection: Connection,
        request: CryptixdRequest,
    ) -> GrpcServerResult<CryptixdResponse> {
        self.methods.get(op).unwrap_or(&self.method_not_implemented).call(self.server_ctx.clone(), connection, request).await
    }

    pub fn get_method(&self, op: &CryptixdPayloadOps) -> DynCryptixdMethod {
        self.methods.get(op).unwrap_or(&self.method_not_implemented).clone()
    }
}

impl Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface").finish()
    }
}
