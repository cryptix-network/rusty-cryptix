//! # RPC Core
//!
//! This crate provides foundational primitives used in Rusty Cryptix node RPC subsystem.
//! These include the main [`RpcApi`](api::rpc::RpcApi) trait, [`RpcApiOps`](crate::api::ops::RpcApiOps)
//! enum used in RPC method dispatching, and various data structures used in RPC method arguments.
//!
//! This crate acts as a foundation for [`cryptix_grpc_client`](https://docs.rs/cryptix_grpc_client) and
//! [`cryptix_wrpc_client`](https://docs.rs/cryptix_wrpc_client) crates, which provide gRPC and WebSocket
//! RPC client implementations. This crate is also used by WASM bindings to provide [WASM RpcClient
//! implementation](https://docs.rs/cryptix-wrpc-client/latest/cryptix_wrpc_client/wasm/struct.RpcClient.html)
//! (based on wRPC).
//!

// This attribute is required by BorshSerialize/Deserialize
#![recursion_limit = "256"]

pub mod api;
pub mod convert;
pub mod error;
pub mod model;
pub mod notify;
pub mod wasm;

pub mod prelude {
    //! Re-exports of the most commonly used types and traits in this crate.
    pub use super::api::notifications::*;
    pub use super::model::script_class::*;
    pub use super::model::*;
}

pub use api::notifications::*;
pub use convert::utxo::*;
pub use error::*;
pub use model::script_class::*;
pub use model::*;
