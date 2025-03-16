use crate::protowire::{cryptixd_request, CryptixdRequest, CryptixdResponse};

impl From<cryptixd_request::Payload> for CryptixdRequest {
    fn from(item: cryptixd_request::Payload) -> Self {
        CryptixdRequest { id: 0, payload: Some(item) }
    }
}

impl AsRef<CryptixdRequest> for CryptixdRequest {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<CryptixdResponse> for CryptixdResponse {
    fn as_ref(&self) -> &Self {
        self
    }
}

pub mod cryptixd_request_convert {
    use crate::protowire::*;
    use cryptix_rpc_core::{RpcError, RpcResult};

    impl_into_cryptixd_request!(Shutdown);
    impl_into_cryptixd_request!(SubmitBlock);
    impl_into_cryptixd_request!(GetBlockTemplate);
    impl_into_cryptixd_request!(GetBlock);
    impl_into_cryptixd_request!(GetInfo);

    impl_into_cryptixd_request!(GetCurrentNetwork);
    impl_into_cryptixd_request!(GetPeerAddresses);
    impl_into_cryptixd_request!(GetSink);
    impl_into_cryptixd_request!(GetMempoolEntry);
    impl_into_cryptixd_request!(GetMempoolEntries);
    impl_into_cryptixd_request!(GetConnectedPeerInfo);
    impl_into_cryptixd_request!(AddPeer);
    impl_into_cryptixd_request!(SubmitTransaction);
    impl_into_cryptixd_request!(SubmitTransactionReplacement);
    impl_into_cryptixd_request!(GetSubnetwork);
    impl_into_cryptixd_request!(GetVirtualChainFromBlock);
    impl_into_cryptixd_request!(GetBlocks);
    impl_into_cryptixd_request!(GetBlockCount);
    impl_into_cryptixd_request!(GetBlockDagInfo);
    impl_into_cryptixd_request!(ResolveFinalityConflict);
    impl_into_cryptixd_request!(GetHeaders);
    impl_into_cryptixd_request!(GetUtxosByAddresses);
    impl_into_cryptixd_request!(GetBalanceByAddress);
    impl_into_cryptixd_request!(GetBalancesByAddresses);
    impl_into_cryptixd_request!(GetSinkBlueScore);
    impl_into_cryptixd_request!(Ban);
    impl_into_cryptixd_request!(Unban);
    impl_into_cryptixd_request!(EstimateNetworkHashesPerSecond);
    impl_into_cryptixd_request!(GetMempoolEntriesByAddresses);
    impl_into_cryptixd_request!(GetCoinSupply);
    impl_into_cryptixd_request!(Ping);
    impl_into_cryptixd_request!(GetMetrics);
    impl_into_cryptixd_request!(GetConnections);
    impl_into_cryptixd_request!(GetSystemInfo);
    impl_into_cryptixd_request!(GetServerInfo);
    impl_into_cryptixd_request!(GetSyncStatus);
    impl_into_cryptixd_request!(GetDaaScoreTimestampEstimate);
    impl_into_cryptixd_request!(GetFeeEstimate);
    impl_into_cryptixd_request!(GetFeeEstimateExperimental);
    impl_into_cryptixd_request!(GetCurrentBlockColor);
    impl_into_cryptixd_request!(GetUtxoReturnAddress);

    impl_into_cryptixd_request!(NotifyBlockAdded);
    impl_into_cryptixd_request!(NotifyNewBlockTemplate);
    impl_into_cryptixd_request!(NotifyUtxosChanged);
    impl_into_cryptixd_request!(NotifyPruningPointUtxoSetOverride);
    impl_into_cryptixd_request!(NotifyFinalityConflict);
    impl_into_cryptixd_request!(NotifyVirtualDaaScoreChanged);
    impl_into_cryptixd_request!(NotifyVirtualChainChanged);
    impl_into_cryptixd_request!(NotifySinkBlueScoreChanged);

    macro_rules! impl_into_cryptixd_request {
        ($name:tt) => {
            paste::paste! {
                impl_into_cryptixd_request_ex!(cryptix_rpc_core::[<$name Request>],[<$name RequestMessage>],[<$name Request>]);
            }
        };
    }

    use impl_into_cryptixd_request;

    macro_rules! impl_into_cryptixd_request_ex {
        // ($($core_struct:ident)::+, $($protowire_struct:ident)::+, $($variant:ident)::+) => {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<&$core_struct> for cryptixd_request::Payload {
                fn from(item: &$core_struct) -> Self {
                    Self::$variant(item.into())
                }
            }

            impl From<&$core_struct> for CryptixdRequest {
                fn from(item: &$core_struct) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl From<$core_struct> for cryptixd_request::Payload {
                fn from(item: $core_struct) -> Self {
                    Self::$variant((&item).into())
                }
            }

            impl From<$core_struct> for CryptixdRequest {
                fn from(item: $core_struct) -> Self {
                    Self { id: 0, payload: Some((&item).into()) }
                }
            }

            // ----------------------------------------------------------------------------
            // protowire to rpc_core
            // ----------------------------------------------------------------------------

            impl TryFrom<&cryptixd_request::Payload> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &cryptixd_request::Payload) -> RpcResult<Self> {
                    if let cryptixd_request::Payload::$variant(request) = item {
                        request.try_into()
                    } else {
                        Err(RpcError::MissingRpcFieldError("Payload".to_string(), stringify!($variant).to_string()))
                    }
                }
            }

            impl TryFrom<&CryptixdRequest> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &CryptixdRequest) -> RpcResult<Self> {
                    item.payload
                        .as_ref()
                        .ok_or(RpcError::MissingRpcFieldError("CryptixRequest".to_string(), "Payload".to_string()))?
                        .try_into()
                }
            }

            impl From<$protowire_struct> for CryptixdRequest {
                fn from(item: $protowire_struct) -> Self {
                    Self { id: 0, payload: Some(cryptixd_request::Payload::$variant(item)) }
                }
            }

            impl From<$protowire_struct> for cryptixd_request::Payload {
                fn from(item: $protowire_struct) -> Self {
                    cryptixd_request::Payload::$variant(item)
                }
            }
        };
    }
    use impl_into_cryptixd_request_ex;
}

pub mod cryptixd_response_convert {
    use crate::protowire::*;
    use cryptix_rpc_core::{RpcError, RpcResult};

    impl_into_cryptixd_response!(Shutdown);
    impl_into_cryptixd_response!(SubmitBlock);
    impl_into_cryptixd_response!(GetBlockTemplate);
    impl_into_cryptixd_response!(GetBlock);
    impl_into_cryptixd_response!(GetInfo);
    impl_into_cryptixd_response!(GetCurrentNetwork);

    impl_into_cryptixd_response!(GetPeerAddresses);
    impl_into_cryptixd_response!(GetSink);
    impl_into_cryptixd_response!(GetMempoolEntry);
    impl_into_cryptixd_response!(GetMempoolEntries);
    impl_into_cryptixd_response!(GetConnectedPeerInfo);
    impl_into_cryptixd_response!(AddPeer);
    impl_into_cryptixd_response!(SubmitTransaction);
    impl_into_cryptixd_response!(SubmitTransactionReplacement);
    impl_into_cryptixd_response!(GetSubnetwork);
    impl_into_cryptixd_response!(GetVirtualChainFromBlock);
    impl_into_cryptixd_response!(GetBlocks);
    impl_into_cryptixd_response!(GetBlockCount);
    impl_into_cryptixd_response!(GetBlockDagInfo);
    impl_into_cryptixd_response!(ResolveFinalityConflict);
    impl_into_cryptixd_response!(GetHeaders);
    impl_into_cryptixd_response!(GetUtxosByAddresses);
    impl_into_cryptixd_response!(GetBalanceByAddress);
    impl_into_cryptixd_response!(GetBalancesByAddresses);
    impl_into_cryptixd_response!(GetSinkBlueScore);
    impl_into_cryptixd_response!(Ban);
    impl_into_cryptixd_response!(Unban);
    impl_into_cryptixd_response!(EstimateNetworkHashesPerSecond);
    impl_into_cryptixd_response!(GetMempoolEntriesByAddresses);
    impl_into_cryptixd_response!(GetCoinSupply);
    impl_into_cryptixd_response!(Ping);
    impl_into_cryptixd_response!(GetMetrics);
    impl_into_cryptixd_response!(GetConnections);
    impl_into_cryptixd_response!(GetSystemInfo);
    impl_into_cryptixd_response!(GetServerInfo);
    impl_into_cryptixd_response!(GetSyncStatus);
    impl_into_cryptixd_response!(GetDaaScoreTimestampEstimate);
    impl_into_cryptixd_response!(GetFeeEstimate);
    impl_into_cryptixd_response!(GetFeeEstimateExperimental);
    impl_into_cryptixd_response!(GetCurrentBlockColor);
    impl_into_cryptixd_response!(GetUtxoReturnAddress);

    impl_into_cryptixd_notify_response!(NotifyBlockAdded);
    impl_into_cryptixd_notify_response!(NotifyNewBlockTemplate);
    impl_into_cryptixd_notify_response!(NotifyUtxosChanged);
    impl_into_cryptixd_notify_response!(NotifyPruningPointUtxoSetOverride);
    impl_into_cryptixd_notify_response!(NotifyFinalityConflict);
    impl_into_cryptixd_notify_response!(NotifyVirtualDaaScoreChanged);
    impl_into_cryptixd_notify_response!(NotifyVirtualChainChanged);
    impl_into_cryptixd_notify_response!(NotifySinkBlueScoreChanged);

    impl_into_cryptixd_notify_response!(NotifyUtxosChanged, StopNotifyingUtxosChanged);
    impl_into_cryptixd_notify_response!(NotifyPruningPointUtxoSetOverride, StopNotifyingPruningPointUtxoSetOverride);

    macro_rules! impl_into_cryptixd_response {
        ($name:tt) => {
            paste::paste! {
                impl_into_cryptixd_response_ex!(cryptix_rpc_core::[<$name Response>],[<$name ResponseMessage>],[<$name Response>]);
            }
        };
        ($core_name:tt, $protowire_name:tt) => {
            paste::paste! {
                impl_into_cryptixd_response_base!(cryptix_rpc_core::[<$core_name Response>],[<$protowire_name ResponseMessage>],[<$protowire_name Response>]);
            }
        };
    }
    use impl_into_cryptixd_response;

    macro_rules! impl_into_cryptixd_response_base {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<RpcResult<$core_struct>> for $protowire_struct {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    item.as_ref().map_err(|x| (*x).clone()).into()
                }
            }

            impl From<RpcError> for $protowire_struct {
                fn from(item: RpcError) -> Self {
                    let x: RpcResult<&$core_struct> = Err(item);
                    x.into()
                }
            }

            impl From<$protowire_struct> for cryptixd_response::Payload {
                fn from(item: $protowire_struct) -> Self {
                    cryptixd_response::Payload::$variant(item)
                }
            }

            impl From<$protowire_struct> for CryptixdResponse {
                fn from(item: $protowire_struct) -> Self {
                    Self { id: 0, payload: Some(cryptixd_response::Payload::$variant(item)) }
                }
            }
        };
    }
    use impl_into_cryptixd_response_base;

    macro_rules! impl_into_cryptixd_response_ex {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<RpcResult<&$core_struct>> for cryptixd_response::Payload {
                fn from(item: RpcResult<&$core_struct>) -> Self {
                    cryptixd_response::Payload::$variant(item.into())
                }
            }

            impl From<RpcResult<&$core_struct>> for CryptixdResponse {
                fn from(item: RpcResult<&$core_struct>) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl From<RpcResult<$core_struct>> for cryptixd_response::Payload {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    cryptixd_response::Payload::$variant(item.into())
                }
            }

            impl From<RpcResult<$core_struct>> for CryptixdResponse {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl_into_cryptixd_response_base!($core_struct, $protowire_struct, $variant);

            // ----------------------------------------------------------------------------
            // protowire to rpc_core
            // ----------------------------------------------------------------------------

            impl TryFrom<&cryptixd_response::Payload> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &cryptixd_response::Payload) -> RpcResult<Self> {
                    if let cryptixd_response::Payload::$variant(response) = item {
                        response.try_into()
                    } else {
                        Err(RpcError::MissingRpcFieldError("Payload".to_string(), stringify!($variant).to_string()))
                    }
                }
            }

            impl TryFrom<&CryptixdResponse> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &CryptixdResponse) -> RpcResult<Self> {
                    item.payload
                        .as_ref()
                        .ok_or(RpcError::MissingRpcFieldError("CryptixResponse".to_string(), "Payload".to_string()))?
                        .try_into()
                }
            }
        };
    }
    use impl_into_cryptixd_response_ex;

    macro_rules! impl_into_cryptixd_notify_response {
        ($name:tt) => {
            impl_into_cryptixd_response!($name);

            paste::paste! {
                impl_into_cryptixd_notify_response_ex!(cryptix_rpc_core::[<$name Response>],[<$name ResponseMessage>]);
            }
        };
        ($core_name:tt, $protowire_name:tt) => {
            impl_into_cryptixd_response!($core_name, $protowire_name);

            paste::paste! {
                impl_into_cryptixd_notify_response_ex!(cryptix_rpc_core::[<$core_name Response>],[<$protowire_name ResponseMessage>]);
            }
        };
    }
    use impl_into_cryptixd_notify_response;

    macro_rules! impl_into_cryptixd_notify_response_ex {
        ($($core_struct:ident)::+, $protowire_struct:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl<T> From<Result<(), T>> for $protowire_struct
            where
                T: Into<RpcError>,
            {
                fn from(item: Result<(), T>) -> Self {
                    item
                        .map(|_| $($core_struct)::+{})
                        .map_err(|err| err.into()).into()
                }
            }

        };
    }
    use impl_into_cryptixd_notify_response_ex;
}
