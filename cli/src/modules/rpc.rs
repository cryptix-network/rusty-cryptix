use crate::imports::*;
use convert_case::{Case, Casing};
use cryptix_rpc_core::api::ops::RpcApiOps;

#[derive(Default, Handler)]
#[help("Execute RPC commands against the connected Cryptix node")]
pub struct Rpc;

impl Rpc {
    fn sanitize_terminal_output(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0usize;

        while i < bytes.len() {
            let b = bytes[i];
            if b == 0x1B {
                // Strip ANSI CSI: ESC [ ... final-byte
                if i + 1 < bytes.len() && bytes[i + 1] == b'[' {
                    i += 2;
                    while i < bytes.len() {
                        let c = bytes[i];
                        if (0x40..=0x7E).contains(&c) {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
                // Strip ANSI OSC: ESC ] ... BEL or ESC \
                if i + 1 < bytes.len() && bytes[i + 1] == b']' {
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
                // Drop standalone ESC.
                i += 1;
                continue;
            }

            if b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t' {
                out.push(' ');
                i += 1;
                continue;
            }

            let ch = input[i..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
        }

        out
    }

    fn println<T>(&self, ctx: &Arc<CryptixCli>, v: T)
    where
        T: core::fmt::Debug,
    {
        let rendered = format!("{v:#?}");
        let sanitized = Self::sanitize_terminal_output(&rendered);
        ctx.term().writeln(sanitized.crlf());
    }

    fn parse_optional_hash(value: Option<&String>) -> Result<Option<RpcHash>> {
        value.map(|hash| RpcHash::from_hex(hash.as_str()).map_err(Error::from)).transpose()
    }

    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, mut argv: Vec<String>, cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;
        let rpc = ctx.wallet().rpc_api().clone();
        // tprintln!(ctx, "{response}");

        if argv.is_empty() {
            return self.display_help(ctx, argv).await;
        }

        let op_str = argv.remove(0);

        let sanitize = regex::Regex::new(r"\s*rpc\s+\S+\s+").unwrap();
        let _args = sanitize.replace(cmd, "").trim().to_string();
        let op_str_uc = op_str.to_case(Case::UpperCamel).to_string();
        // tprintln!(ctx, "uc: '{op_str_uc}'");

        let op = RpcApiOps::from_str(op_str_uc.as_str()).ok_or(Error::custom(format!("No such rpc method: '{op_str}'")))?;

        match op {
            RpcApiOps::Ping => {
                rpc.ping().await?;
                tprintln!(ctx, "ok");
            }
            RpcApiOps::GetMetrics => {
                let result = rpc.get_metrics(true, true, true, true, true, true).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetSystemInfo => {
                let result = rpc.get_system_info().await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetConnections => {
                let result = rpc.get_connections(true).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetServerInfo => {
                let result = rpc.get_server_info_call(None, GetServerInfoRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetSyncStatus => {
                let result = rpc.get_sync_status_call(None, GetSyncStatusRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetCurrentNetwork => {
                let result = rpc.get_current_network_call(None, GetCurrentNetworkRequest {}).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::SubmitBlock => {
            //     let result = rpc.submit_block_call(SubmitBlockRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            // RpcApiOps::GetBlockTemplate => {
            //     let result = rpc.get_block_template_call(GetBlockTemplateRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetPeerAddresses => {
                let result = rpc.get_peer_addresses_call(None, GetPeerAddressesRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetSink => {
                let result = rpc.get_sink_call(None, GetSinkRequest {}).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::GetMempoolEntry => {
            //     let result = rpc.get_mempool_entry_call(GetMempoolEntryRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetMempoolEntries => {
                // TODO
                let result = rpc
                    .get_mempool_entries_call(
                        None,
                        GetMempoolEntriesRequest { include_orphan_pool: true, filter_transaction_pool: true },
                    )
                    .await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetConnectedPeerInfo => {
                let result = rpc.get_connected_peer_info_call(None, GetConnectedPeerInfoRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::AddPeer => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc addpeer <ip:port> [true|false for 'is_permanent']"));
                }
                let peer_address = argv.remove(0).parse::<RpcContextualPeerAddress>()?;
                let is_permanent = argv.remove(0).parse::<bool>().unwrap_or(false);
                let result = rpc.add_peer_call(None, AddPeerRequest { peer_address, is_permanent }).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::SubmitTransaction => {
            //     let result = rpc.submit_transaction_call(SubmitTransactionRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetBlock => {
                if argv.is_empty() {
                    return Err(Error::custom("Missing block hash argument"));
                }
                let hash = argv.remove(0);
                let hash = RpcHash::from_hex(hash.as_str())?;
                let include_transactions = argv.first().and_then(|x| x.parse::<bool>().ok()).unwrap_or(true);
                let result = rpc.get_block_call(None, GetBlockRequest { hash, include_transactions }).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::GetSubnetwork => {
            //     let result = rpc.get_subnetwork_call(GetSubnetworkRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetVirtualChainFromBlock => {
                if argv.is_empty() {
                    return Err(Error::custom("Missing startHash argument"));
                };
                let start_hash = RpcHash::from_hex(argv.remove(0).as_str())?;
                let include_accepted_transaction_ids = argv.first().and_then(|x| x.parse::<bool>().ok()).unwrap_or_default();
                let result = rpc
                    .get_virtual_chain_from_block_call(
                        None,
                        GetVirtualChainFromBlockRequest { start_hash, include_accepted_transaction_ids },
                    )
                    .await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::GetBlocks => {
            //     let result = rpc.get_blocks_call(GetBlocksRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetBlockCount => {
                let result = rpc.get_block_count_call(None, GetBlockCountRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetBlockDagInfo => {
                let result = rpc.get_block_dag_info_call(None, GetBlockDagInfoRequest {}).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::ResolveFinalityConflict => {
            //     let result = rpc.resolve_finality_conflict_call(ResolveFinalityConflictRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::Shutdown => {
                let result = rpc.shutdown_call(None, ShutdownRequest {}).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::GetHeaders => {
            //     let result = rpc.get_headers_call(GetHeadersRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetUtxosByAddresses => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify at least one address"));
                }
                let addresses = argv.iter().map(|s| Address::try_from(s.as_str())).collect::<std::result::Result<Vec<_>, _>>()?;
                let result = rpc.get_utxos_by_addresses_call(None, GetUtxosByAddressesRequest { addresses }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetBalanceByAddress => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify at least one address"));
                }
                let addresses = argv.iter().map(|s| Address::try_from(s.as_str())).collect::<std::result::Result<Vec<_>, _>>()?;
                for address in addresses {
                    let result = rpc.get_balance_by_address_call(None, GetBalanceByAddressRequest { address }).await?;
                    self.println(&ctx, sompi_to_cryptix(result.balance));
                }
            }
            RpcApiOps::GetBalancesByAddresses => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify at least one address"));
                }
                let addresses = argv.iter().map(|s| Address::try_from(s.as_str())).collect::<std::result::Result<Vec<_>, _>>()?;
                let result = rpc.get_balances_by_addresses_call(None, GetBalancesByAddressesRequest { addresses }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetSinkBlueScore => {
                let result = rpc.get_sink_blue_score_call(None, GetSinkBlueScoreRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::Ban => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify peer IP address"));
                }
                let ip: RpcIpAddress = argv.remove(0).parse()?;
                let result = rpc.ban_call(None, BanRequest { ip }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::Unban => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify peer IP address"));
                }
                let ip: RpcIpAddress = argv.remove(0).parse()?;
                let result = rpc.unban_call(None, UnbanRequest { ip }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetInfo => {
                let result = rpc.get_info_call(None, GetInfoRequest {}).await?;
                self.println(&ctx, result);
            }
            // RpcApiOps::EstimateNetworkHashesPerSecond => {
            //     let result = rpc.estimate_network_hashes_per_second_call(EstimateNetworkHashesPerSecondRequest {  }).await?;
            //     self.println(&ctx, result);
            // }
            RpcApiOps::GetMempoolEntriesByAddresses => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify at least one address"));
                }
                let addresses = argv.iter().map(|s| Address::try_from(s.as_str())).collect::<std::result::Result<Vec<_>, _>>()?;
                let include_orphan_pool = true;
                let filter_transaction_pool = true;
                let result = rpc
                    .get_mempool_entries_by_addresses_call(
                        None,
                        GetMempoolEntriesByAddressesRequest { addresses, include_orphan_pool, filter_transaction_pool },
                    )
                    .await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetCoinSupply => {
                let result = rpc.get_coin_supply_call(None, GetCoinSupplyRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetDaaScoreTimestampEstimate => {
                if argv.is_empty() {
                    return Err(Error::custom("Please specify a daa_score"));
                }
                let daa_score_result = argv.iter().map(|s| s.parse::<u64>()).collect::<std::result::Result<Vec<_>, _>>();

                match daa_score_result {
                    Ok(daa_scores) => {
                        let result = rpc
                            .get_daa_score_timestamp_estimate_call(None, GetDaaScoreTimestampEstimateRequest { daa_scores })
                            .await?;
                        self.println(&ctx, result);
                    }
                    Err(_err) => {
                        return Err(Error::custom("Could not parse daa_scores to u64"));
                    }
                }
            }
            RpcApiOps::GetFeeEstimate => {
                let result = rpc.get_fee_estimate_call(None, GetFeeEstimateRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetFeeEstimateExperimental => {
                let verbose = if argv.is_empty() { false } else { argv.remove(0).parse().unwrap_or(false) };
                let result = rpc.get_fee_estimate_experimental_call(None, GetFeeEstimateExperimentalRequest { verbose }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetCurrentBlockColor => {
                if argv.is_empty() {
                    return Err(Error::custom("Missing block hash argument"));
                }
                let hash = argv.remove(0);
                let hash = RpcHash::from_hex(hash.as_str())?;
                let result = rpc.get_current_block_color_call(None, GetCurrentBlockColorRequest { hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::SimulateTokenOp => {
                if argv.len() < 2 {
                    return Err(Error::custom("Usage: rpc simulate-token-op <payloadHex> <ownerId> [atBlockHash]"));
                }
                let payload_hex = argv.remove(0);
                let owner_id = argv.remove(0);
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.simulate_token_op_call(None, SimulateTokenOpRequest { payload_hex, owner_id, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenBalance => {
                if argv.len() < 2 {
                    return Err(Error::custom("Usage: rpc get-token-balance <assetId> <ownerId> [atBlockHash]"));
                }
                let asset_id = argv.remove(0);
                let owner_id = argv.remove(0);
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.get_token_balance_call(None, GetTokenBalanceRequest { asset_id, owner_id, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenNonce => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc get-token-nonce <ownerId> [atBlockHash]"));
                }
                let owner_id = argv.remove(0);
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.get_token_nonce_call(None, GetTokenNonceRequest { owner_id, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenAsset => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc get-token-asset <assetId> [atBlockHash]"));
                }
                let asset_id = argv.remove(0);
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.get_token_asset_call(None, GetTokenAssetRequest { asset_id, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenOpStatus => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc get-token-op-status <txid> [atBlockHash]"));
                }
                let txid = RpcHash::from_hex(argv.remove(0).as_str())?;
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.get_token_op_status_call(None, GetTokenOpStatusRequest { txid, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenStateHash => {
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.get_token_state_hash_call(None, GetTokenStateHashRequest { at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenSpendability => {
                if argv.len() < 2 {
                    return Err(Error::custom("Usage: rpc get-token-spendability <assetId> <ownerId> [minDaaForSpend] [atBlockHash]"));
                }
                let asset_id = argv.remove(0);
                let owner_id = argv.remove(0);
                let min_daa_for_spend = argv.first().and_then(|value| value.parse::<u64>().ok());
                let at_block_hash = if min_daa_for_spend.is_some() {
                    Self::parse_optional_hash(argv.get(1))?
                } else {
                    Self::parse_optional_hash(argv.first())?
                };
                let result = rpc
                    .get_token_spendability_call(
                        None,
                        GetTokenSpendabilityRequest { asset_id, owner_id, min_daa_for_spend, at_block_hash },
                    )
                    .await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenEvents => {
                let after_sequence = argv.first().and_then(|value| value.parse::<u64>().ok()).unwrap_or(0);
                let limit = argv.get(1).and_then(|value| value.parse::<u32>().ok()).unwrap_or(100);
                let at_block_hash = Self::parse_optional_hash(argv.get(2))?;
                let result = rpc.get_token_events_call(None, GetTokenEventsRequest { after_sequence, limit, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenAssets => {
                let offset = argv.first().and_then(|value| value.parse::<u32>().ok()).unwrap_or(0);
                let limit = argv.get(1).and_then(|value| value.parse::<u32>().ok()).unwrap_or(100);
                let query = argv.get(2).cloned().filter(|value| !value.is_empty());
                let at_block_hash = Self::parse_optional_hash(argv.get(3))?;
                let result = rpc.get_token_assets_call(None, GetTokenAssetsRequest { offset, limit, query, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenBalancesByOwner => {
                if argv.is_empty() {
                    return Err(Error::custom(
                        "Usage: rpc get-token-balances-by-owner <ownerId> [offset] [limit] [includeAssets] [atBlockHash]",
                    ));
                }
                let owner_id = argv.remove(0);
                let offset = argv.first().and_then(|value| value.parse::<u32>().ok()).unwrap_or(0);
                let limit = argv.get(1).and_then(|value| value.parse::<u32>().ok()).unwrap_or(100);
                let include_assets = argv.get(2).and_then(|value| value.parse::<bool>().ok()).unwrap_or(false);
                let at_block_hash = Self::parse_optional_hash(argv.get(3))?;
                let result = rpc
                    .get_token_balances_by_owner_call(
                        None,
                        GetTokenBalancesByOwnerRequest { owner_id, offset, limit, include_assets, at_block_hash },
                    )
                    .await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenHolders => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc get-token-holders <assetId> [offset] [limit] [atBlockHash]"));
                }
                let asset_id = argv.remove(0);
                let offset = argv.first().and_then(|value| value.parse::<u32>().ok()).unwrap_or(0);
                let limit = argv.get(1).and_then(|value| value.parse::<u32>().ok()).unwrap_or(100);
                let at_block_hash = Self::parse_optional_hash(argv.get(2))?;
                let result =
                    rpc.get_token_holders_call(None, GetTokenHoldersRequest { asset_id, offset, limit, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenOwnerIdByAddress => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc get-token-owner-id-by-address <address> [atBlockHash]"));
                }
                let address = argv.remove(0);
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result =
                    rpc.get_token_owner_id_by_address_call(None, GetTokenOwnerIdByAddressRequest { address, at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::ExportTokenSnapshot => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc export-token-snapshot <path>"));
                }
                let path = argv.remove(0);
                let result = rpc.export_token_snapshot_call(None, ExportTokenSnapshotRequest { path }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::ImportTokenSnapshot => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc import-token-snapshot <path>"));
                }
                let path = argv.remove(0);
                let result = rpc.import_token_snapshot_call(None, ImportTokenSnapshotRequest { path }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetTokenHealth => {
                let at_block_hash = Self::parse_optional_hash(argv.first())?;
                let result = rpc.get_token_health_call(None, GetTokenHealthRequest { at_block_hash }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetScBootstrapSources => {
                let result = rpc.get_sc_bootstrap_sources_call(None, GetScBootstrapSourcesRequest {}).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetScSnapshotManifest => {
                if argv.is_empty() {
                    return Err(Error::custom("Usage: rpc get-sc-snapshot-manifest <snapshotId>"));
                }
                let snapshot_id = argv.remove(0);
                let result = rpc.get_sc_snapshot_manifest_call(None, GetScSnapshotManifestRequest { snapshot_id }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetScSnapshotChunk => {
                if argv.len() < 2 {
                    return Err(Error::custom("Usage: rpc get-sc-snapshot-chunk <snapshotId> <chunkIndex> [chunkSize]"));
                }
                let snapshot_id = argv.remove(0);
                let chunk_index = argv.remove(0).parse::<u32>().map_err(|err| Error::custom(err.to_string()))?;
                let chunk_size =
                    argv.first().map(|value| value.parse::<u32>().map_err(|err| Error::custom(err.to_string()))).transpose()?;
                let result =
                    rpc.get_sc_snapshot_chunk_call(None, GetScSnapshotChunkRequest { snapshot_id, chunk_index, chunk_size }).await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetScReplayWindowChunk => {
                if argv.len() < 2 {
                    return Err(Error::custom("Usage: rpc get-sc-replay-window-chunk <snapshotId> <chunkIndex> [chunkSize]"));
                }
                let snapshot_id = argv.remove(0);
                let chunk_index = argv.remove(0).parse::<u32>().map_err(|err| Error::custom(err.to_string()))?;
                let chunk_size =
                    argv.first().map(|value| value.parse::<u32>().map_err(|err| Error::custom(err.to_string()))).transpose()?;
                let result = rpc
                    .get_sc_replay_window_chunk_call(None, GetScReplayWindowChunkRequest { snapshot_id, chunk_index, chunk_size })
                    .await?;
                self.println(&ctx, result);
            }
            RpcApiOps::GetScSnapshotHead => {
                let result = rpc.get_sc_snapshot_head_call(None, GetScSnapshotHeadRequest {}).await?;
                self.println(&ctx, result);
            }
            _ => {
                tprintln!(ctx, "rpc method exists but is not supported by the cli: '{op_str}'\r\n");
                return Ok(());
            }
        }

        let prefix = Regex::new(r"(?i)^\s*rpc\s+\S+\s+").unwrap();
        let _req = prefix.replace(cmd, "").trim().to_string();

        Ok(())
    }

    async fn display_help(self: Arc<Self>, ctx: Arc<CryptixCli>, _argv: Vec<String>) -> Result<()> {
        // RpcApiOps that do not contain docs are not displayed
        let help = RpcApiOps::into_iter()
            .filter_map(|op| op.rustdoc().is_not_empty().then_some((op.as_str().to_case(Case::Kebab).to_string(), op.rustdoc())))
            .collect::<Vec<(_, _)>>();

        ctx.term().help(&help, None)?;

        tprintln!(ctx);
        tprintln!(ctx, "Please note that not all listed RPC methods are currently implemented");
        tprintln!(ctx);

        Ok(())
    }
}
