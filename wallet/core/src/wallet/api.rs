//!
//! [`WalletApi`] trait implementation for [`Wallet`].
//!

use crate::api::{message::*, traits::WalletApi};
use crate::imports::*;
use crate::result::Result;
use crate::storage::interface::TransactionRangeResult;
use crate::storage::Binding;
use crate::tx::Fees;
use workflow_core::{
    channel::{DuplexChannel, Sender},
    task::spawn,
};

#[async_trait]
impl WalletApi for super::Wallet {
    async fn register_notifications(self: Arc<Self>, channel: Sender<WalletNotification>) -> Result<u64> {
        let channel_id = self.inner.next_notification_relay_id.fetch_add(1, Ordering::SeqCst);
        let relay_ctl = DuplexChannel::oneshot();

        self.inner.notification_relays.lock().unwrap().insert(channel_id, super::NotificationRelay { task_ctl: relay_ctl.clone() });

        let events = self.multiplexer().channel();
        let relay_ctl_receiver = relay_ctl.request.receiver.clone();
        let relay_ctl_sender = relay_ctl.response.sender.clone();
        let this = self.clone();
        spawn(async move {
            loop {
                select! {
                    _ = relay_ctl_receiver.recv().fuse() => {
                        break;
                    },
                    msg = events.receiver.recv().fuse() => {
                        match msg {
                            Ok(event) => {
                                let notification = WalletNotification {
                                    kind: event.kind(),
                                    event_json: serde_json::to_string(event.as_ref()).unwrap_or_else(|_| "{}".to_string()),
                                };
                                if channel.send(notification).await.is_err() {
                                    break;
                                }
                            },
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
            }

            this.inner.notification_relays.lock().unwrap().remove(&channel_id);
            let _ = relay_ctl_sender.send(()).await;
        });

        Ok(channel_id)
    }

    async fn unregister_notifications(self: Arc<Self>, channel_id: u64) -> Result<()> {
        let relay = self
            .inner
            .notification_relays
            .lock()
            .unwrap()
            .remove(&channel_id)
            .ok_or_else(|| Error::Custom(format!("wallet notification channel id `{channel_id}` is not registered")))?;

        relay.task_ctl.signal(()).await.map_err(|err| Error::Custom(format!("wallet notification channel shutdown failed: {err}")))?;

        Ok(())
    }

    async fn get_status_call(self: Arc<Self>, request: GetStatusRequest) -> Result<GetStatusResponse> {
        let guard = self.guard();
        let guard = guard.lock().await;

        let GetStatusRequest { name } = request;
        let context = name.and_then(|name| self.inner.retained_contexts.lock().unwrap().get(&name).cloned());

        let is_connected = self.is_connected();
        let is_synced = self.is_synced();
        let is_open = self.is_open();
        let network_id = self.network_id().ok();
        let (url, is_wrpc_client) =
            if let Some(wrpc_client) = self.try_wrpc_client() { (wrpc_client.url(), true) } else { (None, false) };

        let selected_account_id = self.inner.selected_account.lock().unwrap().as_ref().map(|account| *account.id());

        let (wallet_descriptor, account_descriptors) = if self.is_open() {
            let wallet_descriptor = self.descriptor();
            let account_descriptors = self.account_descriptors(&guard).await.ok();
            (wallet_descriptor, account_descriptors)
        } else {
            (None, None)
        };

        Ok(GetStatusResponse {
            is_connected,
            is_synced,
            is_open,
            network_id,
            url,
            is_wrpc_client,
            context,
            selected_account_id,
            wallet_descriptor,
            account_descriptors,
        })
    }

    async fn retain_context_call(self: Arc<Self>, request: RetainContextRequest) -> Result<RetainContextResponse> {
        let RetainContextRequest { name, data } = request;

        if let Some(data) = data {
            self.inner.retained_contexts.lock().unwrap().insert(name, Arc::new(data));

            Ok(RetainContextResponse {})
        } else {
            self.inner.retained_contexts.lock().unwrap().remove(&name);
            // let data = self.inner.retained_contexts.lock().unwrap().get(&name).cloned();
            Ok(RetainContextResponse {})
        }

        // self.retain_context(retain);
    }

    // -------------------------------------------------------------------------------------

    async fn connect_call(self: Arc<Self>, request: ConnectRequest) -> Result<ConnectResponse> {
        use workflow_rpc::client::{ConnectOptions, ConnectStrategy};

        let ConnectRequest { url, network_id, retry_on_error, block_async_connect, require_sync } = request;

        if let Some(wrpc_client) = self.try_wrpc_client().as_ref() {
            let strategy = if retry_on_error { ConnectStrategy::Retry } else { ConnectStrategy::Fallback };

            let url = url
                .map(|url| wrpc_client.parse_url_with_network_type(url, network_id.into()).map_err(|e| e.to_string()))
                .transpose()?;
            let options = ConnectOptions { block_async_connect, strategy, url, ..Default::default() };
            wrpc_client.disconnect().await?;

            self.set_network_id(&network_id)?;

            let processor = self.utxo_processor().clone();
            let (sender, receiver) = oneshot();

            // set connection signaler that gets triggered
            // by utxo processor when connection occurs
            processor.set_connection_signaler(sender);

            // connect rpc
            wrpc_client.connect(Some(options)).await.map_err(|e| e.to_string())?;

            // wait for connection signal, cascade if error
            receiver.recv().await?.map_err(Error::custom)?;

            if require_sync && !self.is_synced() {
                Err(Error::NotSynced)
            } else {
                Ok(ConnectResponse {})
            }
        } else {
            Err(Error::NotWrpcClient)
        }
    }

    async fn disconnect_call(self: Arc<Self>, _request: DisconnectRequest) -> Result<DisconnectResponse> {
        if let Some(wrpc_client) = self.try_wrpc_client() {
            wrpc_client.disconnect().await?;
            Ok(DisconnectResponse {})
        } else {
            Err(Error::NotWrpcClient)
        }
    }

    async fn change_network_id_call(self: Arc<Self>, request: ChangeNetworkIdRequest) -> Result<ChangeNetworkIdResponse> {
        let ChangeNetworkIdRequest { network_id } = &request;
        self.set_network_id(network_id)?;
        Ok(ChangeNetworkIdResponse {})
    }

    // -------------------------------------------------------------------------------------

    async fn ping_call(self: Arc<Self>, request: PingRequest) -> Result<PingResponse> {
        log_info!("Wallet received ping request '{:?}' ...", request.message);
        Ok(PingResponse { message: request.message })
    }

    async fn batch_call(self: Arc<Self>, _request: BatchRequest) -> Result<BatchResponse> {
        self.store().batch().await?;
        Ok(BatchResponse {})
    }

    async fn flush_call(self: Arc<Self>, request: FlushRequest) -> Result<FlushResponse> {
        let FlushRequest { wallet_secret } = request;
        self.store().flush(&wallet_secret).await?;
        Ok(FlushResponse {})
    }

    async fn wallet_enumerate_call(self: Arc<Self>, _request: WalletEnumerateRequest) -> Result<WalletEnumerateResponse> {
        let wallet_descriptors = self.store().wallet_list().await?;
        Ok(WalletEnumerateResponse { wallet_descriptors })
    }

    async fn wallet_create_call(self: Arc<Self>, request: WalletCreateRequest) -> Result<WalletCreateResponse> {
        let WalletCreateRequest { wallet_secret, wallet_args } = request;

        let (wallet_descriptor, storage_descriptor) = self.create_wallet(&wallet_secret, wallet_args).await?;

        Ok(WalletCreateResponse { wallet_descriptor, storage_descriptor })
    }

    async fn wallet_open_call(self: Arc<Self>, request: WalletOpenRequest) -> Result<WalletOpenResponse> {
        let guard = self.guard();
        let guard = guard.lock().await;

        let WalletOpenRequest { wallet_secret, filename, account_descriptors, legacy_accounts } = request;
        let args = WalletOpenArgs { account_descriptors, legacy_accounts: legacy_accounts.unwrap_or_default() };
        let account_descriptors = self.open(&wallet_secret, filename, args, &guard).await?;
        Ok(WalletOpenResponse { account_descriptors })
    }

    async fn wallet_close_call(self: Arc<Self>, _request: WalletCloseRequest) -> Result<WalletCloseResponse> {
        self.close().await?;
        Ok(WalletCloseResponse {})
    }

    async fn wallet_reload_call(self: Arc<Self>, request: WalletReloadRequest) -> Result<WalletReloadResponse> {
        let WalletReloadRequest { reactivate } = request;
        if !self.is_open() {
            return Err(Error::WalletNotOpen);
        }

        let guard = self.guard();
        let guard = guard.lock().await;

        self.reload(reactivate, &guard).await?;
        Ok(WalletReloadResponse {})
    }

    async fn wallet_rename_call(self: Arc<Self>, request: WalletRenameRequest) -> Result<WalletRenameResponse> {
        let WalletRenameRequest { wallet_secret, title, filename } = request;
        self.rename(title, filename, &wallet_secret).await?;
        Ok(WalletRenameResponse {})
    }

    async fn wallet_change_secret_call(self: Arc<Self>, request: WalletChangeSecretRequest) -> Result<WalletChangeSecretResponse> {
        let WalletChangeSecretRequest { old_wallet_secret, new_wallet_secret } = request;
        self.store().change_secret(&old_wallet_secret, &new_wallet_secret).await?;
        Ok(WalletChangeSecretResponse {})
    }

    async fn wallet_export_call(self: Arc<Self>, request: WalletExportRequest) -> Result<WalletExportResponse> {
        let WalletExportRequest { wallet_secret, include_transactions } = request;

        let options = storage::WalletExportOptions { include_transactions };
        let wallet_data = self.store().wallet_export(&wallet_secret, options).await?;

        Ok(WalletExportResponse { wallet_data })
    }

    async fn wallet_import_call(self: Arc<Self>, request: WalletImportRequest) -> Result<WalletImportResponse> {
        let WalletImportRequest { wallet_secret, wallet_data } = request;

        let wallet_descriptor = self.store().wallet_import(&wallet_secret, &wallet_data).await?;

        Ok(WalletImportResponse { wallet_descriptor })
    }

    async fn prv_key_data_enumerate_call(
        self: Arc<Self>,
        _request: PrvKeyDataEnumerateRequest,
    ) -> Result<PrvKeyDataEnumerateResponse> {
        let prv_key_data_list = self.store().as_prv_key_data_store()?.iter().await?.try_collect::<Vec<_>>().await?;
        Ok(PrvKeyDataEnumerateResponse { prv_key_data_list })
    }

    async fn prv_key_data_create_call(self: Arc<Self>, request: PrvKeyDataCreateRequest) -> Result<PrvKeyDataCreateResponse> {
        let PrvKeyDataCreateRequest { wallet_secret, prv_key_data_args } = request;
        let prv_key_data_id = self.create_prv_key_data(&wallet_secret, prv_key_data_args).await?;
        Ok(PrvKeyDataCreateResponse { prv_key_data_id })
    }

    async fn prv_key_data_remove_call(self: Arc<Self>, _request: PrvKeyDataRemoveRequest) -> Result<PrvKeyDataRemoveResponse> {
        // TODO handle key removal
        return Err(Error::NotImplemented);
    }

    async fn prv_key_data_get_call(self: Arc<Self>, request: PrvKeyDataGetRequest) -> Result<PrvKeyDataGetResponse> {
        let PrvKeyDataGetRequest { prv_key_data_id, wallet_secret } = request;

        let prv_key_data = self.store().as_prv_key_data_store()?.load_key_data(&wallet_secret, &prv_key_data_id).await?;

        Ok(PrvKeyDataGetResponse { prv_key_data })
    }

    async fn accounts_rename_call(self: Arc<Self>, request: AccountsRenameRequest) -> Result<AccountsRenameResponse> {
        let AccountsRenameRequest { account_id, name, wallet_secret } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        let account = self.get_account_by_id(&account_id, &guard).await?.ok_or(Error::AccountNotFound(account_id))?;
        account.rename(&wallet_secret, name.as_deref()).await?;

        Ok(AccountsRenameResponse {})
    }

    async fn accounts_select_call(self: Arc<Self>, request: AccountsSelectRequest) -> Result<AccountsSelectResponse> {
        let AccountsSelectRequest { account_id } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        if let Some(account_id) = account_id {
            let account = self.get_account_by_id(&account_id, &guard).await?.ok_or(Error::AccountNotFound(account_id))?;
            self.select(Some(&account)).await?;
        } else {
            self.select(None).await?;
        }
        // self.inner.selected_account.lock().unwrap().replace(account);

        Ok(AccountsSelectResponse {})
    }

    async fn accounts_enumerate_call(self: Arc<Self>, _request: AccountsEnumerateRequest) -> Result<AccountsEnumerateResponse> {
        let guard = self.guard();
        let guard = guard.lock().await;

        let account_descriptors = self.account_descriptors(&guard).await?;
        Ok(AccountsEnumerateResponse { account_descriptors })
    }

    async fn accounts_activate_call(self: Arc<Self>, request: AccountsActivateRequest) -> Result<AccountsActivateResponse> {
        let AccountsActivateRequest { account_ids } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        self.activate_accounts(account_ids.as_deref(), &guard).await?;

        Ok(AccountsActivateResponse {})
    }

    async fn accounts_deactivate_call(self: Arc<Self>, request: AccountsDeactivateRequest) -> Result<AccountsDeactivateResponse> {
        let AccountsDeactivateRequest { account_ids } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        self.deactivate_accounts(account_ids.as_deref(), &guard).await?;

        Ok(AccountsDeactivateResponse {})
    }

    async fn accounts_discovery_call(self: Arc<Self>, request: AccountsDiscoveryRequest) -> Result<AccountsDiscoveryResponse> {
        let AccountsDiscoveryRequest { discovery_kind: _, address_scan_extent, account_scan_extent, bip39_passphrase, bip39_mnemonic } =
            request;

        let last_account_index_found =
            self.scan_bip44_accounts(bip39_mnemonic, bip39_passphrase, address_scan_extent, account_scan_extent).await?;

        Ok(AccountsDiscoveryResponse { last_account_index_found })
    }

    async fn accounts_create_call(self: Arc<Self>, request: AccountsCreateRequest) -> Result<AccountsCreateResponse> {
        let AccountsCreateRequest { wallet_secret, account_create_args } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        let account = self.create_account(&wallet_secret, account_create_args, true, &guard).await?;
        let account_descriptor = account.descriptor()?;

        Ok(AccountsCreateResponse { account_descriptor })
    }

    async fn accounts_ensure_default_call(
        self: Arc<Self>,
        request: AccountsEnsureDefaultRequest,
    ) -> Result<AccountsEnsureDefaultResponse> {
        let AccountsEnsureDefaultRequest { wallet_secret, payment_secret, account_kind, mnemonic_phrase } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        let account_descriptor = self
            .ensure_default_account_impl(&wallet_secret, payment_secret.as_ref(), account_kind, mnemonic_phrase.as_ref(), &guard)
            .await?;

        Ok(AccountsEnsureDefaultResponse { account_descriptor })
    }

    async fn accounts_import_call(self: Arc<Self>, _request: AccountsImportRequest) -> Result<AccountsImportResponse> {
        // TODO handle account imports
        return Err(Error::NotImplemented);
    }

    async fn accounts_get_call(self: Arc<Self>, request: AccountsGetRequest) -> Result<AccountsGetResponse> {
        let AccountsGetRequest { account_id } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        let account = self.get_account_by_id(&account_id, &guard).await?.ok_or(Error::AccountNotFound(account_id))?;
        let account_descriptor = account.descriptor().unwrap();
        Ok(AccountsGetResponse { account_descriptor })
    }

    async fn accounts_utxos_call(self: Arc<Self>, request: AccountsUtxosRequest) -> Result<AccountsUtxosResponse> {
        let AccountsUtxosRequest { account_id, start, end, include_pending } = request;

        if start > end {
            return Err(Error::InvalidRange(start, end));
        }

        let guard = self.guard();
        let _guard = guard.lock().await;

        let account = self
            .active_accounts()
            .get(&account_id)
            .ok_or_else(|| Error::custom(format!("account {account_id} is not active")))?;

        let mut groups = HashMap::<TransactionId, AccountUtxoTransaction>::new();
        {
            let context = account.utxo_context().context();

            for utxo in context.mature.iter() {
                let transaction_id = utxo.transaction_id();
                let entry = AccountUtxoEntry::from_reference(utxo, "mature");
                groups.entry(transaction_id).or_insert_with(|| AccountUtxoTransaction::new(transaction_id, "mature")).push(entry);
            }

            if include_pending {
                for utxo in context.pending.values() {
                    let transaction_id = utxo.transaction_id();
                    let entry = AccountUtxoEntry::from_reference(utxo, "pending");
                    groups.entry(transaction_id).or_insert_with(|| AccountUtxoTransaction::new(transaction_id, "pending")).push(entry);
                }

                for utxo in context.stasis.values() {
                    let transaction_id = utxo.transaction_id();
                    let entry = AccountUtxoEntry::from_reference(utxo, "stasis");
                    groups.entry(transaction_id).or_insert_with(|| AccountUtxoTransaction::new(transaction_id, "stasis")).push(entry);
                }
            }
        }

        let mut transactions = groups.into_values().collect::<Vec<_>>();
        transactions.sort_by(|left, right| {
            right
                .block_daa_score
                .cmp(&left.block_daa_score)
                .then_with(|| right.transaction_id.to_string().cmp(&left.transaction_id.to_string()))
        });

        let total = transactions.len() as u64;
        let range_start = start.min(total) as usize;
        let range_end = end.min(total) as usize;
        let transactions = transactions[range_start..range_end].to_vec();

        Ok(AccountsUtxosResponse { account_id, transactions, start, total })
    }

    async fn accounts_create_new_address_call(
        self: Arc<Self>,
        request: AccountsCreateNewAddressRequest,
    ) -> Result<AccountsCreateNewAddressResponse> {
        let AccountsCreateNewAddressRequest { account_id, kind } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        let account = self.get_account_by_id(&account_id, &guard).await?.ok_or(Error::AccountNotFound(account_id))?;

        let address = match kind {
            NewAddressKind::Receive => account.as_derivation_capable()?.new_receive_address().await?,
            NewAddressKind::Change => account.as_derivation_capable()?.new_change_address().await?,
        };

        Ok(AccountsCreateNewAddressResponse { address })
    }

    async fn accounts_send_call(self: Arc<Self>, request: AccountsSendRequest) -> Result<AccountsSendResponse> {
        let AccountsSendRequest {
            account_id,
            sender_address,
            wallet_secret,
            payment_secret,
            destination,
            priority_fee_sompi,
            payload,
            fast_path,
        } = request;

        let guard = self.guard();
        let guard = guard.lock().await;
        let account = self.get_account_by_id(&account_id, &guard).await?.ok_or(Error::AccountNotFound(account_id))?;

        let abortable = Abortable::new();
        let fast_submit = fast_path.and_then(|fast_path| {
            if fast_path.enabled {
                Some(crate::tx::FastSubmitOptions {
                    enabled: true,
                    intent_nonce: fast_path.intent_nonce,
                    client_created_at_ms: fast_path.client_created_at_ms,
                    max_fee_sompi: fast_path.max_fee_sompi,
                })
            } else {
                None
            }
        });
        let (generator_summary, transaction_ids, fast_summary) = account
            .send(
                destination,
                priority_fee_sompi,
                payload,
                sender_address,
                fast_submit,
                wallet_secret,
                payment_secret,
                &abortable,
                None,
            )
            .await?;

        Ok(AccountsSendResponse {
            generator_summary,
            transaction_ids,
            fast_path_requested: fast_summary.requested,
            fast_path_used: fast_summary.used,
            fast_path_status: fast_summary.status,
            fast_path_reason: fast_summary.reason,
            basechain_submitted: fast_summary.basechain_submitted,
        })
    }

    async fn accounts_transfer_call(self: Arc<Self>, request: AccountsTransferRequest) -> Result<AccountsTransferResponse> {
        let AccountsTransferRequest {
            source_account_id,
            destination_account_id,
            wallet_secret,
            payment_secret,
            priority_fee_sompi,
            transfer_amount_sompi,
        } = request;

        let guard = self.guard();
        let guard = guard.lock().await;

        let source_account =
            self.get_account_by_id(&source_account_id, &guard).await?.ok_or(Error::AccountNotFound(source_account_id))?;

        let abortable = Abortable::new();
        let (generator_summary, transaction_ids) = source_account
            .transfer(
                destination_account_id,
                transfer_amount_sompi,
                priority_fee_sompi.unwrap_or(Fees::SenderPays(0)),
                wallet_secret,
                payment_secret,
                &abortable,
                None,
                &guard,
            )
            .await?;

        Ok(AccountsTransferResponse { generator_summary, transaction_ids })
    }

    async fn accounts_estimate_call(self: Arc<Self>, request: AccountsEstimateRequest) -> Result<AccountsEstimateResponse> {
        let AccountsEstimateRequest { account_id, sender_address, destination, priority_fee_sompi, payload } = request;

        let guard = self.guard();
        let guard = guard.lock().await;
        let account = self.get_account_by_id(&account_id, &guard).await?.ok_or(Error::AccountNotFound(account_id))?;

        // Abort currently running async estimate for the same account if present. The estimate
        // call can be invoked continuously by the client/UI. If the estimate call is
        // invoked more than once for the same account, the previous estimate call should
        // be aborted.  The [`Abortable`] is an [`AtomicBool`] that is periodically checked by the
        // [`Generator`], resulting in the [`Generator`] halting the estimation process if it
        // detects that the [`Abortable`] is set to `true`. This effectively halts the previously
        // spawned async task that will return [`Error::Aborted`].
        if let Some(abortable) = self.inner.estimation_abortables.lock().unwrap().get(&account_id) {
            abortable.abort();
        }

        let abortable = Abortable::new();
        self.inner.estimation_abortables.lock().unwrap().insert(account_id, abortable.clone());
        let result = account.estimate(destination, priority_fee_sompi, payload, sender_address, &abortable).await;
        self.inner.estimation_abortables.lock().unwrap().remove(&account_id);

        Ok(AccountsEstimateResponse { generator_summary: result? })
    }

    async fn transactions_data_get_call(self: Arc<Self>, request: TransactionsDataGetRequest) -> Result<TransactionsDataGetResponse> {
        let TransactionsDataGetRequest { account_id, network_id, filter, start, end } = request;

        if start > end {
            return Err(Error::InvalidRange(start, end));
        }

        let binding = Binding::Account(account_id);
        let store = self.store().as_transaction_record_store()?;
        let TransactionRangeResult { transactions, total } =
            store.load_range(&binding, &network_id, filter, start as usize..end as usize).await?;
        let current_daa_score = self.current_daa_score();
        let mut records = transactions
            .into_iter()
            .map(|record| {
                let mut record = (*record).clone();
                record.refresh_payload_availability(current_daa_score);
                record
            })
            .collect::<Vec<_>>();
        let mut records_to_persist = Vec::<TransactionRecord>::new();

        // Refresh records with missing embedded tx data at query time so payload
        // availability can recover from "missing" once the tx is resolvable.
        // New nodes support one batched lookup, avoiding hundreds of per-record
        // header scans when a wallet has a long payload/messenger history.
        let enrichment_indices = records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                (!record.has_embedded_transaction() && Self::needs_transaction_enrichment(record)).then_some(index)
            })
            .collect::<Vec<_>>();

        let mut batch_lookup_available = false;
        if !enrichment_indices.is_empty() {
            if let Ok(resolved_transactions) = self.resolve_records_transactions_by_ids(&records, &enrichment_indices).await {
                batch_lookup_available = true;
                for index in enrichment_indices.iter().copied() {
                    let Some(transaction) = resolved_transactions.get(records[index].id()).cloned() else {
                        continue;
                    };
                    if records[index].try_attach_transaction(transaction) {
                        records[index].refresh_payload_availability(current_daa_score);
                        records_to_persist.push(records[index].clone());
                    }
                }
            }
        }

        let unresolved_indices = records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                (!record.has_embedded_transaction() && Self::needs_transaction_enrichment(record)).then_some(index)
            })
            .collect::<Vec<_>>();
        let allow_legacy_lookup = !batch_lookup_available || unresolved_indices.len() <= super::TX_ENRICH_LEGACY_RESIDUAL_LIMIT;
        if allow_legacy_lookup {
            for index in unresolved_indices {
                if let Ok(enriched) = self.enrich_record_transaction(&records[index], true).await {
                    if enriched.has_embedded_transaction() {
                        records_to_persist.push(enriched.clone());
                    }
                    records[index] = enriched;
                }
            }
        }

        let resolved = records.into_iter().map(Arc::new).collect::<Vec<_>>();

        if !records_to_persist.is_empty() {
            let record_refs: Vec<&TransactionRecord> = records_to_persist.iter().collect();
            store.store(&record_refs).await?;
        }

        Ok(TransactionsDataGetResponse { transactions: resolved, total, account_id, start })
    }

    async fn transactions_replace_note_call(
        self: Arc<Self>,
        request: TransactionsReplaceNoteRequest,
    ) -> Result<TransactionsReplaceNoteResponse> {
        let TransactionsReplaceNoteRequest { account_id, network_id, transaction_id, note } = request;

        self.store()
            .as_transaction_record_store()?
            .store_transaction_note(&Binding::Account(account_id), &network_id, transaction_id, note)
            .await?;

        Ok(TransactionsReplaceNoteResponse {})
    }

    async fn transactions_replace_metadata_call(
        self: Arc<Self>,
        request: TransactionsReplaceMetadataRequest,
    ) -> Result<TransactionsReplaceMetadataResponse> {
        let TransactionsReplaceMetadataRequest { account_id, network_id, transaction_id, metadata } = request;

        self.store()
            .as_transaction_record_store()?
            .store_transaction_metadata(&Binding::Account(account_id), &network_id, transaction_id, metadata)
            .await?;

        Ok(TransactionsReplaceMetadataResponse {})
    }

    async fn address_book_enumerate_call(
        self: Arc<Self>,
        _request: AddressBookEnumerateRequest,
    ) -> Result<AddressBookEnumerateResponse> {
        return Err(Error::NotImplemented);
    }
}
