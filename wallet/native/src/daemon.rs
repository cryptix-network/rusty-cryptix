use cryptix_addresses::Address;
use cryptix_consensus_client::{TransactionOutpoint as ClientTransactionOutpoint, UtxoEntry, UtxoEntryReference};
use cryptix_consensus_core::config::params::Params;
use cryptix_consensus_core::constants::{MAX_SOMPI, SOMPI_PER_CRYPTIX};
use cryptix_consensus_core::network::{NetworkId, NetworkType};
use cryptix_consensus_core::tx::ScriptPublicKey;
use cryptix_rpc_core::model::message::{
    GetLiquidityPoolStateRequest, GetLiquidityQuoteRequest, GetTokenBalancesByOwnerRequest, GetTokenNonceRequest,
    GetTokenOwnerIdByAddressRequest, RpcLiquidityPoolState,
};
use cryptix_wallet_core::account::{descriptor::AccountDescriptor, Account, BIP32_ACCOUNT_KIND};
use cryptix_wallet_core::api::message::{
    AccountsActivateRequest, AccountsCreateNewAddressRequest, AccountsEnsureDefaultRequest, AccountsEnumerateRequest,
    AccountsEstimateRequest, AccountsSelectRequest, AccountsSendRequest, ConnectRequest, NewAddressKind, WalletOpenRequest,
};
use cryptix_wallet_core::api::traits::WalletApi;
use cryptix_wallet_core::prelude::Secret;
use cryptix_wallet_core::tx::{
    Fees, Generator, GeneratorSettings, PaymentDestination, PaymentOutput, ScriptPaymentOutput, ScriptPaymentOutputs,
};
use cryptix_wallet_core::wallet::Wallet;
use cryptix_wrpc_client::Resolver;
use futures::TryStreamExt;
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::watch;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("cryptixwalletd");
}

const DEFAULT_DAEMON_LISTEN: &str = "localhost:8082";
const DEFAULT_RPC_SERVER: &str = "localhost";
const CAT_MAGIC: [u8; 3] = *b"CAT";
const CAT_VERSION: u8 = 1;
const CAT_FLAGS: u8 = 0;
const CAT_OP_CREATE_ASSET: u8 = 0;
const CAT_OP_TRANSFER: u8 = 1;
const CAT_OP_MINT: u8 = 2;
const CAT_OP_BURN: u8 = 3;
const CAT_OP_CREATE_ASSET_WITH_MINT: u8 = 4;
const CAT_OP_CREATE_LIQUIDITY_ASSET: u8 = 5;
const CAT_OP_BUY_LIQUIDITY_EXACT_IN: u8 = 6;
const CAT_OP_SELL_LIQUIDITY_EXACT_IN: u8 = 7;
const CAT_OP_CLAIM_LIQUIDITY_FEES: u8 = 8;
const CAT_MAX_NAME_LEN: usize = 32;
const CAT_MAX_SYMBOL_LEN: usize = 10;
const CAT_MAX_METADATA_LEN: usize = 256;
const CAT_MAX_PLATFORM_TAG_LEN: usize = 50;
const CAT_MAX_DECIMALS: u8 = 18;
const CAT_MAX_LIQUIDITY_RECIPIENTS: usize = 2;
const CAT_MIN_LIQUIDITY_FEE_BPS: u16 = 10;
const CAT_MAX_LIQUIDITY_FEE_BPS: u16 = 1000;
const LIQUIDITY_TOKEN_DECIMALS: u8 = 0;
const MIN_LIQUIDITY_SUPPLY_RAW: u128 = 1_000;
const MAX_LIQUIDITY_SUPPLY_RAW: u128 = 1_000_000;
const MIN_LIQUIDITY_SEED_RESERVE_SOMPI: u64 = SOMPI_PER_CRYPTIX;
const DEFAULT_AUTH_INPUT_INDEX: u16 = 0;
const LIQUIDITY_AUTH_INPUT_INDEX: u16 = 1;
const LIQUIDITY_QUOTE_SIDE_BUY: u32 = 0;
const LIQUIDITY_QUOTE_SIDE_SELL: u32 = 1;
const TOKEN_CARRIER_OUTPUT_SOMPI: u64 = 1_000;
const TOKEN_OWNER_BALANCES_PAGE_LIMIT: u32 = 512;
const LIQUIDITY_VAULT_SCRIPT_VERSION: u16 = 0;
const LIQUIDITY_VAULT_SCRIPT: [u8; 7] = [0x04, b'C', b'L', b'V', b'1', 0x75, 0x51];
const MIN_FEE_RATE_SOMPI_PER_GRAM: f64 = 1.0;
const DEFAULT_SEND_MAX_FEE_SOMPI: u64 = SOMPI_PER_CRYPTIX;

#[derive(Clone)]
struct LiquidityRecipient {
    address_version: u8,
    address_payload: Vec<u8>,
}

#[derive(Clone)]
struct WalletDaemonRuntime {
    wallet: Arc<Wallet>,
    network_id: NetworkId,
    payment_secret: Option<Secret>,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Clone)]
struct WalletDaemonService {
    runtime: Arc<WalletDaemonRuntime>,
}

impl WalletDaemonService {
    fn new(runtime: Arc<WalletDaemonRuntime>) -> Self {
        Self { runtime }
    }

    fn wallet(&self) -> Arc<Wallet> {
        self.runtime.wallet.clone()
    }

    fn rpc(&self) -> Arc<cryptix_wallet_core::rpc::DynRpcApi> {
        self.runtime.wallet.rpc_api().clone()
    }

    fn current_account(&self) -> Result<Arc<dyn Account>, Status> {
        self.wallet().account().map_err(|err| Status::failed_precondition(format!("no selected account: {err}")))
    }

    fn collect_known_account_addresses(&self, account: Arc<dyn Account>, include_change: bool) -> Result<Vec<Address>, Status> {
        if let Ok(derivation_account) = account.clone().as_derivation_capable() {
            let receive_manager = derivation_account.derivation().receive_address_manager();
            let receive_end = receive_manager.index().saturating_add(1).max(1);
            let mut addresses = receive_manager
                .get_range_with_args(0..receive_end, false)
                .map_err(|err| Status::internal(format!("unable to derive receive addresses: {err}")))?;

            if include_change {
                let change_manager = derivation_account.derivation().change_address_manager();
                let change_end = change_manager.index().saturating_add(1).max(1);
                let mut change_addresses = change_manager
                    .get_range_with_args(0..change_end, false)
                    .map_err(|err| Status::internal(format!("unable to derive change addresses: {err}")))?;
                addresses.append(&mut change_addresses);
            }

            let mut seen = HashSet::<String>::new();
            addresses.retain(|address| seen.insert(address.to_string()));
            Ok(addresses)
        } else {
            let receive =
                account.receive_address().map_err(|err| Status::internal(format!("unable to get receive address: {err}")))?;
            if include_change {
                let change =
                    account.change_address().map_err(|err| Status::internal(format!("unable to get change address: {err}")))?;
                if change == receive {
                    Ok(vec![receive])
                } else {
                    Ok(vec![receive, change])
                }
            } else {
                Ok(vec![receive])
            }
        }
    }

    fn collect_receive_addresses(&self, account: Arc<dyn Account>) -> Result<Vec<Address>, Status> {
        self.collect_known_account_addresses(account, false)
    }

    async fn balances_for_addresses(&self, addresses: &[Address]) -> Result<(Vec<pb::AddressBalances>, u64, u64), Status> {
        let mut per_address: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for address in addresses {
            per_address.entry(address.to_string()).or_insert((0, 0));
        }

        let rpc = self.rpc();
        let utxos = rpc
            .get_utxos_by_addresses(addresses.to_vec())
            .await
            .map_err(|err| Status::internal(format!("GetUtxosByAddresses failed: {err}")))?;

        let virtual_daa_score = rpc
            .get_block_dag_info()
            .await
            .map_err(|err| Status::internal(format!("GetBlockDAGInfo failed: {err}")))?
            .virtual_daa_score;

        let coinbase_maturity = Params::from(self.runtime.network_id).coinbase_maturity;

        for entry in utxos {
            let Some(address) = entry.address else {
                continue;
            };

            let address_key = address.to_string();
            let balances = per_address.entry(address_key).or_insert((0, 0));
            let amount = entry.utxo_entry.amount;
            let is_spendable = !entry.utxo_entry.is_coinbase
                || entry.utxo_entry.block_daa_score.saturating_add(coinbase_maturity) < virtual_daa_score;

            if is_spendable {
                balances.0 = balances.0.saturating_add(amount);
            } else {
                balances.1 = balances.1.saturating_add(amount);
            }
        }

        let mut available_total = 0u64;
        let mut pending_total = 0u64;
        let mut out = Vec::with_capacity(per_address.len());
        for (address, (available, pending)) in per_address {
            available_total = available_total.saturating_add(available);
            pending_total = pending_total.saturating_add(pending);
            out.push(pb::AddressBalances { address, available, pending });
        }

        Ok((out, available_total, pending_total))
    }

    async fn spendable_balance_for_send_scope(
        &self,
        account: Arc<dyn Account>,
        sender_address: Option<&Address>,
    ) -> Result<u64, Status> {
        if let Some(sender_address) = sender_address {
            let (_, available_total, _) = self.balances_for_addresses(std::slice::from_ref(sender_address)).await?;
            return Ok(available_total);
        }

        if let Some(balance) = account.balance() {
            let spendable = balance.mature.saturating_sub(balance.outgoing);
            if spendable > 0 {
                return Ok(spendable);
            }
        }

        let addresses = self.collect_known_account_addresses(account, true)?;
        let (_, available_total, _) = self.balances_for_addresses(addresses.as_slice()).await?;
        Ok(available_total)
    }

    async fn estimate_send_total_fees(
        &self,
        account_id: cryptix_wallet_core::prelude::AccountId,
        sender_address: Option<Address>,
        destination: PaymentDestination,
        priority_fee_sompi: Fees,
    ) -> Result<u64, Status> {
        let response = self
            .wallet()
            .accounts_estimate_call(AccountsEstimateRequest {
                account_id,
                sender_address,
                destination,
                priority_fee_sompi,
                payload: None,
            })
            .await
            .map_err(Self::status_internal)?;

        Ok(response.generator_summary.aggregated_fees)
    }

    async fn network_normal_feerate(&self) -> Result<f64, Status> {
        let estimate = self.rpc().get_fee_estimate().await.map_err(Self::status_internal)?;
        let feerate = estimate.normal_buckets.first().map(|bucket| bucket.feerate).unwrap_or(estimate.priority_bucket.feerate);

        if !feerate.is_finite() || feerate <= 0.0 {
            return Err(Status::internal(format!("rpc returned invalid fee estimate rate `{feerate}`")));
        }

        Ok(feerate.max(MIN_FEE_RATE_SOMPI_PER_GRAM))
    }

    fn estimate_mass_from_fee(total_fee_sompi: u64, feerate_sompi_per_gram: f64) -> Result<u64, Status> {
        if total_fee_sompi == 0 {
            return Ok(0);
        }
        if !feerate_sompi_per_gram.is_finite() || feerate_sompi_per_gram <= 0.0 {
            return Err(Status::invalid_argument("feerate must be a finite positive number"));
        }
        let estimated_mass = (total_fee_sompi as f64 / feerate_sompi_per_gram).ceil();
        if !estimated_mass.is_finite() || estimated_mass < 0.0 {
            return Err(Status::internal("unable to estimate transaction mass from fee policy"));
        }
        if estimated_mass > u64::MAX as f64 {
            return Err(Status::invalid_argument("fee policy implies an unsupported transaction mass"));
        }
        Ok(estimated_mass as u64)
    }

    fn fee_from_mass_and_feerate(mass: u64, feerate_sompi_per_gram: f64) -> Result<u64, Status> {
        if mass == 0 {
            return Ok(0);
        }
        if !feerate_sompi_per_gram.is_finite() || feerate_sompi_per_gram <= 0.0 {
            return Err(Status::invalid_argument("feerate must be a finite positive number"));
        }
        let total_fee = (mass as f64 * feerate_sompi_per_gram).ceil();
        if !total_fee.is_finite() || total_fee < 0.0 {
            return Err(Status::internal("unable to derive total fee from mass and feerate"));
        }
        if total_fee > u64::MAX as f64 {
            return Err(Status::invalid_argument("fee policy implies a fee that is too large"));
        }
        Ok(total_fee as u64)
    }

    fn describe_fee_policy(policy: Option<&pb::FeePolicy>) -> &'static str {
        match policy.and_then(|policy| policy.fee_policy.as_ref()) {
            Some(pb::fee_policy::FeePolicy::ExactFeeRate(_)) => "exactFeeRate",
            Some(pb::fee_policy::FeePolicy::MaxFeeRate(_)) => "maxFeeRate",
            Some(pb::fee_policy::FeePolicy::MaxFee(_)) => "maxFee",
            None => "default",
        }
    }

    fn apply_fee_policy_to_estimate(
        policy: Option<&pb::FeePolicy>,
        baseline_total_fees: u64,
        baseline_feerate: f64,
    ) -> Result<(u64, Option<u64>), Status> {
        let mut priority_fee_sompi = 0u64;
        let max_total_fee_sompi = match policy.and_then(|policy| policy.fee_policy.as_ref()) {
            Some(pb::fee_policy::FeePolicy::MaxFee(max_fee)) => Some(*max_fee),
            Some(pb::fee_policy::FeePolicy::ExactFeeRate(exact_fee_rate)) => {
                if !exact_fee_rate.is_finite() || *exact_fee_rate < MIN_FEE_RATE_SOMPI_PER_GRAM {
                    return Err(Status::invalid_argument(format!("exactFeeRate must be >= {MIN_FEE_RATE_SOMPI_PER_GRAM} sompi/gram")));
                }

                let estimated_mass = Self::estimate_mass_from_fee(baseline_total_fees, baseline_feerate)?;
                let target_total_fees = Self::fee_from_mass_and_feerate(estimated_mass, *exact_fee_rate)?;
                if target_total_fees < baseline_total_fees {
                    return Err(Status::failed_precondition(format!(
                        "exactFeeRate={exact_fee_rate} would require total fees {target_total_fees} below estimated base fee {baseline_total_fees}; lowering base relay fee is not supported"
                    )));
                }

                priority_fee_sompi = target_total_fees.saturating_sub(baseline_total_fees);
                Some(target_total_fees)
            }
            Some(pb::fee_policy::FeePolicy::MaxFeeRate(max_fee_rate)) => {
                if !max_fee_rate.is_finite() || *max_fee_rate < MIN_FEE_RATE_SOMPI_PER_GRAM {
                    return Err(Status::invalid_argument(format!("maxFeeRate must be >= {MIN_FEE_RATE_SOMPI_PER_GRAM} sompi/gram")));
                }

                let effective_rate = baseline_feerate.min(*max_fee_rate);
                let estimated_mass = Self::estimate_mass_from_fee(baseline_total_fees, baseline_feerate)?;
                let target_total_fees = Self::fee_from_mass_and_feerate(estimated_mass, effective_rate)?;
                if target_total_fees < baseline_total_fees {
                    return Err(Status::failed_precondition(format!(
                        "maxFeeRate={max_fee_rate} implies total fees {target_total_fees} below estimated base fee {baseline_total_fees}; lowering base relay fee is not supported"
                    )));
                }

                priority_fee_sompi = target_total_fees.saturating_sub(baseline_total_fees);
                Some(target_total_fees)
            }
            None => Some(DEFAULT_SEND_MAX_FEE_SOMPI),
        };

        Ok((priority_fee_sompi, max_total_fee_sompi))
    }

    fn fee_from_send_mode(is_send_all: bool, priority_fee_sompi: u64) -> Fees {
        if is_send_all {
            Fees::ReceiverPays(priority_fee_sompi)
        } else {
            Fees::SenderPays(priority_fee_sompi)
        }
    }

    fn require_password(password: String) -> Result<Secret, Status> {
        if password.trim().is_empty() {
            return Err(Status::invalid_argument("password must not be empty"));
        }
        Ok(Secret::from(password))
    }

    fn parse_u128(value: &str, field: &str) -> Result<u128, Status> {
        value.parse::<u128>().map_err(|err| Status::invalid_argument(format!("{field} must be an unsigned integer: {err}")))
    }

    fn parse_positive_u128(value: &str, field: &str) -> Result<u128, Status> {
        let parsed = Self::parse_u128(value, field)?;
        if parsed == 0 {
            return Err(Status::invalid_argument(format!("{field} must be greater than zero")));
        }
        Ok(parsed)
    }

    fn parse_u64(value: &str, field: &str) -> Result<u64, Status> {
        value.parse::<u64>().map_err(|err| Status::invalid_argument(format!("{field} must be an unsigned integer: {err}")))
    }

    fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32], Status> {
        let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        let bytes = hex::decode(normalized)
            .map_err(|err| Status::invalid_argument(format!("{field} must be valid hex (optional 0x prefix): {err}")))?;
        if bytes.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "{field} must be exactly 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            )));
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(bytes.as_slice());
        Ok(out)
    }

    fn parse_metadata_hex(metadata_hex: &str) -> Result<Vec<u8>, Status> {
        if metadata_hex.trim().is_empty() {
            return Ok(vec![]);
        }

        let normalized = metadata_hex.trim().strip_prefix("0x").unwrap_or(metadata_hex.trim());
        hex::decode(normalized).map_err(|err| Status::invalid_argument(format!("metadata_hex must be valid hex: {err}")))
    }

    fn parse_decimals(decimals: u32) -> Result<u8, Status> {
        let decimals = u8::try_from(decimals).map_err(|_| Status::invalid_argument("decimals must fit into u8"))?;
        if decimals > CAT_MAX_DECIMALS {
            return Err(Status::invalid_argument(format!("decimals must be <= {CAT_MAX_DECIMALS}")));
        }
        Ok(decimals)
    }

    fn validate_supply_mode(capped: bool, max_supply: u128) -> Result<u8, Status> {
        if capped {
            if max_supply == 0 {
                return Err(Status::invalid_argument("max_supply_raw must be > 0 when capped=true"));
            }
            Ok(1)
        } else {
            if max_supply != 0 {
                return Err(Status::invalid_argument("max_supply_raw must be 0 when capped=false"));
            }
            Ok(0)
        }
    }

    fn validate_asset_identity_fields(name: &str, symbol: &str, metadata: &[u8], decimals: u8) -> Result<(), Status> {
        if decimals > CAT_MAX_DECIMALS {
            return Err(Status::invalid_argument(format!("decimals must be <= {CAT_MAX_DECIMALS}")));
        }
        if name.len() > CAT_MAX_NAME_LEN {
            return Err(Status::invalid_argument(format!("name must be <= {CAT_MAX_NAME_LEN} bytes")));
        }
        if symbol.len() > CAT_MAX_SYMBOL_LEN {
            return Err(Status::invalid_argument(format!("symbol must be <= {CAT_MAX_SYMBOL_LEN} bytes")));
        }
        if metadata.len() > CAT_MAX_METADATA_LEN {
            return Err(Status::invalid_argument(format!("metadata must be <= {CAT_MAX_METADATA_LEN} bytes")));
        }
        Ok(())
    }

    fn validate_platform_tag(platform_tag: &str) -> Result<(), Status> {
        if platform_tag.len() > CAT_MAX_PLATFORM_TAG_LEN {
            return Err(Status::invalid_argument(format!("platform_tag must be <= {CAT_MAX_PLATFORM_TAG_LEN} UTF-8 bytes")));
        }
        Ok(())
    }

    fn append_platform_tag_tail(payload: &mut Vec<u8>, platform_tag: &str) -> Result<(), Status> {
        Self::validate_platform_tag(platform_tag)?;
        let tag_len = u8::try_from(platform_tag.len())
            .map_err(|_| Status::invalid_argument(format!("platform_tag must be <= {CAT_MAX_PLATFORM_TAG_LEN} UTF-8 bytes")))?;
        payload.push(tag_len);
        payload.extend_from_slice(platform_tag.as_bytes());
        Ok(())
    }

    fn append_optional_platform_tag_tail(payload: &mut Vec<u8>, platform_tag: &str) -> Result<(), Status> {
        Self::validate_platform_tag(platform_tag)?;
        if !platform_tag.is_empty() {
            Self::append_platform_tag_tail(payload, platform_tag)?;
        }
        Ok(())
    }

    fn ensure_liquidity_outflow_unlocked(pool: &RpcLiquidityPoolState, operation: &str) -> Result<(), Status> {
        if pool.sell_locked {
            return Err(Status::failed_precondition(format!(
                "{operation} is locked until curve_reserve_sompi reaches {}",
                pool.unlock_target_sompi
            )));
        }
        Ok(())
    }

    fn normalize_asset_id(value: &str) -> String {
        value.trim().strip_prefix("0x").unwrap_or(value.trim()).to_lowercase()
    }

    fn parse_asset_filter(asset_ids: &[String]) -> Result<Option<HashSet<String>>, Status> {
        if asset_ids.is_empty() {
            return Ok(None);
        }

        let mut out = HashSet::new();
        for asset_id in asset_ids {
            let bytes = Self::parse_hex_32(asset_id.as_str(), "asset_id")?;
            out.insert(hex::encode(bytes));
        }
        Ok(Some(out))
    }

    fn parse_auth_input_index(value: u32) -> Result<u16, Status> {
        u16::try_from(value).map_err(|_| Status::invalid_argument("auth_input_index must be <= 65535"))
    }

    fn parse_liquidity_recipients(recipient_addresses: &[String]) -> Result<Vec<LiquidityRecipient>, Status> {
        if recipient_addresses.len() > CAT_MAX_LIQUIDITY_RECIPIENTS {
            return Err(Status::invalid_argument(format!(
                "recipient_addresses supports at most {CAT_MAX_LIQUIDITY_RECIPIENTS} entries"
            )));
        }

        let mut recipients = Vec::with_capacity(recipient_addresses.len());
        for (index, raw) in recipient_addresses.iter().enumerate() {
            let address = Address::try_from(raw.as_str())
                .map_err(|err| Status::invalid_argument(format!("recipient_addresses[{index}] is not a valid address: {err}")))?;
            if address.payload.len() != address.version.public_key_len() {
                return Err(Status::invalid_argument(format!(
                    "recipient_addresses[{index}] has invalid payload length {} for version {}",
                    address.payload.len(),
                    address.version
                )));
            }

            recipients.push(LiquidityRecipient { address_version: address.version as u8, address_payload: address.payload.to_vec() });
        }

        if recipients.len() == 2 {
            if recipients[0].address_version == recipients[1].address_version
                && recipients[0].address_payload == recipients[1].address_payload
            {
                return Err(Status::invalid_argument("recipient_addresses must not contain duplicates"));
            }
            let key_a = (recipients[0].address_version, recipients[0].address_payload.as_slice());
            let key_b = (recipients[1].address_version, recipients[1].address_payload.as_slice());
            if key_a > key_b {
                return Err(Status::invalid_argument("recipient_addresses must be in canonical lexicographic order"));
            }
        }

        Ok(recipients)
    }

    async fn resolve_owner_id(&self, address: &Address, label: &str) -> Result<String, Status> {
        let response = self
            .rpc()
            .get_token_owner_id_by_address_call(
                None,
                GetTokenOwnerIdByAddressRequest { address: address.to_string(), at_block_hash: None },
            )
            .await
            .map_err(Self::status_internal)?;

        response.owner_id.ok_or_else(|| {
            let reason = response.reason.unwrap_or_else(|| "owner id not derivable for address".to_string());
            Status::failed_precondition(format!("{label} {} is not usable for token operations: {reason}", address))
        })
    }

    async fn resolve_sender_nonce(&self, sender_owner_id: &str) -> Result<u64, Status> {
        let nonce_response = self
            .rpc()
            .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: sender_owner_id.to_string(), at_block_hash: None })
            .await
            .map_err(Self::status_internal)?;
        let nonce = nonce_response.expected_next_nonce;
        if nonce == 0 {
            return Err(Status::failed_precondition("RPC returned expected_next_nonce=0, token nonce must be greater than zero"));
        }
        Ok(nonce)
    }

    async fn submit_payload_tx(
        &self,
        account: Arc<dyn Account>,
        wallet_secret: Secret,
        payload: Vec<u8>,
        sender_address: Address,
        carrier_sompi: u64,
    ) -> Result<Vec<String>, Status> {
        let destination = PaymentDestination::from(PaymentOutput::new(sender_address.clone(), carrier_sompi));
        self.submit_payload_tx_to_destination(account, wallet_secret, payload, destination, Some(sender_address)).await
    }

    async fn submit_payload_tx_to_destination(
        &self,
        account: Arc<dyn Account>,
        wallet_secret: Secret,
        payload: Vec<u8>,
        destination: PaymentDestination,
        sender_address: Option<Address>,
    ) -> Result<Vec<String>, Status> {
        let account_id = *account.id();
        let response = self
            .wallet()
            .accounts_send_call(AccountsSendRequest {
                account_id,
                wallet_secret,
                payment_secret: self.runtime.payment_secret.clone(),
                sender_address,
                destination,
                priority_fee_sompi: Fees::SenderPays(0),
                payload: Some(payload),
                fast_path: None,
            })
            .await
            .map_err(Self::status_internal)?;

        Ok(response.transaction_ids.into_iter().map(|txid| txid.to_string()).collect())
    }

    async fn fetch_liquidity_pool(&self, asset_id: &str) -> Result<RpcLiquidityPoolState, Status> {
        let response = self
            .rpc()
            .get_liquidity_pool_state_call(None, GetLiquidityPoolStateRequest { asset_id: asset_id.to_string(), at_block_hash: None })
            .await
            .map_err(Self::status_internal)?;
        response.pool.ok_or_else(|| Status::failed_precondition(format!("liquidity pool not found for asset_id {asset_id}")))
    }

    fn pool_vault_value(pool: &RpcLiquidityPoolState) -> Result<u64, Status> {
        Self::parse_u64(pool.vault_value_sompi.as_str(), "pool.vault_value_sompi")
    }

    fn liquidity_vault_utxo_entry(pool: &RpcLiquidityPoolState) -> Result<UtxoEntryReference, Status> {
        let entry = UtxoEntry {
            address: None,
            outpoint: ClientTransactionOutpoint::new(pool.vault_txid, pool.vault_output_index),
            amount: Self::pool_vault_value(pool)?,
            script_public_key: Self::liquidity_vault_script_public_key(),
            block_daa_score: 0,
            is_coinbase: false,
        };
        Ok(UtxoEntryReference::from(entry))
    }

    async fn submit_liquidity_transition_tx(
        &self,
        account: Arc<dyn Account>,
        wallet_secret: Secret,
        payload: Vec<u8>,
        destination: PaymentDestination,
        sender_address: Address,
        vault_entry: UtxoEntryReference,
    ) -> Result<Vec<String>, Status> {
        let keydata = account.prv_key_data(wallet_secret).await.map_err(Self::status_internal)?;
        let derivation = account.clone().as_derivation_capable().map_err(Self::status_internal)?;
        let (receive, change) = derivation.derivation().addresses_indexes(&[&sender_address]).map_err(Self::status_internal)?;
        let mut private_keys = derivation
            .create_private_keys(&keydata, &self.runtime.payment_secret, &receive, &change)
            .map_err(Self::status_internal)?
            .into_iter()
            .map(|(_, key)| key.secret_bytes())
            .collect::<Vec<_>>();
        if private_keys.is_empty() {
            return Err(Status::failed_precondition(format!(
                "sender_address {sender_address} is not controlled by the selected account"
            )));
        }

        let settings = GeneratorSettings::try_new_with_account_and_priority_untracked(
            account,
            destination,
            Fees::SenderPays(0),
            Some(payload),
            Some(sender_address),
            Some(vec![vault_entry]),
        )
        .map_err(Self::status_internal)?;
        let generator = Generator::try_new(settings, None, None).map_err(Self::status_internal)?;
        let mut stream = generator.stream();
        let mut tx_ids = Vec::new();
        while let Some(transaction) = stream.try_next().await.map_err(Self::status_internal)? {
            if !transaction.is_final() {
                Self::clear_private_keys(&mut private_keys);
                return Err(Status::failed_precondition(
                    "liquidity transition requires a single final transaction; consolidate sender UTXOs and retry",
                ));
            }
            transaction.set_input_sig_op_count(0, 0).map_err(Self::status_internal)?;
            transaction.try_sign_with_keys(&private_keys, Some(false)).map_err(Self::status_internal)?;
            transaction.fill_input(0, vec![]).map_err(Self::status_internal)?;
            let tx_id = transaction.try_submit(&self.wallet().rpc_api()).await.map_err(Self::status_internal)?;
            tx_ids.push(tx_id.to_string());
            tokio::task::yield_now().await;
        }
        Self::clear_private_keys(&mut private_keys);
        Ok(tx_ids)
    }

    fn clear_private_keys(private_keys: &mut [[u8; 32]]) {
        for key in private_keys {
            key.fill(0);
        }
    }

    async fn token_balances_for_addresses(
        &self,
        addresses: &[Address],
        asset_filter: Option<&HashSet<String>>,
    ) -> Result<(Vec<pb::TokenAddressBalance>, Vec<pb::TokenBalance>), Status> {
        let rpc = self.rpc();
        let mut seen = HashSet::new();
        let mut per_address = Vec::new();
        let mut totals: BTreeMap<String, (u128, String, String)> = BTreeMap::new();

        for address in addresses {
            let address_str = address.to_string();
            if !seen.insert(address_str.clone()) {
                continue;
            }

            let owner_response = rpc
                .get_token_owner_id_by_address_call(
                    None,
                    GetTokenOwnerIdByAddressRequest { address: address_str.clone(), at_block_hash: None },
                )
                .await
                .map_err(Self::status_internal)?;

            let Some(owner_id) = owner_response.owner_id else {
                let skip_reason = owner_response.reason.unwrap_or_else(|| "owner id not derivable".to_string());
                per_address.push(pb::TokenAddressBalance {
                    address: address_str,
                    owner_id: String::new(),
                    balances: vec![],
                    skip_reason,
                });
                continue;
            };

            let mut offset = 0u32;
            let mut address_balances: BTreeMap<String, (u128, String, String)> = BTreeMap::new();
            loop {
                let response = rpc
                    .get_token_balances_by_owner_call(
                        None,
                        GetTokenBalancesByOwnerRequest {
                            owner_id: owner_id.clone(),
                            offset,
                            limit: TOKEN_OWNER_BALANCES_PAGE_LIMIT,
                            include_assets: true,
                            at_block_hash: None,
                        },
                    )
                    .await
                    .map_err(Self::status_internal)?;

                if response.balances.is_empty() {
                    break;
                }

                let page_len = response.balances.len() as u32;
                for balance in response.balances {
                    let asset_id = Self::normalize_asset_id(balance.asset_id.as_str());
                    if let Some(filter) = asset_filter {
                        if !filter.contains(&asset_id) {
                            continue;
                        }
                    }

                    let amount = balance.balance.parse::<u128>().map_err(|err| {
                        Status::internal(format!(
                            "invalid token balance `{}` for asset `{}`: {err}",
                            balance.balance, balance.asset_id
                        ))
                    })?;

                    let (symbol, name) =
                        if let Some(asset) = balance.asset { (asset.symbol, asset.name) } else { (String::new(), String::new()) };

                    let entry = address_balances.entry(asset_id.clone()).or_insert((0, String::new(), String::new()));
                    entry.0 = entry.0.saturating_add(amount);
                    if entry.1.is_empty() && !symbol.is_empty() {
                        entry.1 = symbol.clone();
                    }
                    if entry.2.is_empty() && !name.is_empty() {
                        entry.2 = name.clone();
                    }

                    let total = totals.entry(asset_id).or_insert((0, String::new(), String::new()));
                    total.0 = total.0.saturating_add(amount);
                    if total.1.is_empty() && !symbol.is_empty() {
                        total.1 = symbol;
                    }
                    if total.2.is_empty() && !name.is_empty() {
                        total.2 = name;
                    }
                }

                offset = offset.saturating_add(page_len);
                if u64::from(offset) >= response.total {
                    break;
                }
            }

            let balances = address_balances
                .into_iter()
                .map(|(asset_id, (amount_raw, symbol, name))| pb::TokenBalance {
                    asset_id,
                    amount_raw: amount_raw.to_string(),
                    symbol,
                    name,
                })
                .collect();

            per_address.push(pb::TokenAddressBalance { address: address_str, owner_id, balances, skip_reason: String::new() });
        }

        let totals = totals
            .into_iter()
            .map(|(asset_id, (amount_raw, symbol, name))| pb::TokenBalance {
                asset_id,
                amount_raw: amount_raw.to_string(),
                symbol,
                name,
            })
            .collect();

        Ok((per_address, totals))
    }

    fn build_header(op: u8, nonce: u64, auth_input_index: u16) -> Result<Vec<u8>, Status> {
        if nonce == 0 {
            return Err(Status::invalid_argument("nonce must be greater than zero"));
        }

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&CAT_MAGIC);
        payload.push(CAT_VERSION);
        payload.push(op);
        payload.push(CAT_FLAGS);
        payload.extend_from_slice(&auth_input_index.to_le_bytes());
        payload.extend_from_slice(&nonce.to_le_bytes());
        Ok(payload)
    }

    fn push_create_common_fields(
        payload: &mut Vec<u8>,
        name: &str,
        symbol: &str,
        decimals: u8,
        supply_mode: u8,
        max_supply: u128,
        mint_authority_owner_id: &str,
        metadata: &[u8],
    ) -> Result<(), Status> {
        let mint_authority_owner_id = Self::parse_hex_32(mint_authority_owner_id, "mint_authority_owner_id")?;
        payload.push(decimals);
        payload.push(supply_mode);
        payload.extend_from_slice(&max_supply.to_le_bytes());
        payload.extend_from_slice(&mint_authority_owner_id);
        payload.push(name.len() as u8);
        payload.push(symbol.len() as u8);
        payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(symbol.as_bytes());
        payload.extend_from_slice(metadata);
        Ok(())
    }

    fn build_transfer_payload(
        asset_id: &str,
        to_owner_id: &str,
        amount: u128,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let asset_id = Self::parse_hex_32(asset_id, "asset_id")?;
        let to_owner_id = Self::parse_hex_32(to_owner_id, "to_owner_id")?;
        let mut payload = Self::build_header(CAT_OP_TRANSFER, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&to_owner_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        Ok(payload)
    }

    fn build_mint_payload(
        asset_id: &str,
        to_owner_id: &str,
        amount: u128,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let asset_id = Self::parse_hex_32(asset_id, "asset_id")?;
        let to_owner_id = Self::parse_hex_32(to_owner_id, "to_owner_id")?;
        let mut payload = Self::build_header(CAT_OP_MINT, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&to_owner_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        Ok(payload)
    }

    fn build_burn_payload(asset_id: &str, amount: u128, nonce: u64, auth_input_index: u16) -> Result<Vec<u8>, Status> {
        let asset_id = Self::parse_hex_32(asset_id, "asset_id")?;
        let mut payload = Self::build_header(CAT_OP_BURN, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        Ok(payload)
    }

    fn build_create_asset_payload(
        name: &str,
        symbol: &str,
        decimals: u8,
        supply_mode: u8,
        max_supply: u128,
        mint_authority_owner_id: &str,
        metadata: &[u8],
        platform_tag: &str,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let mut payload = Self::build_header(CAT_OP_CREATE_ASSET, nonce, auth_input_index)?;
        Self::push_create_common_fields(
            &mut payload,
            name,
            symbol,
            decimals,
            supply_mode,
            max_supply,
            mint_authority_owner_id,
            metadata,
        )?;
        Self::append_optional_platform_tag_tail(&mut payload, platform_tag)?;
        Ok(payload)
    }

    fn build_create_asset_with_mint_payload(
        name: &str,
        symbol: &str,
        decimals: u8,
        supply_mode: u8,
        max_supply: u128,
        mint_authority_owner_id: &str,
        metadata: &[u8],
        initial_mint_amount: u128,
        initial_mint_to_owner_id: &str,
        platform_tag: &str,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let initial_mint_to_owner_id = Self::parse_hex_32(initial_mint_to_owner_id, "initial_mint_to_owner_id")?;
        let mut payload = Self::build_header(CAT_OP_CREATE_ASSET_WITH_MINT, nonce, auth_input_index)?;
        Self::push_create_common_fields(
            &mut payload,
            name,
            symbol,
            decimals,
            supply_mode,
            max_supply,
            mint_authority_owner_id,
            metadata,
        )?;
        payload.extend_from_slice(&initial_mint_amount.to_le_bytes());
        payload.extend_from_slice(&initial_mint_to_owner_id);
        Self::append_optional_platform_tag_tail(&mut payload, platform_tag)?;
        Ok(payload)
    }

    fn build_create_liquidity_asset_payload(
        name: &str,
        symbol: &str,
        decimals: u8,
        max_supply: u128,
        metadata: &[u8],
        seed_reserve_sompi: u64,
        fee_bps: u16,
        recipients: &[LiquidityRecipient],
        launch_buy_sompi: u64,
        launch_buy_min_token_out: u128,
        platform_tag: &str,
        liquidity_unlock_target_sompi: u64,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        if max_supply == 0 {
            return Err(Status::invalid_argument("max_supply_raw must be greater than zero"));
        }
        if seed_reserve_sompi == 0 {
            return Err(Status::invalid_argument("seed_reserve_sompi must be greater than zero"));
        }
        Self::validate_platform_tag(platform_tag)?;
        if liquidity_unlock_target_sompi > MAX_SOMPI {
            return Err(Status::invalid_argument(format!(
                "liquidity_unlock_target_sompi must be 0 or <= MAX_SOMPI ({MAX_SOMPI})"
            )));
        }
        Self::validate_liquidity_create_parameters(decimals, max_supply, seed_reserve_sompi)?;
        if recipients.len() > CAT_MAX_LIQUIDITY_RECIPIENTS {
            return Err(Status::invalid_argument(format!(
                "recipient_addresses supports at most {CAT_MAX_LIQUIDITY_RECIPIENTS} entries"
            )));
        }

        let mut payload = Self::build_header(CAT_OP_CREATE_LIQUIDITY_ASSET, nonce, auth_input_index)?;
        payload.push(decimals);
        payload.extend_from_slice(&max_supply.to_le_bytes());
        payload.push(name.len() as u8);
        payload.push(symbol.len() as u8);
        payload.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(symbol.as_bytes());
        payload.extend_from_slice(metadata);
        payload.extend_from_slice(&seed_reserve_sompi.to_le_bytes());
        payload.extend_from_slice(&fee_bps.to_le_bytes());
        payload.push(recipients.len() as u8);
        for recipient in recipients {
            payload.push(recipient.address_version);
            payload.extend_from_slice(recipient.address_payload.as_slice());
        }
        payload.extend_from_slice(&launch_buy_sompi.to_le_bytes());
        payload.extend_from_slice(&launch_buy_min_token_out.to_le_bytes());
        if !platform_tag.is_empty() || liquidity_unlock_target_sompi > 0 {
            Self::append_platform_tag_tail(&mut payload, platform_tag)?;
            payload.extend_from_slice(&liquidity_unlock_target_sompi.to_le_bytes());
        }
        Ok(payload)
    }

    fn validate_liquidity_create_parameters(decimals: u8, max_supply: u128, seed_reserve_sompi: u64) -> Result<(), Status> {
        if decimals != LIQUIDITY_TOKEN_DECIMALS {
            return Err(Status::invalid_argument(format!("liquidity token decimals must be {LIQUIDITY_TOKEN_DECIMALS}")));
        }
        if !(MIN_LIQUIDITY_SUPPLY_RAW..=MAX_LIQUIDITY_SUPPLY_RAW).contains(&max_supply) {
            return Err(Status::invalid_argument(format!(
                "max_supply_raw for liquidity tokens must be between {MIN_LIQUIDITY_SUPPLY_RAW} and {MAX_LIQUIDITY_SUPPLY_RAW}"
            )));
        }
        if seed_reserve_sompi < MIN_LIQUIDITY_SEED_RESERVE_SOMPI {
            return Err(Status::invalid_argument(format!(
                "seed_reserve_sompi must be at least {MIN_LIQUIDITY_SEED_RESERVE_SOMPI} (1 CPAY)"
            )));
        }
        let required_final_reserve = u128::from(seed_reserve_sompi)
            .checked_mul(max_supply.checked_add(1).ok_or_else(|| Status::invalid_argument("max_supply_raw + 1 overflows"))?)
            .ok_or_else(|| Status::invalid_argument("liquidity final reserve check overflows"))?;
        if required_final_reserve > u128::from(MAX_SOMPI) {
            return Err(Status::invalid_argument("seed_reserve_sompi is too high for this max_supply_raw"));
        }
        Ok(())
    }

    fn build_buy_liquidity_payload(
        asset_id: &str,
        expected_pool_nonce: u64,
        cpay_in_sompi: u64,
        min_token_out: u128,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let asset_id = Self::parse_hex_32(asset_id, "asset_id")?;
        let mut payload = Self::build_header(CAT_OP_BUY_LIQUIDITY_EXACT_IN, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
        payload.extend_from_slice(&cpay_in_sompi.to_le_bytes());
        payload.extend_from_slice(&min_token_out.to_le_bytes());
        Ok(payload)
    }

    fn build_sell_liquidity_payload(
        asset_id: &str,
        expected_pool_nonce: u64,
        token_in: u128,
        min_cpay_out_sompi: u64,
        cpay_receive_output_index: u16,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let asset_id = Self::parse_hex_32(asset_id, "asset_id")?;
        let mut payload = Self::build_header(CAT_OP_SELL_LIQUIDITY_EXACT_IN, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
        payload.extend_from_slice(&token_in.to_le_bytes());
        payload.extend_from_slice(&min_cpay_out_sompi.to_le_bytes());
        payload.extend_from_slice(&cpay_receive_output_index.to_le_bytes());
        Ok(payload)
    }

    fn build_claim_liquidity_payload(
        asset_id: &str,
        expected_pool_nonce: u64,
        recipient_index: u8,
        claim_amount_sompi: u64,
        claim_receive_output_index: u16,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>, Status> {
        let asset_id = Self::parse_hex_32(asset_id, "asset_id")?;
        let mut payload = Self::build_header(CAT_OP_CLAIM_LIQUIDITY_FEES, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
        payload.push(recipient_index);
        payload.extend_from_slice(&claim_amount_sompi.to_le_bytes());
        payload.extend_from_slice(&claim_receive_output_index.to_le_bytes());
        Ok(payload)
    }

    fn liquidity_vault_destination(vault_value: u64) -> PaymentDestination {
        let output = ScriptPaymentOutput::new(vault_value, Self::liquidity_vault_script_public_key());
        PaymentDestination::from(ScriptPaymentOutputs { outputs: vec![output] })
    }

    fn liquidity_vault_and_payout_destination(vault_value: u64, payout_value: u64, payout_address: &Address) -> PaymentDestination {
        let outputs = vec![
            ScriptPaymentOutput::new(vault_value, Self::liquidity_vault_script_public_key()),
            ScriptPaymentOutput::new(payout_value, cryptix_txscript::pay_to_address_script(payout_address)),
        ];
        PaymentDestination::from(ScriptPaymentOutputs { outputs })
    }

    fn liquidity_vault_script_public_key() -> ScriptPublicKey {
        ScriptPublicKey::from_vec(LIQUIDITY_VAULT_SCRIPT_VERSION, LIQUIDITY_VAULT_SCRIPT.to_vec())
    }

    fn status_internal(err: impl std::fmt::Display) -> Status {
        Status::internal(err.to_string())
    }
}

#[tonic::async_trait]
impl pb::cryptixwalletd_server::Cryptixwalletd for WalletDaemonService {
    async fn get_balance(&self, _request: Request<pb::GetBalanceRequest>) -> Result<Response<pb::GetBalanceResponse>, Status> {
        let account = self.current_account()?;
        let addresses = self.collect_receive_addresses(account)?;
        let (address_balances, available, pending) = self.balances_for_addresses(addresses.as_slice()).await?;

        Ok(Response::new(pb::GetBalanceResponse { available, pending, address_balances }))
    }

    async fn get_external_spendable_utx_os(
        &self,
        request: Request<pb::GetExternalSpendableUtxOsRequest>,
    ) -> Result<Response<pb::GetExternalSpendableUtxOsResponse>, Status> {
        let request = request.into_inner();
        let address =
            Address::try_from(request.address.as_str()).map_err(|err| Status::invalid_argument(format!("invalid address: {err}")))?;

        let rpc = self.rpc();
        let utxos = rpc
            .get_utxos_by_addresses(vec![address.clone()])
            .await
            .map_err(|err| Status::internal(format!("GetUtxosByAddresses failed: {err}")))?;
        let virtual_daa_score = rpc
            .get_block_dag_info()
            .await
            .map_err(|err| Status::internal(format!("GetBlockDAGInfo failed: {err}")))?
            .virtual_daa_score;
        let coinbase_maturity = Params::from(self.runtime.network_id).coinbase_maturity;

        let mut entries = Vec::new();
        for entry in utxos {
            let Some(entry_address) = entry.address else {
                continue;
            };
            let is_spendable = !entry.utxo_entry.is_coinbase
                || entry.utxo_entry.block_daa_score.saturating_add(coinbase_maturity) < virtual_daa_score;
            if !is_spendable {
                continue;
            }

            entries.push(pb::UtxosByAddressesEntry {
                address: entry_address.to_string(),
                outpoint: Some(pb::Outpoint {
                    transaction_id: entry.outpoint.transaction_id.to_string(),
                    index: entry.outpoint.index,
                }),
                utxo_entry: Some(pb::UtxoEntry {
                    amount: entry.utxo_entry.amount,
                    script_public_key: Some(pb::ScriptPublicKey {
                        version: u32::from(entry.utxo_entry.script_public_key.version()),
                        script_public_key: hex::encode(entry.utxo_entry.script_public_key.script()),
                    }),
                    block_daa_score: entry.utxo_entry.block_daa_score,
                    is_coinbase: entry.utxo_entry.is_coinbase,
                }),
            });
        }

        Ok(Response::new(pb::GetExternalSpendableUtxOsResponse { entries }))
    }

    async fn create_unsigned_transactions(
        &self,
        _request: Request<pb::CreateUnsignedTransactionsRequest>,
    ) -> Result<Response<pb::CreateUnsignedTransactionsResponse>, Status> {
        Err(Status::unimplemented(
            "CreateUnsignedTransactions is not implemented in rust wallet daemon yet (PSKB format differs from legacy go bytes format)",
        ))
    }

    async fn show_addresses(
        &self,
        _request: Request<pb::ShowAddressesRequest>,
    ) -> Result<Response<pb::ShowAddressesResponse>, Status> {
        let account = self.current_account()?;
        let addresses = self.collect_receive_addresses(account)?;
        let addresses = addresses.into_iter().map(|address| address.to_string()).collect();
        Ok(Response::new(pb::ShowAddressesResponse { address: addresses }))
    }

    async fn new_address(&self, _request: Request<pb::NewAddressRequest>) -> Result<Response<pb::NewAddressResponse>, Status> {
        let account = self.current_account()?;
        let account_id = *account.id();
        let response = self
            .wallet()
            .accounts_create_new_address_call(AccountsCreateNewAddressRequest { account_id, kind: NewAddressKind::Receive })
            .await
            .map_err(Self::status_internal)?;

        Ok(Response::new(pb::NewAddressResponse { address: response.address.to_string() }))
    }

    async fn shutdown(&self, _request: Request<pb::ShutdownRequest>) -> Result<Response<pb::ShutdownResponse>, Status> {
        let _ = self.runtime.shutdown_tx.send(true);
        Ok(Response::new(pb::ShutdownResponse {}))
    }

    async fn broadcast(&self, _request: Request<pb::BroadcastRequest>) -> Result<Response<pb::BroadcastResponse>, Status> {
        Err(Status::unimplemented(
            "Broadcast is not implemented in rust wallet daemon yet (legacy serialized transaction format is not supported)",
        ))
    }

    async fn broadcast_replacement(&self, _request: Request<pb::BroadcastRequest>) -> Result<Response<pb::BroadcastResponse>, Status> {
        Err(Status::unimplemented("BroadcastReplacement is not implemented in rust wallet daemon yet"))
    }

    async fn send(&self, request: Request<pb::SendRequest>) -> Result<Response<pb::SendResponse>, Status> {
        let request = request.into_inner();

        let to_address = Address::try_from(request.to_address.as_str())
            .map_err(|err| Status::invalid_argument(format!("invalid toAddress: {err}")))?;

        let sender_address = match request.from.as_slice() {
            [] => None,
            [single] => Some(
                Address::try_from(single.as_str()).map_err(|err| Status::invalid_argument(format!("invalid from-address: {err}")))?,
            ),
            _ => {
                return Err(Status::unimplemented("multiple from-address values are not implemented in rust wallet daemon yet"));
            }
        };

        let account = self.current_account()?;
        let account_id = *account.id();
        let wallet_secret = Self::require_password(request.password)?;
        let payment_secret = self.runtime.payment_secret.clone();
        let send_value = if request.is_send_all {
            let spendable = self.spendable_balance_for_send_scope(account.clone(), sender_address.as_ref()).await?;
            if spendable == 0 {
                return Err(Status::failed_precondition(
                    "isSendAll requested but no spendable balance is available for the selected send scope",
                ));
            }
            spendable
        } else {
            if request.amount == 0 {
                return Err(Status::invalid_argument("amount must be greater than zero when isSendAll=false"));
            }
            request.amount
        };
        let destination = PaymentDestination::from(PaymentOutput::new(to_address, send_value));

        let baseline_fee_mode = Self::fee_from_send_mode(request.is_send_all, 0);
        let baseline_total_fees =
            self.estimate_send_total_fees(account_id, sender_address.clone(), destination.clone(), baseline_fee_mode).await?;
        let baseline_feerate = self.network_normal_feerate().await?;
        let (priority_fee_sompi, max_total_fee_sompi) =
            Self::apply_fee_policy_to_estimate(request.fee_policy.as_ref(), baseline_total_fees, baseline_feerate)?;
        let selected_fee_mode = Self::fee_from_send_mode(request.is_send_all, priority_fee_sompi);

        let estimated_total_fees = if priority_fee_sompi == 0 {
            baseline_total_fees
        } else {
            self.estimate_send_total_fees(account_id, sender_address.clone(), destination.clone(), selected_fee_mode.clone()).await?
        };

        if let Some(max_total_fee) = max_total_fee_sompi {
            if estimated_total_fees > max_total_fee {
                return Err(Status::failed_precondition(format!(
                    "estimated total fees {estimated_total_fees} exceed configured max fee {max_total_fee} (policy: {})",
                    Self::describe_fee_policy(request.fee_policy.as_ref())
                )));
            }
        }
        if request.is_send_all && estimated_total_fees >= send_value {
            return Err(Status::failed_precondition(format!(
                "isSendAll leaves no spendable output after fees (estimated total fees: {estimated_total_fees}, spendable balance: {send_value})"
            )));
        }

        let response = self
            .wallet()
            .accounts_send_call(AccountsSendRequest {
                account_id,
                wallet_secret,
                payment_secret,
                sender_address,
                destination,
                priority_fee_sompi: selected_fee_mode,
                payload: None,
                fast_path: None,
            })
            .await
            .map_err(Self::status_internal)?;

        let tx_ids = response.transaction_ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>();
        Ok(Response::new(pb::SendResponse { tx_i_ds: tx_ids, signed_transactions: vec![] }))
    }

    async fn send_payload(&self, request: Request<pb::SendPayloadRequest>) -> Result<Response<pb::SendPayloadResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };

        let payload_hex = request.payload_hex.trim();
        if payload_hex.is_empty() {
            return Err(Status::invalid_argument("payload_hex must not be empty"));
        }
        let payload_hex = payload_hex.strip_prefix("0x").unwrap_or(payload_hex);
        let payload =
            hex::decode(payload_hex).map_err(|err| Status::invalid_argument(format!("payload_hex must be valid hex: {err}")))?;
        if payload.is_empty() {
            return Err(Status::invalid_argument("payload_hex decodes to empty payload"));
        }

        let carrier_sompi = if request.carrier_sompi == 0 { TOKEN_CARRIER_OUTPUT_SOMPI } else { request.carrier_sompi };
        let tx_ids = self.submit_payload_tx(account, wallet_secret, payload, sender_address, carrier_sompi).await?;
        Ok(Response::new(pb::SendPayloadResponse { tx_ids }))
    }

    async fn token_send(&self, request: Request<pb::TokenSendRequest>) -> Result<Response<pb::TokenSendResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let amount = Self::parse_positive_u128(request.amount_raw.as_str(), "amount_raw")?;
        let auth_input_index = if request.auth_input_index == 0 {
            DEFAULT_AUTH_INPUT_INDEX
        } else {
            Self::parse_auth_input_index(request.auth_input_index)?
        };

        let account = self.current_account()?;
        let recipient_address = Address::try_from(request.to_address.as_str())
            .map_err(|err| Status::invalid_argument(format!("invalid to_address: {err}")))?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let recipient_owner_id = self.resolve_owner_id(&recipient_address, "to_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload =
            Self::build_transfer_payload(request.asset_id.as_str(), recipient_owner_id.as_str(), amount, nonce, auth_input_index)?;

        let tx_ids = self.submit_payload_tx(account, wallet_secret, payload, sender_address, TOKEN_CARRIER_OUTPUT_SOMPI).await?;
        Ok(Response::new(pb::TokenSendResponse { tx_ids, nonce, sender_owner_id, recipient_owner_id }))
    }

    async fn token_mint(&self, request: Request<pb::TokenMintRequest>) -> Result<Response<pb::TokenMintResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let amount = Self::parse_positive_u128(request.amount_raw.as_str(), "amount_raw")?;
        let auth_input_index = if request.auth_input_index == 0 {
            DEFAULT_AUTH_INPUT_INDEX
        } else {
            Self::parse_auth_input_index(request.auth_input_index)?
        };

        let account = self.current_account()?;
        let recipient_address = Address::try_from(request.to_address.as_str())
            .map_err(|err| Status::invalid_argument(format!("invalid to_address: {err}")))?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let recipient_owner_id = self.resolve_owner_id(&recipient_address, "to_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload =
            Self::build_mint_payload(request.asset_id.as_str(), recipient_owner_id.as_str(), amount, nonce, auth_input_index)?;

        let tx_ids = self.submit_payload_tx(account, wallet_secret, payload, sender_address, TOKEN_CARRIER_OUTPUT_SOMPI).await?;
        Ok(Response::new(pb::TokenMintResponse { tx_ids, nonce, sender_owner_id, recipient_owner_id }))
    }

    async fn token_burn(&self, request: Request<pb::TokenBurnRequest>) -> Result<Response<pb::TokenBurnResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let amount = Self::parse_positive_u128(request.amount_raw.as_str(), "amount_raw")?;
        let auth_input_index = if request.auth_input_index == 0 {
            DEFAULT_AUTH_INPUT_INDEX
        } else {
            Self::parse_auth_input_index(request.auth_input_index)?
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_burn_payload(request.asset_id.as_str(), amount, nonce, auth_input_index)?;

        let tx_ids = self.submit_payload_tx(account, wallet_secret, payload, sender_address, TOKEN_CARRIER_OUTPUT_SOMPI).await?;
        Ok(Response::new(pb::TokenBurnResponse { tx_ids, nonce, sender_owner_id }))
    }

    async fn token_create(&self, request: Request<pb::TokenCreateRequest>) -> Result<Response<pb::TokenCreateResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let decimals = Self::parse_decimals(request.decimals)?;
        let max_supply = Self::parse_u128(request.max_supply_raw.as_str(), "max_supply_raw")?;
        let supply_mode = Self::validate_supply_mode(request.capped, max_supply)?;
        let metadata = Self::parse_metadata_hex(request.metadata_hex.as_str())?;
        Self::validate_platform_tag(request.platform_tag.as_str())?;
        Self::validate_asset_identity_fields(request.name.as_str(), request.symbol.as_str(), metadata.as_slice(), decimals)?;
        let auth_input_index = if request.auth_input_index == 0 {
            DEFAULT_AUTH_INPUT_INDEX
        } else {
            Self::parse_auth_input_index(request.auth_input_index)?
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };
        let mint_authority_address = if request.mint_authority_address.trim().is_empty() {
            sender_address.clone()
        } else {
            Address::try_from(request.mint_authority_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid mint_authority_address: {err}")))?
        };

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let mint_authority_owner_id = self.resolve_owner_id(&mint_authority_address, "mint_authority_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_create_asset_payload(
            request.name.as_str(),
            request.symbol.as_str(),
            decimals,
            supply_mode,
            max_supply,
            mint_authority_owner_id.as_str(),
            metadata.as_slice(),
            request.platform_tag.as_str(),
            nonce,
            auth_input_index,
        )?;

        let tx_ids = self.submit_payload_tx(account, wallet_secret, payload, sender_address, TOKEN_CARRIER_OUTPUT_SOMPI).await?;
        let asset_id = tx_ids.first().cloned().unwrap_or_default();
        Ok(Response::new(pb::TokenCreateResponse { tx_ids, nonce, sender_owner_id, mint_authority_owner_id, asset_id }))
    }

    async fn token_create_mint(
        &self,
        request: Request<pb::TokenCreateMintRequest>,
    ) -> Result<Response<pb::TokenCreateMintResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let decimals = Self::parse_decimals(request.decimals)?;
        let max_supply = Self::parse_u128(request.max_supply_raw.as_str(), "max_supply_raw")?;
        let supply_mode = Self::validate_supply_mode(request.capped, max_supply)?;
        let initial_mint_amount = Self::parse_positive_u128(request.initial_mint_amount_raw.as_str(), "initial_mint_amount_raw")?;
        if supply_mode == 1 && initial_mint_amount > max_supply {
            return Err(Status::invalid_argument("initial_mint_amount_raw exceeds max_supply_raw for capped token"));
        }

        let metadata = Self::parse_metadata_hex(request.metadata_hex.as_str())?;
        Self::validate_platform_tag(request.platform_tag.as_str())?;
        Self::validate_asset_identity_fields(request.name.as_str(), request.symbol.as_str(), metadata.as_slice(), decimals)?;
        let auth_input_index = if request.auth_input_index == 0 {
            DEFAULT_AUTH_INPUT_INDEX
        } else {
            Self::parse_auth_input_index(request.auth_input_index)?
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };
        let mint_authority_address = if request.mint_authority_address.trim().is_empty() {
            sender_address.clone()
        } else {
            Address::try_from(request.mint_authority_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid mint_authority_address: {err}")))?
        };
        let initial_mint_to_address = Address::try_from(request.initial_mint_to_address.as_str())
            .map_err(|err| Status::invalid_argument(format!("invalid initial_mint_to_address: {err}")))?;

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let mint_authority_owner_id = self.resolve_owner_id(&mint_authority_address, "mint_authority_address").await?;
        let initial_mint_to_owner_id = self.resolve_owner_id(&initial_mint_to_address, "initial_mint_to_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_create_asset_with_mint_payload(
            request.name.as_str(),
            request.symbol.as_str(),
            decimals,
            supply_mode,
            max_supply,
            mint_authority_owner_id.as_str(),
            metadata.as_slice(),
            initial_mint_amount,
            initial_mint_to_owner_id.as_str(),
            request.platform_tag.as_str(),
            nonce,
            auth_input_index,
        )?;

        let tx_ids = self.submit_payload_tx(account, wallet_secret, payload, sender_address, TOKEN_CARRIER_OUTPUT_SOMPI).await?;
        let asset_id = tx_ids.first().cloned().unwrap_or_default();
        Ok(Response::new(pb::TokenCreateMintResponse {
            tx_ids,
            nonce,
            sender_owner_id,
            mint_authority_owner_id,
            initial_mint_to_owner_id,
            asset_id,
        }))
    }

    async fn token_create_liquidity(
        &self,
        request: Request<pb::TokenCreateLiquidityRequest>,
    ) -> Result<Response<pb::TokenCreateLiquidityResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let decimals = Self::parse_decimals(request.decimals)?;
        let max_supply = Self::parse_positive_u128(request.max_supply_raw.as_str(), "max_supply_raw")?;
        let metadata = Self::parse_metadata_hex(request.metadata_hex.as_str())?;
        Self::validate_platform_tag(request.platform_tag.as_str())?;
        if request.liquidity_unlock_target_sompi > MAX_SOMPI {
            return Err(Status::invalid_argument(format!(
                "liquidity_unlock_target_sompi must be 0 or <= MAX_SOMPI ({MAX_SOMPI})"
            )));
        }
        Self::validate_asset_identity_fields(request.name.as_str(), request.symbol.as_str(), metadata.as_slice(), decimals)?;
        if request.seed_reserve_sompi == 0 {
            return Err(Status::invalid_argument("seed_reserve_sompi must be greater than zero"));
        }

        let fee_bps = u16::try_from(request.fee_bps).map_err(|_| Status::invalid_argument("fee_bps must be <= 65535"))?;
        if !(fee_bps == 0 || (CAT_MIN_LIQUIDITY_FEE_BPS..=CAT_MAX_LIQUIDITY_FEE_BPS).contains(&fee_bps)) {
            return Err(Status::invalid_argument(format!(
                "fee_bps must be 0 or between {CAT_MIN_LIQUIDITY_FEE_BPS} and {CAT_MAX_LIQUIDITY_FEE_BPS}"
            )));
        }
        let recipients = Self::parse_liquidity_recipients(request.recipient_addresses.as_slice())?;
        if fee_bps == 0 && !recipients.is_empty() {
            return Err(Status::invalid_argument("recipient_addresses must be empty when fee_bps is 0"));
        }
        if fee_bps > 0 && recipients.is_empty() {
            return Err(Status::invalid_argument("recipient_addresses must contain 1 or 2 entries when fee_bps is > 0"));
        }

        let launch_buy_min_token_out =
            Self::parse_u128(request.launch_buy_min_token_out_raw.as_str(), "launch_buy_min_token_out_raw")?;
        if request.launch_buy_sompi == 0 && launch_buy_min_token_out != 0 {
            return Err(Status::invalid_argument("launch_buy_min_token_out_raw must be 0 when launch_buy_sompi is 0"));
        }
        if request.launch_buy_sompi > 0 && launch_buy_min_token_out == 0 {
            return Err(Status::invalid_argument("launch_buy_min_token_out_raw must be > 0 when launch_buy_sompi is > 0"));
        }

        let auth_input_index = if request.auth_input_index == 0 {
            DEFAULT_AUTH_INPUT_INDEX
        } else {
            Self::parse_auth_input_index(request.auth_input_index)?
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_create_liquidity_asset_payload(
            request.name.as_str(),
            request.symbol.as_str(),
            decimals,
            max_supply,
            metadata.as_slice(),
            request.seed_reserve_sompi,
            fee_bps,
            recipients.as_slice(),
            request.launch_buy_sompi,
            launch_buy_min_token_out,
            request.platform_tag.as_str(),
            request.liquidity_unlock_target_sompi,
            nonce,
            auth_input_index,
        )?;

        let vault_value = request
            .seed_reserve_sompi
            .checked_add(request.launch_buy_sompi)
            .ok_or_else(|| Status::invalid_argument("seed_reserve_sompi + launch_buy_sompi overflows u64"))?;
        let destination = Self::liquidity_vault_destination(vault_value);
        let tx_ids = self.submit_payload_tx_to_destination(account, wallet_secret, payload, destination, Some(sender_address)).await?;
        let asset_id = tx_ids.first().cloned().unwrap_or_default();
        Ok(Response::new(pb::TokenCreateLiquidityResponse { tx_ids, nonce, sender_owner_id, asset_id }))
    }

    async fn token_buy_liquidity(
        &self,
        request: Request<pb::TokenBuyLiquidityRequest>,
    ) -> Result<Response<pb::TokenBuyLiquidityResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        if request.cpay_in_sompi == 0 {
            return Err(Status::invalid_argument("cpay_in_sompi must be greater than zero"));
        }
        let min_token_out = Self::parse_positive_u128(request.min_token_out_raw.as_str(), "min_token_out_raw")?;
        let auth_input_index = if request.auth_input_index == 0 {
            LIQUIDITY_AUTH_INPUT_INDEX
        } else {
            let parsed = Self::parse_auth_input_index(request.auth_input_index)?;
            if parsed != LIQUIDITY_AUTH_INPUT_INDEX {
                return Err(Status::invalid_argument("liquidity transitions require auth_input_index=1"));
            }
            parsed
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };
        let asset_id = Self::normalize_asset_id(request.asset_id.as_str());
        let pool = self.fetch_liquidity_pool(asset_id.as_str()).await?;
        Self::ensure_liquidity_outflow_unlocked(&pool, "liquidity sell")?;
        let quote = self
            .rpc()
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: asset_id.clone(),
                    side: LIQUIDITY_QUOTE_SIDE_BUY,
                    exact_in_amount: request.cpay_in_sompi.to_string(),
                    at_block_hash: None,
                },
            )
            .await
            .map_err(Self::status_internal)?;
        let token_out = Self::parse_u128(quote.amount_out.as_str(), "quote.amount_out")?;
        if token_out < min_token_out {
            return Err(Status::failed_precondition(format!(
                "min_token_out_raw is above current quote: min={} quote={}",
                min_token_out, token_out
            )));
        }

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_buy_liquidity_payload(
            asset_id.as_str(),
            pool.pool_nonce,
            request.cpay_in_sompi,
            min_token_out,
            nonce,
            auth_input_index,
        )?;
        let vault_value = Self::pool_vault_value(&pool)?
            .checked_add(request.cpay_in_sompi)
            .ok_or_else(|| Status::invalid_argument("vault value overflows u64 after buy"))?;
        let destination = Self::liquidity_vault_destination(vault_value);
        let vault_entry = Self::liquidity_vault_utxo_entry(&pool)?;
        let tx_ids =
            self.submit_liquidity_transition_tx(account, wallet_secret, payload, destination, sender_address, vault_entry).await?;

        Ok(Response::new(pb::TokenBuyLiquidityResponse {
            tx_ids,
            nonce,
            sender_owner_id,
            pool_nonce: pool.pool_nonce,
            token_out_raw: token_out.to_string(),
        }))
    }

    async fn token_sell_liquidity(
        &self,
        request: Request<pb::TokenSellLiquidityRequest>,
    ) -> Result<Response<pb::TokenSellLiquidityResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let token_in = Self::parse_positive_u128(request.token_in_raw.as_str(), "token_in_raw")?;
        if request.min_cpay_out_sompi == 0 {
            return Err(Status::invalid_argument("min_cpay_out_sompi must be greater than zero"));
        }
        let auth_input_index = if request.auth_input_index == 0 {
            LIQUIDITY_AUTH_INPUT_INDEX
        } else {
            let parsed = Self::parse_auth_input_index(request.auth_input_index)?;
            if parsed != LIQUIDITY_AUTH_INPUT_INDEX {
                return Err(Status::invalid_argument("liquidity transitions require auth_input_index=1"));
            }
            parsed
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };
        let asset_id = Self::normalize_asset_id(request.asset_id.as_str());
        let pool = self.fetch_liquidity_pool(asset_id.as_str()).await?;
        let quote = self
            .rpc()
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: asset_id.clone(),
                    side: LIQUIDITY_QUOTE_SIDE_SELL,
                    exact_in_amount: token_in.to_string(),
                    at_block_hash: None,
                },
            )
            .await
            .map_err(Self::status_internal)?;
        let cpay_out = Self::parse_u64(quote.amount_out.as_str(), "quote.amount_out")?;
        if cpay_out < request.min_cpay_out_sompi {
            return Err(Status::failed_precondition(format!(
                "min_cpay_out_sompi is above current quote: min={} quote={}",
                request.min_cpay_out_sompi, cpay_out
            )));
        }

        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_sell_liquidity_payload(
            asset_id.as_str(),
            pool.pool_nonce,
            token_in,
            request.min_cpay_out_sompi,
            1,
            nonce,
            auth_input_index,
        )?;
        let vault_value = Self::pool_vault_value(&pool)?
            .checked_sub(cpay_out)
            .ok_or_else(|| Status::invalid_argument("vault value underflows after sell"))?;
        let destination = Self::liquidity_vault_and_payout_destination(vault_value, cpay_out, &sender_address);
        let vault_entry = Self::liquidity_vault_utxo_entry(&pool)?;
        let tx_ids =
            self.submit_liquidity_transition_tx(account, wallet_secret, payload, destination, sender_address, vault_entry).await?;

        Ok(Response::new(pb::TokenSellLiquidityResponse {
            tx_ids,
            nonce,
            sender_owner_id,
            pool_nonce: pool.pool_nonce,
            cpay_out_sompi: cpay_out,
        }))
    }

    async fn token_claim_liquidity(
        &self,
        request: Request<pb::TokenClaimLiquidityRequest>,
    ) -> Result<Response<pb::TokenClaimLiquidityResponse>, Status> {
        let request = request.into_inner();
        let wallet_secret = Self::require_password(request.password)?;
        let recipient_index =
            u8::try_from(request.recipient_index).map_err(|_| Status::invalid_argument("recipient_index must be <= 255"))?;
        if request.claim_amount_sompi == 0 {
            return Err(Status::invalid_argument("claim_amount_sompi must be greater than zero"));
        }
        let auth_input_index = if request.auth_input_index == 0 {
            LIQUIDITY_AUTH_INPUT_INDEX
        } else {
            let parsed = Self::parse_auth_input_index(request.auth_input_index)?;
            if parsed != LIQUIDITY_AUTH_INPUT_INDEX {
                return Err(Status::invalid_argument("liquidity transitions require auth_input_index=1"));
            }
            parsed
        };

        let account = self.current_account()?;
        let sender_address = if request.sender_address.trim().is_empty() {
            account.receive_address().map_err(Self::status_internal)?
        } else {
            Address::try_from(request.sender_address.as_str())
                .map_err(|err| Status::invalid_argument(format!("invalid sender_address: {err}")))?
        };
        let asset_id = Self::normalize_asset_id(request.asset_id.as_str());
        let pool = self.fetch_liquidity_pool(asset_id.as_str()).await?;
        Self::ensure_liquidity_outflow_unlocked(&pool, "liquidity fee claim")?;
        let sender_owner_id = self.resolve_owner_id(&sender_address, "sender_address").await?;
        let nonce = self.resolve_sender_nonce(sender_owner_id.as_str()).await?;
        let payload = Self::build_claim_liquidity_payload(
            asset_id.as_str(),
            pool.pool_nonce,
            recipient_index,
            request.claim_amount_sompi,
            1,
            nonce,
            auth_input_index,
        )?;
        let vault_value = Self::pool_vault_value(&pool)?
            .checked_sub(request.claim_amount_sompi)
            .ok_or_else(|| Status::invalid_argument("vault value underflows after claim"))?;
        let destination = Self::liquidity_vault_and_payout_destination(vault_value, request.claim_amount_sompi, &sender_address);
        let vault_entry = Self::liquidity_vault_utxo_entry(&pool)?;
        let tx_ids =
            self.submit_liquidity_transition_tx(account, wallet_secret, payload, destination, sender_address, vault_entry).await?;

        Ok(Response::new(pb::TokenClaimLiquidityResponse { tx_ids, nonce, sender_owner_id, pool_nonce: pool.pool_nonce }))
    }

    async fn token_balances(&self, request: Request<pb::TokenBalancesRequest>) -> Result<Response<pb::TokenBalancesResponse>, Status> {
        let request = request.into_inner();
        if request.addresses.is_empty() {
            return Err(Status::invalid_argument("addresses must contain at least one address"));
        }

        let addresses = request
            .addresses
            .iter()
            .map(|address| {
                Address::try_from(address.as_str())
                    .map_err(|err| Status::invalid_argument(format!("invalid address `{address}`: {err}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let asset_filter = Self::parse_asset_filter(request.asset_ids.as_slice())?;
        let (address_balances, totals) = self.token_balances_for_addresses(addresses.as_slice(), asset_filter.as_ref()).await?;
        Ok(Response::new(pb::TokenBalancesResponse { address_balances, totals }))
    }

    async fn scan_addresses(&self, request: Request<pb::ScanAddressesRequest>) -> Result<Response<pb::ScanAddressesResponse>, Status> {
        let request = request.into_inner();
        if request.addresses.is_empty() {
            return Err(Status::invalid_argument("addresses must contain at least one address"));
        }

        let addresses = request
            .addresses
            .iter()
            .map(|address| {
                Address::try_from(address.as_str())
                    .map_err(|err| Status::invalid_argument(format!("invalid address `{address}`: {err}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (coin_balances, coin_available_total, coin_pending_total) = self.balances_for_addresses(addresses.as_slice()).await?;
        let asset_filter = Self::parse_asset_filter(request.asset_ids.as_slice())?;
        let (token_address_balances, token_totals) =
            self.token_balances_for_addresses(addresses.as_slice(), asset_filter.as_ref()).await?;

        Ok(Response::new(pb::ScanAddressesResponse {
            coin_balances,
            coin_available_total,
            coin_pending_total,
            token_address_balances,
            token_totals,
        }))
    }

    async fn sign(&self, _request: Request<pb::SignRequest>) -> Result<Response<pb::SignResponse>, Status> {
        Err(Status::unimplemented(
            "Sign is not implemented in rust wallet daemon yet (legacy unsigned transaction bytes format is not supported)",
        ))
    }

    async fn get_version(&self, _request: Request<pb::GetVersionRequest>) -> Result<Response<pb::GetVersionResponse>, Status> {
        Ok(Response::new(pb::GetVersionResponse { version: env!("CARGO_PKG_VERSION").to_string() }))
    }

    async fn bump_fee(&self, _request: Request<pb::BumpFeeRequest>) -> Result<Response<pb::BumpFeeResponse>, Status> {
        Err(Status::unimplemented("BumpFee is not implemented in rust wallet daemon yet"))
    }
}

#[derive(Clone)]
struct StartDaemonConfig {
    listen: String,
    rpc_server: String,
    wallet_secret: Option<Secret>,
    payment_secret: Option<Secret>,
    wallet_file: Option<String>,
    network_id: NetworkId,
    account_selector: Option<String>,
    create_if_missing: bool,
}

impl Default for StartDaemonConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_DAEMON_LISTEN.to_string(),
            rpc_server: DEFAULT_RPC_SERVER.to_string(),
            wallet_secret: None,
            payment_secret: None,
            wallet_file: None,
            network_id: NetworkId::new(NetworkType::Mainnet),
            account_selector: None,
            create_if_missing: false,
        }
    }
}

#[derive(Clone)]
struct GetDaemonVersionConfig {
    daemon_address: String,
}

impl Default for GetDaemonVersionConfig {
    fn default() -> Self {
        Self { daemon_address: DEFAULT_DAEMON_LISTEN.to_string() }
    }
}

pub fn handles_command(first_arg: Option<&str>) -> bool {
    matches!(
        first_arg,
        Some("--start-daemon")
            | Some("start-daemon")
            | Some("--daemon")
            | Some("get-daemon-version")
            | Some("version")
            | Some("--version")
            | Some("-V")
    )
}

pub async fn run_with_args(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("missing command".to_string());
    };

    match command {
        "--start-daemon" => {
            let cfg = parse_start_daemon_args(args[1..].to_vec())?;
            run_start_daemon(cfg).await
        }
        "start-daemon" | "--daemon" => Err("use --start-daemon to start the wallet daemon".to_string()),
        "get-daemon-version" => {
            let cfg = parse_get_daemon_version_args(args[1..].to_vec())?;
            run_get_daemon_version(cfg).await
        }
        "version" | "--version" | "-V" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn parse_start_daemon_args(args: Vec<String>) -> Result<StartDaemonConfig, String> {
    let mut cfg = StartDaemonConfig::default();
    let mut network_override: Option<NetworkType> = None;
    let mut network_id_arg: Option<NetworkId> = None;
    let mut net_suffix: Option<u32> = None;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--help" | "-h" => {
                print_start_daemon_help();
                std::process::exit(0);
            }
            "--listen" | "-l" => {
                i += 1;
                cfg.listen = args.get(i).cloned().ok_or_else(|| "missing value for --listen".to_string())?;
            }
            "--rpcserver" | "-s" => {
                i += 1;
                cfg.rpc_server = args.get(i).cloned().ok_or_else(|| "missing value for --rpcserver".to_string())?;
            }
            "--password" | "-p" => {
                i += 1;
                let value = args.get(i).cloned().ok_or_else(|| "missing value for --password".to_string())?;
                cfg.wallet_secret = Some(Secret::from(value));
            }
            "--payment-secret" => {
                i += 1;
                let value = args.get(i).cloned().ok_or_else(|| "missing value for --payment-secret".to_string())?;
                cfg.payment_secret = Some(Secret::from(value));
            }
            "--keys-file" | "--wallet-file" | "-f" => {
                i += 1;
                cfg.wallet_file = Some(args.get(i).cloned().ok_or_else(|| "missing value for --wallet-file".to_string())?);
            }
            "--network" => {
                i += 1;
                let value = args.get(i).cloned().ok_or_else(|| "missing value for --network".to_string())?;
                network_id_arg = Some(NetworkId::from_str(value.as_str()).map_err(|err| format!("invalid --network value: {err}"))?);
            }
            "--testnet" => network_override = merge_network_flag(network_override, NetworkType::Testnet)?,
            "--devnet" => network_override = merge_network_flag(network_override, NetworkType::Devnet)?,
            "--simnet" => network_override = merge_network_flag(network_override, NetworkType::Simnet)?,
            "--mainnet" => network_override = merge_network_flag(network_override, NetworkType::Mainnet)?,
            "--netsuffix" => {
                i += 1;
                let value = args.get(i).cloned().ok_or_else(|| "missing value for --netsuffix".to_string())?;
                net_suffix = Some(value.parse::<u32>().map_err(|err| format!("invalid --netsuffix value `{value}`: {err}"))?);
            }
            "--account" => {
                i += 1;
                cfg.account_selector = Some(args.get(i).cloned().ok_or_else(|| "missing value for --account".to_string())?);
            }
            "--create-if-missing" => cfg.create_if_missing = true,
            "--wait-timeout" | "-w" | "--profile" => {
                i += 1;
                let _ = args.get(i).cloned().ok_or_else(|| format!("missing value for {arg} (flag accepted for compatibility)"))?;
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--listen=") {
                    cfg.listen = value.to_string();
                } else if let Some(value) = arg.strip_prefix("--rpcserver=") {
                    cfg.rpc_server = value.to_string();
                } else if let Some(value) = arg.strip_prefix("--password=") {
                    cfg.wallet_secret = Some(Secret::from(value.to_string()));
                } else if let Some(value) = arg.strip_prefix("--payment-secret=") {
                    cfg.payment_secret = Some(Secret::from(value.to_string()));
                } else if let Some(value) = arg.strip_prefix("--wallet-file=") {
                    cfg.wallet_file = Some(value.to_string());
                } else if let Some(value) = arg.strip_prefix("--keys-file=") {
                    cfg.wallet_file = Some(value.to_string());
                } else if let Some(value) = arg.strip_prefix("--network=") {
                    network_id_arg = Some(NetworkId::from_str(value).map_err(|err| format!("invalid --network value: {err}"))?);
                } else if let Some(value) = arg.strip_prefix("--netsuffix=") {
                    net_suffix = Some(value.parse::<u32>().map_err(|err| format!("invalid --netsuffix value `{value}`: {err}"))?);
                } else if let Some(value) = arg.strip_prefix("--account=") {
                    cfg.account_selector = Some(value.to_string());
                } else if arg.starts_with('-') {
                    return Err(format!("unknown argument: {arg}"));
                } else {
                    return Err(format!("unexpected positional argument: {arg}"));
                }
            }
        }

        i += 1;
    }

    if cfg.wallet_secret.is_none() {
        return Err("missing --password for start-daemon".to_string());
    }

    cfg.network_id = if let Some(mut network_id) = network_id_arg {
        if let Some(network_type) = network_override {
            if network_id.network_type() != network_type {
                return Err("--network conflicts with --testnet/--devnet/--simnet/--mainnet".to_string());
            }
        }

        if let Some(suffix) = net_suffix {
            if network_id.network_type() != NetworkType::Testnet {
                return Err("--netsuffix is only valid on testnet".to_string());
            }
            network_id = NetworkId::with_suffix(NetworkType::Testnet, suffix);
        }

        network_id
    } else {
        match network_override.unwrap_or(NetworkType::Mainnet) {
            NetworkType::Testnet => {
                if let Some(suffix) = net_suffix {
                    NetworkId::with_suffix(NetworkType::Testnet, suffix)
                } else {
                    NetworkId::new(NetworkType::Testnet)
                }
            }
            NetworkType::Mainnet => {
                if net_suffix.is_some() {
                    return Err("--netsuffix is only valid on testnet".to_string());
                }
                NetworkId::new(NetworkType::Mainnet)
            }
            NetworkType::Devnet => {
                if net_suffix.is_some() {
                    return Err("--netsuffix is only valid on testnet".to_string());
                }
                NetworkId::new(NetworkType::Devnet)
            }
            NetworkType::Simnet => {
                if net_suffix.is_some() {
                    return Err("--netsuffix is only valid on testnet".to_string());
                }
                NetworkId::new(NetworkType::Simnet)
            }
        }
    };

    Ok(cfg)
}

fn parse_get_daemon_version_args(args: Vec<String>) -> Result<GetDaemonVersionConfig, String> {
    let mut cfg = GetDaemonVersionConfig::default();

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--help" | "-h" => {
                print_get_daemon_version_help();
                std::process::exit(0);
            }
            "--daemonaddress" | "-d" => {
                i += 1;
                cfg.daemon_address = args.get(i).cloned().ok_or_else(|| "missing value for --daemonaddress".to_string())?;
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--daemonaddress=") {
                    cfg.daemon_address = value.to_string();
                } else if arg.starts_with('-') {
                    return Err(format!("unknown argument: {arg}"));
                } else {
                    return Err(format!("unexpected positional argument: {arg}"));
                }
            }
        }
        i += 1;
    }

    Ok(cfg)
}

fn merge_network_flag(current: Option<NetworkType>, next: NetworkType) -> Result<Option<NetworkType>, String> {
    if let Some(existing) = current {
        if existing != next {
            return Err("multiple conflicting network flags supplied".to_string());
        }
    }
    Ok(Some(next))
}

async fn run_start_daemon(cfg: StartDaemonConfig) -> Result<(), String> {
    let listen_addr: SocketAddr = cfg.listen.parse().map_err(|err| format!("invalid --listen address `{}`: {err}", cfg.listen))?;

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let runtime = initialize_runtime(&cfg, shutdown_tx.clone()).await?;
    let service = WalletDaemonService::new(runtime.clone());

    println!("cryptix-wallet daemon listening on {} (network={}, rpcserver={})", cfg.listen, cfg.network_id, cfg.rpc_server);

    let shutdown_future = async move {
        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }
    };

    let serve_result = Server::builder()
        .add_service(pb::cryptixwalletd_server::CryptixwalletdServer::new(service))
        .serve_with_shutdown(listen_addr, shutdown_future)
        .await;

    let stop_result = runtime.wallet.stop().await.map_err(|err| format!("wallet stop failed: {err}"));
    if let Err(err) = serve_result {
        return Err(format!("wallet daemon server failed: {err}"));
    }
    stop_result?;

    Ok(())
}

async fn initialize_runtime(cfg: &StartDaemonConfig, shutdown_tx: watch::Sender<bool>) -> Result<Arc<WalletDaemonRuntime>, String> {
    let wallet_secret = cfg.wallet_secret.clone().ok_or_else(|| "missing wallet secret".to_string())?;

    let wallet = Arc::new(
        Wallet::try_new(Wallet::local_store().map_err(|err| err.to_string())?, Some(Resolver::default()), Some(cfg.network_id))
            .map_err(|err| format!("wallet initialization failed: {err}"))?,
    );

    wallet.start().await.map_err(|err| format!("wallet start failed: {err}"))?;

    wallet
        .clone()
        .connect_call(ConnectRequest {
            url: Some(cfg.rpc_server.clone()),
            network_id: cfg.network_id,
            retry_on_error: false,
            block_async_connect: true,
            require_sync: false,
        })
        .await
        .map_err(|err| format!("unable to connect wallet to node `{}`: {err}", cfg.rpc_server))?;

    wallet
        .clone()
        .wallet_open_call(WalletOpenRequest {
            wallet_secret: wallet_secret.clone(),
            filename: cfg.wallet_file.clone(),
            account_descriptors: true,
            legacy_accounts: Some(false),
        })
        .await
        .map_err(|err| format!("wallet open failed: {err}"))?;

    let mut accounts = wallet
        .clone()
        .accounts_enumerate_call(AccountsEnumerateRequest {})
        .await
        .map_err(|err| format!("unable to enumerate accounts: {err}"))?
        .account_descriptors;

    if accounts.is_empty() && cfg.create_if_missing {
        wallet
            .clone()
            .accounts_ensure_default_call(AccountsEnsureDefaultRequest {
                wallet_secret: wallet_secret.clone(),
                payment_secret: cfg.payment_secret.clone(),
                account_kind: BIP32_ACCOUNT_KIND.into(),
                mnemonic_phrase: None,
            })
            .await
            .map_err(|err| format!("unable to create default account: {err}"))?;

        accounts = wallet
            .clone()
            .accounts_enumerate_call(AccountsEnumerateRequest {})
            .await
            .map_err(|err| format!("unable to enumerate accounts after creation: {err}"))?
            .account_descriptors;
    }

    if accounts.is_empty() {
        return Err(
            "wallet has no accounts. create one in interactive CLI first, or start daemon with --create-if-missing".to_string()
        );
    }

    let selected = select_account(&accounts, cfg.account_selector.as_deref())?;

    wallet
        .clone()
        .accounts_activate_call(AccountsActivateRequest { account_ids: Some(vec![selected.account_id]) })
        .await
        .map_err(|err| format!("unable to activate selected account: {err}"))?;

    wallet
        .clone()
        .accounts_select_call(AccountsSelectRequest { account_id: Some(selected.account_id) })
        .await
        .map_err(|err| format!("unable to select account: {err}"))?;

    Ok(Arc::new(WalletDaemonRuntime { wallet, network_id: cfg.network_id, payment_secret: cfg.payment_secret.clone(), shutdown_tx }))
}

fn select_account(accounts: &[AccountDescriptor], selector: Option<&str>) -> Result<AccountDescriptor, String> {
    if accounts.is_empty() {
        return Err("no accounts available".to_string());
    }

    let Some(selector) = selector.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(accounts[0].clone());
    };

    let selector_lower = selector.to_ascii_lowercase();
    let mut matches = accounts
        .iter()
        .filter(|descriptor| {
            let id = descriptor.account_id.to_string();
            let name_match =
                descriptor.account_name.as_deref().map(|name| name.to_ascii_lowercase() == selector_lower).unwrap_or(false);
            name_match || id.eq_ignore_ascii_case(selector) || id.starts_with(selector)
        })
        .cloned()
        .collect::<Vec<_>>();

    match matches.len() {
        0 => Err(format!("account selector `{selector}` did not match any account")),
        1 => Ok(matches.remove(0)),
        _ => Err(format!("account selector `{selector}` is ambiguous; use full account id prefix to disambiguate")),
    }
}

async fn run_get_daemon_version(cfg: GetDaemonVersionConfig) -> Result<(), String> {
    let endpoint = normalize_grpc_endpoint(cfg.daemon_address.as_str());
    let mut client = pb::cryptixwalletd_client::CryptixwalletdClient::connect(endpoint.clone())
        .await
        .map_err(|err| format!("unable to connect to wallet daemon at {endpoint}: {err}"))?;
    let version = client
        .get_version(Request::new(pb::GetVersionRequest {}))
        .await
        .map_err(|err| format!("GetVersion RPC failed: {err}"))?
        .into_inner()
        .version;

    println!("{version}");
    Ok(())
}

fn normalize_grpc_endpoint(address: &str) -> String {
    if address.starts_with("http://") || address.starts_with("https://") {
        address.to_string()
    } else {
        format!("http://{address}")
    }
}

fn print_start_daemon_help() {
    println!("cryptix-wallet --start-daemon");
    println!("  starts the exchange-grade wallet daemon (coins + token RPC methods)");
    println!("  note: daemon startup command is only `--start-daemon`");
    println!("  --listen,-l <addr>              daemon listen address (default: {DEFAULT_DAEMON_LISTEN})");
    println!("  --rpcserver,-s <host[:port]>    node RPC endpoint/host (default: {DEFAULT_RPC_SERVER})");
    println!("  --password,-p <secret>          wallet secret (required)");
    println!("  --payment-secret <secret>       optional payment secret for encrypted mnemonics");
    println!("  --wallet-file,--keys-file,-f    wallet filename");
    println!("  --network <mainnet|testnet|devnet|simnet[-suffix]>");
    println!("  --testnet|--devnet|--simnet     network shortcuts");
    println!("  --netsuffix <n>                 testnet suffix");
    println!("  --account <name-or-id-prefix>   selected account");
    println!("  --create-if-missing             create a default account if wallet has none");
    println!("  coin RPC methods: GetBalance, ShowAddresses, NewAddress, Send, SendPayload, GetExternalSpendableUTXOs");
    println!("  token RPC methods: TokenSend, TokenMint, TokenBurn, TokenCreate, TokenCreateMint, TokenCreateLiquidity, TokenBuyLiquidity, TokenSellLiquidity, TokenClaimLiquidity");
    println!("  watch/scan RPC methods: TokenBalances, ScanAddresses");
}

fn print_get_daemon_version_help() {
    println!("cryptix-wallet get-daemon-version");
    println!("  --daemonaddress,-d <addr>       wallet daemon address (default: {DEFAULT_DAEMON_LISTEN})");
}
