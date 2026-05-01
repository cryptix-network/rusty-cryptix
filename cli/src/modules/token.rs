use crate::imports::*;
use cryptix_consensus_client::{TransactionOutpoint as ClientTransactionOutpoint, UtxoEntry, UtxoEntryReference};
use cryptix_consensus_core::{
    constants::{MAX_SOMPI, SOMPI_PER_CRYPTIX},
    tx::{ScriptPublicKey, TransactionId},
};
use cryptix_rpc_core::{GetLiquidityPoolStateRequest, GetLiquidityQuoteRequest, RpcLiquidityPoolState};
use cryptix_wallet_core::account::GenerationNotifier;
use cryptix_wallet_core::tx::{Generator, GeneratorSettings, GeneratorSummary, ScriptPaymentOutput, ScriptPaymentOutputs};
use std::collections::{BTreeMap, HashMap, HashSet};
use workflow_core::time::Duration;

const CAT_MAGIC: [u8; 3] = *b"CAT";
const CAT_VERSION: u8 = 1;
const CAT_CURRENT_TOKEN_VERSION: u8 = 1;
const CAT_CURRENT_LIQUIDITY_CURVE_VERSION: u8 = 1;
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
const MIN_LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 100_000;
const LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 1_000_000;
const DEFAULT_LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = LIQUIDITY_TOKEN_SUPPLY_RAW;
const MAX_LIQUIDITY_TOKEN_SUPPLY_RAW: u128 = 10_000_000;
const MIN_LIQUIDITY_SEED_RESERVE_SOMPI: u64 = SOMPI_PER_CRYPTIX;
const MIN_LIQUIDITY_REAL_TOKEN_RESERVE_RAW: u128 = 1;
const INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI: u64 = 250_000_000_000_000;

const DEFAULT_AUTH_INPUT_INDEX: u16 = 0;
const LIQUIDITY_AUTH_INPUT_INDEX: u16 = 1;
const LIQUIDITY_QUOTE_SIDE_BUY: u32 = 0;
const LIQUIDITY_QUOTE_SIDE_SELL: u32 = 1;
const TOKEN_CARRIER_OUTPUT_SOMPI: u64 = 1_000;
const TOKEN_OWNER_BALANCES_PAGE_LIMIT: u32 = 512;
const TOKEN_MONITOR_DEFAULT_INTERVAL_SECS: u64 = 5;
const LIQUIDITY_VAULT_SCRIPT_VERSION: u16 = 0;
const LIQUIDITY_VAULT_SCRIPT: [u8; 7] = [0x04, b'C', b'L', b'V', b'1', 0x75, 0x51];

#[derive(Clone)]
struct LiquidityRecipient {
    address_version: u8,
    address_payload: Vec<u8>,
}

struct TokenSnapshot {
    totals: BTreeMap<String, u128>,
    labels: HashMap<String, String>,
    skipped: Vec<String>,
}

#[derive(Default, Handler)]
#[help("Token operations (CAT): send, mint, burn, create, create-mint, create-liquidity, buy-liquidity, sell-liquidity, claim-liquidity, balances, monitor")]
pub struct Token;

impl Token {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, mut argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        if argv.is_empty() {
            return self.display_help(ctx, argv).await;
        }

        let op = argv.remove(0);
        match op.as_str() {
            "send" => self.send(ctx, argv).await,
            "mint" => self.mint(ctx, argv).await,
            "burn" => self.burn(ctx, argv).await,
            "create" => self.create(ctx, argv).await,
            "create-mint" => self.create_with_mint(ctx, argv).await,
            "create-liquidity" => self.create_liquidity(ctx, argv).await,
            "buy-liquidity" => self.buy_liquidity(ctx, argv).await,
            "sell-liquidity" => self.sell_liquidity(ctx, argv).await,
            "claim-liquidity" => self.claim_liquidity(ctx, argv).await,
            "balances" => self.balances(ctx, argv).await,
            "monitor" => self.monitor(ctx, argv).await,
            v => {
                tprintln!(ctx, "unknown command: '{v}'");
                self.display_help(ctx, vec![]).await
            }
        }
    }

    async fn send(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 3 || argv.len() > 4 {
            tprintln!(ctx, "usage: token send <assetId> <toAddress> <amountRaw> [senderAddress]");
            tprintln!(ctx, "note: amountRaw must be the raw integer token amount (u128 units)");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();

        let asset_id = argv.remove(0);
        let recipient_address = Address::try_from(argv.remove(0).as_str())?;
        let amount_raw = argv.remove(0);
        let amount = Self::parse_positive_u128(amount_raw.as_str(), "amountRaw")?;
        let sender_address =
            if let Some(sender) = argv.first() { Address::try_from(sender.as_str())? } else { account.receive_address()? };

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "senderAddress").await?;
        let recipient_owner_id = Self::resolve_owner_id(&rpc, &recipient_address, "toAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;

        let payload =
            Self::build_transfer_payload(asset_id.as_str(), recipient_owner_id.as_str(), amount, nonce, DEFAULT_AUTH_INPUT_INDEX)?;

        let (summary, ids) = Self::submit_payload_tx(&ctx, &account, payload, sender_address.clone()).await?;
        tprintln!(ctx, "Token send - {summary}");
        tprintln!(
            ctx,
            "asset={} amount={} recipient={} sender={} nonce={}",
            style(asset_id).dim(),
            amount,
            recipient_address,
            sender_address,
            nonce
        );
        tprintln!(ctx, "carrier output: {} sompi to sender address", TOKEN_CARRIER_OUTPUT_SOMPI);
        tprintln!(ctx, "tx ids:");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }

        Ok(())
    }

    async fn mint(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 3 || argv.len() > 4 {
            tprintln!(ctx, "usage: token mint <assetId> <toAddress> <amountRaw> [senderAddress]");
            tprintln!(ctx, "note: amountRaw must be the raw integer token amount (u128 units)");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();

        let asset_id = argv.remove(0);
        let recipient_address = Address::try_from(argv.remove(0).as_str())?;
        let amount_raw = argv.remove(0);
        let amount = Self::parse_positive_u128(amount_raw.as_str(), "amountRaw")?;
        let sender_address =
            if let Some(sender) = argv.first() { Address::try_from(sender.as_str())? } else { account.receive_address()? };

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "senderAddress").await?;
        let recipient_owner_id = Self::resolve_owner_id(&rpc, &recipient_address, "toAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;
        let payload =
            Self::build_mint_payload(asset_id.as_str(), recipient_owner_id.as_str(), amount, nonce, DEFAULT_AUTH_INPUT_INDEX)?;

        let (summary, ids) = Self::submit_payload_tx(&ctx, &account, payload, sender_address.clone()).await?;
        tprintln!(ctx, "Token mint - {summary}");
        tprintln!(
            ctx,
            "asset={} amount={} recipient={} sender={} nonce={}",
            style(asset_id).dim(),
            amount,
            recipient_address,
            sender_address,
            nonce
        );
        tprintln!(ctx, "carrier output: {} sompi to sender address", TOKEN_CARRIER_OUTPUT_SOMPI);
        tprintln!(ctx, "tx ids:");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }

        Ok(())
    }

    async fn burn(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 2 || argv.len() > 3 {
            tprintln!(ctx, "usage: token burn <assetId> <amountRaw> [senderAddress]");
            tprintln!(ctx, "note: amountRaw must be the raw integer token amount (u128 units)");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();

        let asset_id = argv.remove(0);
        let amount_raw = argv.remove(0);
        let amount = Self::parse_positive_u128(amount_raw.as_str(), "amountRaw")?;
        let sender_address =
            if let Some(sender) = argv.first() { Address::try_from(sender.as_str())? } else { account.receive_address()? };

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "senderAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;
        let payload = Self::build_burn_payload(asset_id.as_str(), amount, nonce, DEFAULT_AUTH_INPUT_INDEX)?;

        let (summary, ids) = Self::submit_payload_tx(&ctx, &account, payload, sender_address.clone()).await?;
        tprintln!(ctx, "Token burn - {summary}");
        tprintln!(ctx, "asset={} amount={} sender={} nonce={}", style(asset_id).dim(), amount, sender_address, nonce);
        tprintln!(ctx, "carrier output: {} sompi to sender address", TOKEN_CARRIER_OUTPUT_SOMPI);
        tprintln!(ctx, "tx ids:");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }

        Ok(())
    }

    async fn create(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 5 {
            tprintln!(ctx, "usage: token create <name> <symbol> <decimals> <uncapped|capped> <maxSupplyRaw> [--sender=<address>] [--mint-authority=<address>] [--metadata-hex=<hex>] [--platform-tag=<tag>]");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();

        let name = argv.remove(0);
        let symbol = argv.remove(0);
        let decimals = Self::parse_decimals(argv.remove(0).as_str())?;
        let supply_mode = Self::parse_supply_mode(argv.remove(0).as_str())?;
        let max_supply = Self::parse_u128(argv.remove(0).as_str(), "maxSupplyRaw")?;
        Self::validate_supply_mode(supply_mode, max_supply)?;

        let (sender_opt, mint_authority_opt, metadata, platform_tag) = Self::parse_create_options(argv)?;
        Self::validate_asset_identity_fields(name.as_str(), symbol.as_str(), metadata.as_slice(), decimals)?;

        let sender_address = sender_opt.unwrap_or(account.receive_address()?);
        let mint_authority_address = mint_authority_opt.unwrap_or_else(|| sender_address.clone());

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "--sender").await?;
        let mint_authority_owner_id = Self::resolve_owner_id(&rpc, &mint_authority_address, "--mint-authority").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;

        let payload = Self::build_create_asset_payload(
            name.as_str(),
            symbol.as_str(),
            decimals,
            supply_mode,
            max_supply,
            mint_authority_owner_id.as_str(),
            metadata.as_slice(),
            platform_tag.as_str(),
            nonce,
            DEFAULT_AUTH_INPUT_INDEX,
        )?;

        let (summary, ids) = Self::submit_payload_tx(&ctx, &account, payload, sender_address.clone()).await?;
        tprintln!(ctx, "Token create - {summary}");
        tprintln!(
            ctx,
            "name='{}' symbol='{}' decimals={} mode={} maxSupply={} sender={} mintAuthority={} nonce={}",
            name,
            symbol,
            decimals,
            if supply_mode == 0 { "uncapped" } else { "capped" },
            max_supply,
            sender_address,
            mint_authority_address,
            nonce
        );
        tprintln!(ctx, "carrier output: {} sompi to sender address", TOKEN_CARRIER_OUTPUT_SOMPI);
        tprintln!(ctx, "create tx ids (assetId is txid):");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }

        Ok(())
    }

    async fn create_with_mint(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 7 {
            tprintln!(ctx, "usage: token create-mint <name> <symbol> <decimals> <uncapped|capped> <maxSupplyRaw> <initialMintAmountRaw> <initialMintToAddress> [--sender=<address>] [--mint-authority=<address>] [--metadata-hex=<hex>] [--platform-tag=<tag>]");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();

        let name = argv.remove(0);
        let symbol = argv.remove(0);
        let decimals = Self::parse_decimals(argv.remove(0).as_str())?;
        let supply_mode = Self::parse_supply_mode(argv.remove(0).as_str())?;
        let max_supply = Self::parse_u128(argv.remove(0).as_str(), "maxSupplyRaw")?;
        Self::validate_supply_mode(supply_mode, max_supply)?;

        let initial_mint_amount = Self::parse_u128(argv.remove(0).as_str(), "initialMintAmountRaw")?;
        let initial_mint_to_address = Address::try_from(argv.remove(0).as_str())?;
        if initial_mint_amount == 0 {
            return Err(Error::custom("initialMintAmountRaw must be greater than zero"));
        }
        if supply_mode == 1 && initial_mint_amount > max_supply {
            return Err(Error::custom("initialMintAmountRaw exceeds maxSupplyRaw for capped token"));
        }

        let (sender_opt, mint_authority_opt, metadata, platform_tag) = Self::parse_create_options(argv)?;
        Self::validate_asset_identity_fields(name.as_str(), symbol.as_str(), metadata.as_slice(), decimals)?;

        let sender_address = sender_opt.unwrap_or(account.receive_address()?);
        let mint_authority_address = mint_authority_opt.unwrap_or_else(|| sender_address.clone());

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "--sender").await?;
        let mint_authority_owner_id = Self::resolve_owner_id(&rpc, &mint_authority_address, "--mint-authority").await?;
        let initial_mint_to_owner_id = Self::resolve_owner_id(&rpc, &initial_mint_to_address, "initialMintToAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;

        let payload = Self::build_create_asset_with_mint_payload(
            name.as_str(),
            symbol.as_str(),
            decimals,
            supply_mode,
            max_supply,
            mint_authority_owner_id.as_str(),
            metadata.as_slice(),
            initial_mint_amount,
            initial_mint_to_owner_id.as_str(),
            platform_tag.as_str(),
            nonce,
            DEFAULT_AUTH_INPUT_INDEX,
        )?;

        let (summary, ids) = Self::submit_payload_tx(&ctx, &account, payload, sender_address.clone()).await?;
        tprintln!(ctx, "Token create-mint - {summary}");
        tprintln!(
            ctx,
            "name='{}' symbol='{}' decimals={} mode={} maxSupply={} initialMint={} to={} sender={} mintAuthority={} nonce={}",
            name,
            symbol,
            decimals,
            if supply_mode == 0 { "uncapped" } else { "capped" },
            max_supply,
            initial_mint_amount,
            initial_mint_to_address,
            sender_address,
            mint_authority_address,
            nonce
        );
        tprintln!(ctx, "carrier output: {} sompi to sender address", TOKEN_CARRIER_OUTPUT_SOMPI);
        tprintln!(ctx, "create tx ids (assetId is txid):");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }

        Ok(())
    }

    async fn create_liquidity(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 6 {
            tprintln!(
                ctx,
                "usage: token create-liquidity <name> <symbol> <decimals=0> <maxSupplyRaw:{MIN_LIQUIDITY_TOKEN_SUPPLY_RAW}..={MAX_LIQUIDITY_TOKEN_SUPPLY_RAW}> <seedReserveSompi={MIN_LIQUIDITY_SEED_RESERVE_SOMPI}> <feeBps> [recipientAddress[,recipientAddress2]] [--launch-buy-sompi=<sompi>] [--launch-buy-min-token-out=<amountRaw>] [--sender=<address>] [--metadata-hex=<hex>] [--platform-tag=<tag>] [--liquidity-unlock-target-sompi=<sompi>]"
            );
            tprintln!(ctx, "defaults: maxSupplyRaw={DEFAULT_LIQUIDITY_TOKEN_SUPPLY_RAW}, decimals=0, seedReserveSompi=1 CPAY");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();

        let name = argv.remove(0);
        let symbol = argv.remove(0);
        let decimals = Self::parse_decimals(argv.remove(0).as_str())?;
        let max_supply = Self::parse_positive_u128(argv.remove(0).as_str(), "maxSupplyRaw")?;
        let seed_reserve_sompi = argv
            .remove(0)
            .parse::<u64>()
            .map_err(|err| Error::custom(format!("seedReserveSompi must be an unsigned integer: {err}")))?;
        if seed_reserve_sompi == 0 {
            return Err(Error::custom("seedReserveSompi must be greater than zero"));
        }
        let fee_bps =
            argv.remove(0).parse::<u16>().map_err(|err| Error::custom(format!("feeBps must be an unsigned integer: {err}")))?;
        if !(fee_bps == 0 || (CAT_MIN_LIQUIDITY_FEE_BPS..=CAT_MAX_LIQUIDITY_FEE_BPS).contains(&fee_bps)) {
            return Err(Error::custom(format!(
                "feeBps must be 0 or between {CAT_MIN_LIQUIDITY_FEE_BPS} and {CAT_MAX_LIQUIDITY_FEE_BPS}"
            )));
        }

        let mut recipients = Vec::new();
        if let Some(value) = argv.first() {
            if !value.starts_with("--") {
                let list = argv.remove(0);
                recipients = Self::parse_liquidity_recipients_csv(list.as_str())?;
            }
        }
        if fee_bps == 0 && !recipients.is_empty() {
            return Err(Error::custom("recipient addresses must be empty when feeBps is 0"));
        }
        if fee_bps > 0 && recipients.is_empty() {
            return Err(Error::custom("recipient addresses are required when feeBps is > 0"));
        }

        let (sender_opt, metadata, launch_buy_budget_sompi, launch_buy_min_token_out, platform_tag, liquidity_unlock_target_sompi) =
            Self::parse_create_liquidity_options(argv)?;
        Self::validate_asset_identity_fields(name.as_str(), symbol.as_str(), metadata.as_slice(), decimals)?;
        if launch_buy_budget_sompi == 0 && launch_buy_min_token_out != 0 {
            return Err(Error::custom("launchBuyMinTokenOut must be 0 when launchBuySompi is 0"));
        }
        if launch_buy_budget_sompi > 0 && launch_buy_min_token_out == 0 {
            return Err(Error::custom("launchBuyMinTokenOut must be > 0 when launchBuySompi is > 0"));
        }
        let (launch_buy_sompi, launch_buy_token_out) = if launch_buy_budget_sompi > 0 {
            let quoted_token_out = Self::quote_initial_liquidity_buy_token_out(max_supply, launch_buy_budget_sompi, fee_bps)?;
            if quoted_token_out < launch_buy_min_token_out {
                return Err(Error::custom(format!(
                    "launchBuyMinTokenOut is above current launch quote: min={} quote={}",
                    launch_buy_min_token_out, quoted_token_out
                )));
            }
            let virtual_tokens = Self::initial_liquidity_virtual_token_reserves(max_supply)?;
            let canonical = Self::min_liquidity_gross_input_for_token_out(
                max_supply,
                INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
                virtual_tokens,
                quoted_token_out,
                fee_bps,
            )?;
            (canonical, quoted_token_out)
        } else {
            (0, 0)
        };
        let launch_buy_unused_budget_sompi = launch_buy_budget_sompi
            .checked_sub(launch_buy_sompi)
            .ok_or_else(|| Error::custom("canonical launch buy exceeds provided budget"))?;

        let sender_address = sender_opt.unwrap_or(account.receive_address()?);
        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "--sender").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;
        let payload = Self::build_create_liquidity_asset_payload(
            name.as_str(),
            symbol.as_str(),
            decimals,
            max_supply,
            metadata.as_slice(),
            seed_reserve_sompi,
            fee_bps,
            recipients.as_slice(),
            launch_buy_sompi,
            launch_buy_min_token_out,
            platform_tag.as_str(),
            liquidity_unlock_target_sompi,
            nonce,
            DEFAULT_AUTH_INPUT_INDEX,
        )?;

        let vault_value = seed_reserve_sompi
            .checked_add(launch_buy_sompi)
            .ok_or_else(|| Error::custom("seedReserveSompi + launchBuySompi overflows u64"))?;
        let vault_destination = Self::liquidity_vault_destination(vault_value);
        let (summary, ids) =
            Self::submit_payload_tx_to_destination(&ctx, &account, payload, vault_destination, Some(sender_address.clone())).await?;

        tprintln!(ctx, "Token create-liquidity - {summary}");
        tprintln!(
            ctx,
            "name='{}' symbol='{}' decimals={} maxSupply={} seedReserveSompi={} feeBps={} launchBuySompi={} launchBuyMinTokenOut={} sender={} nonce={}",
            name,
            symbol,
            decimals,
            max_supply,
            seed_reserve_sompi,
            fee_bps,
            launch_buy_sompi,
            launch_buy_min_token_out,
            sender_address,
            nonce
        );
        if launch_buy_budget_sompi > launch_buy_sompi {
            tprintln!(
                ctx,
                "launch buy budget={} canonicalSpend={} unusedBudget={} quotedTokenOut={}",
                launch_buy_budget_sompi,
                launch_buy_sompi,
                launch_buy_unused_budget_sompi,
                launch_buy_token_out
            );
        }
        tprintln!(ctx, "liquidity vault output: value={} sompi script={} ", vault_value, hex::encode(LIQUIDITY_VAULT_SCRIPT));
        tprintln!(ctx, "create tx ids (assetId is txid):");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }

        Ok(())
    }

    async fn buy_liquidity(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 3 || argv.len() > 4 {
            tprintln!(ctx, "usage: token buy-liquidity <assetId> <cpayInSompi> <minTokenOutRaw> [senderAddress]");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();
        let asset_id = Self::normalize_asset_id(argv.remove(0).as_str());
        let cpay_budget_sompi = Self::parse_positive_u64(argv.remove(0).as_str(), "cpayInSompi")?;
        let min_token_out = Self::parse_positive_u128(argv.remove(0).as_str(), "minTokenOutRaw")?;
        let sender_address =
            if let Some(sender) = argv.first() { Address::try_from(sender.as_str())? } else { account.receive_address()? };

        let pool = Self::fetch_liquidity_pool(&rpc, asset_id.as_str()).await?;
        Self::ensure_liquidity_outflow_unlocked(&pool, "liquidity sell")?;
        let quote = rpc
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: asset_id.clone(),
                    side: LIQUIDITY_QUOTE_SIDE_BUY,
                    exact_in_amount: cpay_budget_sompi.to_string(),
                    at_block_hash: None,
                },
            )
            .await?;
        let quoted_token_out = Self::parse_u128(quote.amount_out.as_str(), "quote.amountOut")?;
        let cpay_in_sompi = Self::parse_positive_u64(quote.exact_in_amount.as_str(), "quote.exactInAmount")?;
        if cpay_in_sompi > cpay_budget_sompi {
            return Err(Error::custom(format!(
                "canonical buy input exceeds provided budget: canonical={} budget={}",
                cpay_in_sompi, cpay_budget_sompi
            )));
        }
        if quoted_token_out < min_token_out {
            return Err(Error::custom(format!(
                "minTokenOutRaw is above current quote: min={} quote={}",
                min_token_out, quoted_token_out
            )));
        }

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "senderAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;
        let payload = Self::build_buy_liquidity_payload(
            asset_id.as_str(),
            pool.pool_nonce,
            cpay_in_sompi,
            min_token_out,
            nonce,
            LIQUIDITY_AUTH_INPUT_INDEX,
        )?;

        let vault_value = Self::pool_vault_value(&pool)?
            .checked_add(cpay_in_sompi)
            .ok_or_else(|| Error::custom("vault value overflows u64 after buy"))?;
        let destination = Self::liquidity_vault_destination(vault_value);
        let vault_entry = Self::liquidity_vault_utxo_entry(&pool)?;
        let (summary, ids) =
            Self::submit_liquidity_transition_tx(&ctx, &account, payload, destination, sender_address.clone(), vault_entry).await?;

        tprintln!(ctx, "Token buy-liquidity - {summary}");
        tprintln!(
            ctx,
            "asset={} cpayInSompi={} tokenOut={} minTokenOut={} sender={} poolNonce={} nonce={}",
            style(asset_id).dim(),
            cpay_in_sompi,
            quoted_token_out,
            min_token_out,
            sender_address,
            pool.pool_nonce,
            nonce
        );
        if cpay_budget_sompi > cpay_in_sompi {
            tprintln!(
                ctx,
                "buy budget={} canonicalSpend={} unusedBudget={}",
                cpay_budget_sompi,
                cpay_in_sompi,
                cpay_budget_sompi - cpay_in_sompi
            );
        }
        tprintln!(ctx, "tx ids:");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }
        Ok(())
    }

    async fn sell_liquidity(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 3 || argv.len() > 4 {
            tprintln!(ctx, "usage: token sell-liquidity <assetId> <tokenInRaw> <minCpayOutSompi> [senderAddress]");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();
        let asset_id = Self::normalize_asset_id(argv.remove(0).as_str());
        let token_in = Self::parse_positive_u128(argv.remove(0).as_str(), "tokenInRaw")?;
        let min_cpay_out_sompi = Self::parse_positive_u64(argv.remove(0).as_str(), "minCpayOutSompi")?;
        let sender_address =
            if let Some(sender) = argv.first() { Address::try_from(sender.as_str())? } else { account.receive_address()? };

        let pool = Self::fetch_liquidity_pool(&rpc, asset_id.as_str()).await?;
        let quote = rpc
            .get_liquidity_quote_call(
                None,
                GetLiquidityQuoteRequest {
                    asset_id: asset_id.clone(),
                    side: LIQUIDITY_QUOTE_SIDE_SELL,
                    exact_in_amount: token_in.to_string(),
                    at_block_hash: None,
                },
            )
            .await?;
        let quoted_cpay_out = Self::parse_u64(quote.amount_out.as_str(), "quote.amountOut")?;
        if quoted_cpay_out < min_cpay_out_sompi {
            return Err(Error::custom(format!(
                "minCpayOutSompi is above current quote: min={} quote={}",
                min_cpay_out_sompi, quoted_cpay_out
            )));
        }

        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "senderAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;
        let payload = Self::build_sell_liquidity_payload(
            asset_id.as_str(),
            pool.pool_nonce,
            token_in,
            min_cpay_out_sompi,
            1,
            nonce,
            LIQUIDITY_AUTH_INPUT_INDEX,
        )?;

        let vault_value = Self::pool_vault_value(&pool)?
            .checked_sub(quoted_cpay_out)
            .ok_or_else(|| Error::custom("vault value underflows after sell"))?;
        let destination = Self::liquidity_vault_and_payout_destination(vault_value, quoted_cpay_out, &sender_address);
        let vault_entry = Self::liquidity_vault_utxo_entry(&pool)?;
        let (summary, ids) =
            Self::submit_liquidity_transition_tx(&ctx, &account, payload, destination, sender_address.clone(), vault_entry).await?;

        tprintln!(ctx, "Token sell-liquidity - {summary}");
        tprintln!(
            ctx,
            "asset={} tokenIn={} cpayOutSompi={} minCpayOutSompi={} sender={} poolNonce={} nonce={}",
            style(asset_id).dim(),
            token_in,
            quoted_cpay_out,
            min_cpay_out_sompi,
            sender_address,
            pool.pool_nonce,
            nonce
        );
        tprintln!(ctx, "tx ids:");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }
        Ok(())
    }

    async fn claim_liquidity(self: Arc<Self>, ctx: Arc<CryptixCli>, mut argv: Vec<String>) -> Result<()> {
        if argv.len() < 3 || argv.len() > 4 {
            tprintln!(ctx, "usage: token claim-liquidity <assetId> <recipientIndex> <claimAmountSompi> [senderAddress]");
            return Ok(());
        }

        let account = ctx.wallet().account()?;
        let rpc = ctx.wallet().rpc_api().clone();
        let asset_id = Self::normalize_asset_id(argv.remove(0).as_str());
        let recipient_index =
            argv.remove(0).parse::<u8>().map_err(|err| Error::custom(format!("recipientIndex must fit into u8: {err}")))?;
        let claim_amount_sompi = Self::parse_positive_u64(argv.remove(0).as_str(), "claimAmountSompi")?;
        let sender_address =
            if let Some(sender) = argv.first() { Address::try_from(sender.as_str())? } else { account.receive_address()? };

        let pool = Self::fetch_liquidity_pool(&rpc, asset_id.as_str()).await?;
        Self::ensure_liquidity_outflow_unlocked(&pool, "liquidity fee claim")?;
        let sender_owner_id = Self::resolve_owner_id(&rpc, &sender_address, "senderAddress").await?;
        let nonce = Self::resolve_sender_nonce(&rpc, sender_owner_id.as_str()).await?;
        let payload = Self::build_claim_liquidity_payload(
            asset_id.as_str(),
            pool.pool_nonce,
            recipient_index,
            claim_amount_sompi,
            1,
            nonce,
            LIQUIDITY_AUTH_INPUT_INDEX,
        )?;

        let vault_value = Self::pool_vault_value(&pool)?
            .checked_sub(claim_amount_sompi)
            .ok_or_else(|| Error::custom("vault value underflows after claim"))?;
        let destination = Self::liquidity_vault_and_payout_destination(vault_value, claim_amount_sompi, &sender_address);
        let vault_entry = Self::liquidity_vault_utxo_entry(&pool)?;
        let (summary, ids) =
            Self::submit_liquidity_transition_tx(&ctx, &account, payload, destination, sender_address.clone(), vault_entry).await?;

        tprintln!(ctx, "Token claim-liquidity - {summary}");
        tprintln!(
            ctx,
            "asset={} recipientIndex={} claimAmountSompi={} sender={} poolNonce={} nonce={}",
            style(asset_id).dim(),
            recipient_index,
            claim_amount_sompi,
            sender_address,
            pool.pool_nonce,
            nonce
        );
        tprintln!(ctx, "tx ids:");
        for id in ids {
            tprintln!(ctx, "  {id}");
        }
        Ok(())
    }

    async fn balances(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let (addresses, asset_filter, _, _) = Self::parse_balance_args(argv, false)?;
        let rpc = ctx.wallet().rpc_api().clone();
        let snapshot = Self::fetch_token_snapshot(&rpc, addresses.as_slice(), asset_filter.as_ref()).await?;
        Self::print_snapshot(&ctx, &snapshot, asset_filter.as_ref(), "Token balances");
        Ok(())
    }

    async fn monitor(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let (addresses, asset_filter, interval_secs, watch_mode) = Self::parse_balance_args(argv, true)?;
        let rpc = ctx.wallet().rpc_api().clone();

        if watch_mode {
            tprintln!(
                ctx,
                "Starting token monitor continuous mode ({}s interval). Stop with Ctrl+C. (This is monitor mode, not `start-daemon`.)",
                interval_secs
            );
        } else {
            tprintln!(ctx, "Starting token monitor ({}s interval). Press any key to stop.", interval_secs);
        }

        let mut ticker = interval(Duration::from_secs(interval_secs));
        let mut previous_totals: Option<BTreeMap<String, u128>> = None;

        if watch_mode {
            loop {
                ticker.next().await;
                Self::run_monitor_tick(&ctx, &rpc, addresses.as_slice(), asset_filter.as_ref(), &mut previous_totals).await;
            }
        } else {
            let (shutdown_tx, shutdown_rx) = oneshot();
            let term = ctx.term();
            spawn(async move {
                term.kbhit(None).await.ok();
                shutdown_tx.send(()).await.ok();
            });

            loop {
                select! {
                    _ = shutdown_rx.recv().fuse() => {
                        tprintln!(ctx, "Token monitor stopped.");
                        break;
                    }
                    _ = ticker.next().fuse() => {
                        Self::run_monitor_tick(&ctx, &rpc, addresses.as_slice(), asset_filter.as_ref(), &mut previous_totals).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_monitor_tick(
        ctx: &Arc<CryptixCli>,
        rpc: &Arc<DynRpcApi>,
        addresses: &[Address],
        asset_filter: Option<&HashSet<String>>,
        previous_totals: &mut Option<BTreeMap<String, u128>>,
    ) {
        match Self::fetch_token_snapshot(rpc, addresses, asset_filter).await {
            Ok(snapshot) => {
                Self::print_snapshot(ctx, &snapshot, asset_filter, "Token monitor snapshot");
                if let Some(prev) = previous_totals.as_ref() {
                    let incoming = Self::detect_incoming(prev, &snapshot.totals);
                    if !incoming.is_empty() {
                        tprintln!(ctx, "Incoming token deltas since last tick:");
                        for (asset_id, delta) in incoming {
                            let label = snapshot.labels.get(&asset_id).cloned().unwrap_or(asset_id);
                            tprintln!(ctx, "  +{} {}", delta, label);
                        }
                    }
                }
                *previous_totals = Some(snapshot.totals.clone());
            }
            Err(err) => {
                tprintln!(ctx, "Token monitor error: {}", style(err.to_string()).red());
            }
        }
    }

    async fn submit_payload_tx(
        ctx: &Arc<CryptixCli>,
        account: &Arc<dyn Account>,
        payload: Vec<u8>,
        sender_address: Address,
    ) -> Result<(GeneratorSummary, Vec<TransactionId>)> {
        let destination = PaymentDestination::from(PaymentOutputs::from((sender_address.clone(), TOKEN_CARRIER_OUTPUT_SOMPI)));
        Self::submit_payload_tx_to_destination(ctx, account, payload, destination, Some(sender_address)).await
    }

    async fn submit_payload_tx_to_destination(
        ctx: &Arc<CryptixCli>,
        account: &Arc<dyn Account>,
        payload: Vec<u8>,
        destination: PaymentDestination,
        sender_address: Option<Address>,
    ) -> Result<(GeneratorSummary, Vec<TransactionId>)> {
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(account)).await?;
        let abortable = Abortable::default();
        let notifier: GenerationNotifier = Arc::new(move |_ptx| {});
        let (summary, ids, _fast_summary) = account
            .clone()
            .send(
                destination,
                Fees::SenderPays(0),
                Some(payload),
                sender_address,
                None,
                wallet_secret,
                payment_secret,
                &abortable,
                Some(notifier),
            )
            .await?;
        Ok((summary, ids))
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

    fn liquidity_vault_utxo_entry(pool: &RpcLiquidityPoolState) -> Result<UtxoEntryReference> {
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

    fn pool_vault_value(pool: &RpcLiquidityPoolState) -> Result<u64> {
        Self::parse_u64(pool.vault_value_sompi.as_str(), "pool.vaultValueSompi")
    }

    async fn fetch_liquidity_pool(rpc: &Arc<DynRpcApi>, asset_id: &str) -> Result<RpcLiquidityPoolState> {
        let response = rpc
            .get_liquidity_pool_state_call(None, GetLiquidityPoolStateRequest { asset_id: asset_id.to_string(), at_block_hash: None })
            .await?;
        response.pool.ok_or_else(|| Error::custom(format!("liquidity pool not found for assetId {asset_id}")))
    }

    async fn submit_liquidity_transition_tx(
        ctx: &Arc<CryptixCli>,
        account: &Arc<dyn Account>,
        payload: Vec<u8>,
        destination: PaymentDestination,
        sender_address: Address,
        vault_entry: UtxoEntryReference,
    ) -> Result<(GeneratorSummary, Vec<TransactionId>)> {
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(account)).await?;
        let keydata = account.prv_key_data(wallet_secret).await?;
        let derivation = account.clone().as_derivation_capable()?;
        let (receive, change) = derivation.derivation().addresses_indexes(&[&sender_address])?;
        let mut private_keys = derivation
            .create_private_keys(&keydata, &payment_secret, &receive, &change)?
            .into_iter()
            .map(|(_, key)| key.secret_bytes())
            .collect::<Vec<_>>();
        if private_keys.is_empty() {
            return Err(Error::custom(format!("senderAddress {sender_address} is not controlled by the selected account")));
        }

        let abortable = Abortable::default();
        let settings = GeneratorSettings::try_new_with_account_and_priority_untracked(
            account.clone(),
            destination,
            Fees::SenderPays(0),
            Some(payload),
            Some(sender_address),
            Some(vec![vault_entry]),
        )?;
        let generator = Generator::try_new(settings, None, Some(&abortable))?;
        let mut stream = generator.stream();
        let mut ids = Vec::new();
        while let Some(transaction) = stream.try_next().await? {
            if !transaction.is_final() {
                Self::clear_private_keys(&mut private_keys);
                return Err(Error::custom(
                    "liquidity transition requires a single final transaction; consolidate sender UTXOs and retry",
                ));
            }
            transaction.set_input_sig_op_count(0, 0)?;
            transaction.try_sign_with_keys(&private_keys, Some(false))?;
            transaction.fill_input(0, vec![])?;
            ids.push(transaction.try_submit(&ctx.wallet().rpc_api()).await?);
            yield_executor().await;
        }
        Self::clear_private_keys(&mut private_keys);
        Ok((generator.summary(), ids))
    }

    fn clear_private_keys(private_keys: &mut [[u8; 32]]) {
        for key in private_keys {
            key.fill(0);
        }
    }

    async fn resolve_sender_nonce(rpc: &Arc<DynRpcApi>, sender_owner_id: &str) -> Result<u64> {
        let nonce_response = rpc
            .get_token_nonce_call(None, GetTokenNonceRequest { owner_id: sender_owner_id.to_string(), at_block_hash: None })
            .await?;
        let nonce = nonce_response.expected_next_nonce;
        if nonce == 0 {
            return Err(Error::custom("RPC returned expectedNextNonce=0; CAT nonce must be greater than zero"));
        }
        Ok(nonce)
    }

    async fn resolve_owner_id(rpc: &Arc<DynRpcApi>, address: &Address, label: &str) -> Result<String> {
        let response = rpc
            .get_token_owner_id_by_address_call(
                None,
                GetTokenOwnerIdByAddressRequest { address: address.to_string(), at_block_hash: None },
            )
            .await?;

        response.owner_id.ok_or_else(|| {
            let reason = response.reason.unwrap_or_else(|| "owner id not derivable for address".to_string());
            Error::custom(format!("{label} {} is not usable for token operations: {reason}", address))
        })
    }

    fn parse_balance_args(argv: Vec<String>, allow_interval: bool) -> Result<(Vec<Address>, Option<HashSet<String>>, u64, bool)> {
        let mut addresses = Vec::new();
        let mut asset_filter: Option<HashSet<String>> = None;
        let mut interval_secs = TOKEN_MONITOR_DEFAULT_INTERVAL_SECS;
        let mut daemon_mode = false;

        for arg in argv {
            if let Some(raw_assets) = arg.strip_prefix("--assets=") {
                if asset_filter.is_some() {
                    return Err(Error::custom("--assets may only be provided once"));
                }
                asset_filter = Some(Self::parse_asset_filter(raw_assets)?);
                continue;
            }

            if let Some(raw_interval) = arg.strip_prefix("--interval=") {
                if !allow_interval {
                    return Err(Error::custom("--interval is only supported for token monitor"));
                }
                interval_secs = raw_interval
                    .parse::<u64>()
                    .map_err(|err| Error::custom(format!("--interval must be an integer number of seconds: {err}")))?;
                if interval_secs == 0 {
                    return Err(Error::custom("--interval must be greater than zero"));
                }
                continue;
            }

            if arg == "--daemon" {
                return Err(Error::custom(
                    "`--daemon` is reserved for wallet daemon startup (`--start-daemon`). Use `--watch` for monitor loop mode.",
                ));
            }

            if arg == "--watch" {
                if !allow_interval {
                    return Err(Error::custom("--watch is only supported for token monitor"));
                }
                if daemon_mode {
                    return Err(Error::custom("--watch may only be provided once"));
                }
                daemon_mode = true;
                continue;
            }

            addresses.push(Address::try_from(arg.as_str())?);
        }

        if addresses.is_empty() {
            if allow_interval {
                return Err(Error::custom(
                    "Usage: token monitor <address> [address2 ...] [--assets=<assetId,assetId2>] [--interval=<seconds>] [--watch]",
                ));
            }
            return Err(Error::custom("Usage: token balances <address> [address2 ...] [--assets=<assetId,assetId2>]"));
        }

        Ok((addresses, asset_filter, interval_secs, daemon_mode))
    }

    fn parse_asset_filter(raw_assets: &str) -> Result<HashSet<String>> {
        let mut out = HashSet::new();
        for raw in raw_assets.split(',').map(str::trim).filter(|part| !part.is_empty()) {
            let bytes = Self::parse_hex_32(raw, "assetId in --assets")?;
            out.insert(bytes.as_slice().to_hex().to_lowercase());
        }
        if out.is_empty() {
            return Err(Error::custom("--assets must contain at least one asset id"));
        }
        Ok(out)
    }

    async fn fetch_token_snapshot(
        rpc: &Arc<DynRpcApi>,
        addresses: &[Address],
        asset_filter: Option<&HashSet<String>>,
    ) -> Result<TokenSnapshot> {
        let mut seen_addresses = HashSet::new();
        let mut totals: BTreeMap<String, u128> = BTreeMap::new();
        let mut labels: HashMap<String, String> = HashMap::new();
        let mut skipped = Vec::new();

        for address in addresses {
            let address_string = address.to_string();
            if !seen_addresses.insert(address_string.clone()) {
                continue;
            }

            let owner_response = rpc
                .get_token_owner_id_by_address_call(
                    None,
                    GetTokenOwnerIdByAddressRequest { address: address_string.clone(), at_block_hash: None },
                )
                .await?;

            let Some(owner_id) = owner_response.owner_id else {
                let reason = owner_response.reason.unwrap_or_else(|| "owner id not derivable".to_string());
                skipped.push(format!("{address_string}: {reason}"));
                continue;
            };

            let mut offset = 0u32;
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
                    .await?;

                if response.balances.is_empty() {
                    break;
                }

                let page_len = response.balances.len() as u32;
                for balance in response.balances {
                    let asset_id_normalized = Self::normalize_asset_id(balance.asset_id.as_str());
                    if let Some(filter) = asset_filter {
                        if !filter.contains(&asset_id_normalized) {
                            continue;
                        }
                    }

                    let amount = balance.balance.parse::<u128>().map_err(|err| {
                        Error::custom(format!("Invalid token balance `{}` for asset `{}`: {err}", balance.balance, balance.asset_id))
                    })?;

                    if let Some(asset) = balance.asset {
                        let label = if asset.symbol.is_empty() {
                            asset_id_normalized.clone()
                        } else {
                            format!("{} ({})", asset.symbol, asset_id_normalized)
                        };
                        labels.insert(asset_id_normalized.clone(), label);
                    } else {
                        labels.entry(asset_id_normalized.clone()).or_insert_with(|| asset_id_normalized.clone());
                    }
                    *totals.entry(asset_id_normalized).or_insert(0) += amount;
                }

                offset = offset.saturating_add(page_len);
                if u64::from(offset) >= response.total {
                    break;
                }
            }
        }

        Ok(TokenSnapshot { totals, labels, skipped })
    }

    fn print_snapshot(ctx: &Arc<CryptixCli>, snapshot: &TokenSnapshot, asset_filter: Option<&HashSet<String>>, title: &str) {
        tprintln!(ctx, "{title}:");
        if !snapshot.skipped.is_empty() {
            tprintln!(ctx, "Skipped addresses:");
            for line in snapshot.skipped.iter() {
                tprintln!(ctx, "  {line}");
            }
        }

        if let Some(filter) = asset_filter {
            if filter.is_empty() {
                tprintln!(ctx, "  (none)");
                tprintln!(ctx);
                return;
            }

            let mut assets: Vec<String> = filter.iter().cloned().collect();
            assets.sort();
            for asset_id in assets {
                let total = snapshot.totals.get(&asset_id).copied().unwrap_or(0);
                let label = snapshot.labels.get(&asset_id).cloned().unwrap_or(asset_id);
                tprintln!(ctx, "  {label}: {total}");
            }
        } else if snapshot.totals.is_empty() {
            tprintln!(ctx, "  (none)");
        } else {
            for (asset_id, total) in snapshot.totals.iter() {
                let label = snapshot.labels.get(asset_id).cloned().unwrap_or_else(|| asset_id.clone());
                tprintln!(ctx, "  {label}: {total}");
            }
        }
        tprintln!(ctx);
    }

    fn detect_incoming(previous: &BTreeMap<String, u128>, current: &BTreeMap<String, u128>) -> Vec<(String, u128)> {
        let mut deltas = Vec::new();
        for (asset_id, value_now) in current.iter() {
            let value_before = previous.get(asset_id).copied().unwrap_or(0);
            if *value_now > value_before {
                deltas.push((asset_id.clone(), *value_now - value_before));
            }
        }
        deltas
    }

    fn parse_supply_mode(value: &str) -> Result<u8> {
        match value.to_ascii_lowercase().as_str() {
            "0" | "uncapped" => Ok(0),
            "1" | "capped" => Ok(1),
            _ => Err(Error::custom("supply mode must be `uncapped|capped` or `0|1`")),
        }
    }

    fn validate_supply_mode(supply_mode: u8, max_supply: u128) -> Result<()> {
        match supply_mode {
            0 if max_supply != 0 => Err(Error::custom("maxSupplyRaw must be 0 for uncapped supply mode")),
            1 if max_supply == 0 => Err(Error::custom("maxSupplyRaw must be > 0 for capped supply mode")),
            _ => Ok(()),
        }
    }

    fn parse_create_options(mut argv: Vec<String>) -> Result<(Option<Address>, Option<Address>, Vec<u8>, String)> {
        let mut sender = None;
        let mut mint_authority = None;
        let mut metadata = Vec::new();
        let mut platform_tag = None;

        while !argv.is_empty() {
            let arg = argv.remove(0);
            if let Some(raw) = arg.strip_prefix("--sender=") {
                if sender.is_some() {
                    return Err(Error::custom("--sender provided more than once"));
                }
                sender = Some(Address::try_from(raw)?);
            } else if let Some(raw) = arg.strip_prefix("--mint-authority=") {
                if mint_authority.is_some() {
                    return Err(Error::custom("--mint-authority provided more than once"));
                }
                mint_authority = Some(Address::try_from(raw)?);
            } else if let Some(raw) = arg.strip_prefix("--metadata-hex=") {
                if !metadata.is_empty() {
                    return Err(Error::custom("--metadata-hex provided more than once"));
                }
                let normalized = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
                metadata = Vec::<u8>::from_hex(normalized)
                    .map_err(|err| Error::custom(format!("--metadata-hex must be valid hex: {err}")))?;
            } else if let Some(raw) = arg.strip_prefix("--platform-tag=") {
                if platform_tag.is_some() {
                    return Err(Error::custom("--platform-tag provided more than once"));
                }
                Self::validate_platform_tag(raw)?;
                platform_tag = Some(raw.to_string());
            } else {
                return Err(Error::custom(format!(
                    "unknown option `{arg}`. supported: --sender=, --mint-authority=, --metadata-hex=, --platform-tag="
                )));
            }
        }

        Ok((sender, mint_authority, metadata, platform_tag.unwrap_or_default()))
    }

    fn parse_create_liquidity_options(mut argv: Vec<String>) -> Result<(Option<Address>, Vec<u8>, u64, u128, String, u64)> {
        let mut sender = None;
        let mut metadata = Vec::new();
        let mut launch_buy_sompi = 0u64;
        let mut launch_buy_min_token_out = 0u128;
        let mut platform_tag = None;
        let mut liquidity_unlock_target_sompi = 0u64;
        let mut launch_buy_sompi_set = false;
        let mut launch_buy_min_set = false;
        let mut unlock_target_set = false;

        while !argv.is_empty() {
            let arg = argv.remove(0);
            if let Some(raw) = arg.strip_prefix("--sender=") {
                if sender.is_some() {
                    return Err(Error::custom("--sender provided more than once"));
                }
                sender = Some(Address::try_from(raw)?);
            } else if let Some(raw) = arg.strip_prefix("--metadata-hex=") {
                if !metadata.is_empty() {
                    return Err(Error::custom("--metadata-hex provided more than once"));
                }
                let normalized = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
                metadata = Vec::<u8>::from_hex(normalized)
                    .map_err(|err| Error::custom(format!("--metadata-hex must be valid hex: {err}")))?;
            } else if let Some(raw) = arg.strip_prefix("--launch-buy-sompi=") {
                if launch_buy_sompi_set {
                    return Err(Error::custom("--launch-buy-sompi provided more than once"));
                }
                launch_buy_sompi_set = true;
                launch_buy_sompi = raw
                    .parse::<u64>()
                    .map_err(|err| Error::custom(format!("--launch-buy-sompi must be an unsigned integer: {err}")))?;
            } else if let Some(raw) = arg.strip_prefix("--launch-buy-min-token-out=") {
                if launch_buy_min_set {
                    return Err(Error::custom("--launch-buy-min-token-out provided more than once"));
                }
                launch_buy_min_set = true;
                launch_buy_min_token_out = Self::parse_u128(raw, "--launch-buy-min-token-out")?;
            } else if let Some(raw) = arg.strip_prefix("--platform-tag=") {
                if platform_tag.is_some() {
                    return Err(Error::custom("--platform-tag provided more than once"));
                }
                Self::validate_platform_tag(raw)?;
                platform_tag = Some(raw.to_string());
            } else if let Some(raw) = arg.strip_prefix("--liquidity-unlock-target-sompi=") {
                if unlock_target_set {
                    return Err(Error::custom("--liquidity-unlock-target-sompi provided more than once"));
                }
                unlock_target_set = true;
                liquidity_unlock_target_sompi = Self::parse_u64(raw, "--liquidity-unlock-target-sompi")?;
                if liquidity_unlock_target_sompi > MAX_SOMPI {
                    return Err(Error::custom(format!("--liquidity-unlock-target-sompi must be 0 or <= MAX_SOMPI ({MAX_SOMPI})")));
                }
            } else {
                return Err(Error::custom(format!(
                    "unknown option `{arg}`. supported: --sender=, --metadata-hex=, --launch-buy-sompi=, --launch-buy-min-token-out=, --platform-tag=, --liquidity-unlock-target-sompi="
                )));
            }
        }

        if launch_buy_sompi_set != launch_buy_min_set {
            return Err(Error::custom("--launch-buy-sompi and --launch-buy-min-token-out must be provided together"));
        }

        Ok((
            sender,
            metadata,
            launch_buy_sompi,
            launch_buy_min_token_out,
            platform_tag.unwrap_or_default(),
            liquidity_unlock_target_sompi,
        ))
    }

    fn parse_liquidity_recipients_csv(csv: &str) -> Result<Vec<LiquidityRecipient>> {
        if csv.trim().is_empty() {
            return Ok(vec![]);
        }

        let mut recipients = Vec::new();
        for (index, raw_address) in csv.split(',').map(str::trim).filter(|value| !value.is_empty()).enumerate() {
            let address = Address::try_from(raw_address)
                .map_err(|err| Error::custom(format!("recipient address at position {} is invalid: {err}", index + 1)))?;
            if address.payload.len() != address.version.public_key_len() {
                return Err(Error::custom(format!(
                    "recipient address at position {} has invalid payload length {} for version {}",
                    index + 1,
                    address.payload.len(),
                    address.version
                )));
            }
            recipients.push(LiquidityRecipient { address_version: address.version as u8, address_payload: address.payload.to_vec() });
        }

        if recipients.len() > CAT_MAX_LIQUIDITY_RECIPIENTS {
            return Err(Error::custom(format!("recipient list supports at most {CAT_MAX_LIQUIDITY_RECIPIENTS} entries")));
        }
        if recipients.len() == 2 {
            if recipients[0].address_version == recipients[1].address_version
                && recipients[0].address_payload == recipients[1].address_payload
            {
                return Err(Error::custom("recipient addresses must not contain duplicates"));
            }
            let key_a = (recipients[0].address_version, recipients[0].address_payload.as_slice());
            let key_b = (recipients[1].address_version, recipients[1].address_payload.as_slice());
            if key_a > key_b {
                return Err(Error::custom("recipient addresses must be in canonical lexicographic order"));
            }
        }

        Ok(recipients)
    }

    fn validate_asset_identity_fields(name: &str, symbol: &str, metadata: &[u8], decimals: u8) -> Result<()> {
        if decimals > CAT_MAX_DECIMALS {
            return Err(Error::custom(format!("decimals must be <= {}", CAT_MAX_DECIMALS)));
        }
        if name.len() > CAT_MAX_NAME_LEN {
            return Err(Error::custom(format!("name must be <= {} bytes", CAT_MAX_NAME_LEN)));
        }
        if symbol.len() > CAT_MAX_SYMBOL_LEN {
            return Err(Error::custom(format!("symbol must be <= {} bytes", CAT_MAX_SYMBOL_LEN)));
        }
        if metadata.len() > CAT_MAX_METADATA_LEN {
            return Err(Error::custom(format!("metadata must be <= {} bytes", CAT_MAX_METADATA_LEN)));
        }
        Ok(())
    }

    fn validate_platform_tag(platform_tag: &str) -> Result<()> {
        if platform_tag.len() > CAT_MAX_PLATFORM_TAG_LEN {
            return Err(Error::custom(format!("platform tag must be <= {} UTF-8 bytes", CAT_MAX_PLATFORM_TAG_LEN)));
        }
        Ok(())
    }

    fn append_platform_tag_tail(payload: &mut Vec<u8>, platform_tag: &str) -> Result<()> {
        Self::validate_platform_tag(platform_tag)?;
        let tag_len = u8::try_from(platform_tag.len()).map_err(|_| Error::custom("platform tag length does not fit into u8"))?;
        payload.push(tag_len);
        payload.extend_from_slice(platform_tag.as_bytes());
        Ok(())
    }

    fn append_optional_platform_tag_tail(payload: &mut Vec<u8>, platform_tag: &str) -> Result<()> {
        Self::validate_platform_tag(platform_tag)?;
        if !platform_tag.is_empty() {
            Self::append_platform_tag_tail(payload, platform_tag)?;
        }
        Ok(())
    }

    fn ensure_liquidity_outflow_unlocked(pool: &RpcLiquidityPoolState, operation: &str) -> Result<()> {
        if pool.sell_locked {
            return Err(Error::custom(format!(
                "{operation} is locked until realCpayReservesSompi reaches {}",
                pool.unlock_target_sompi
            )));
        }
        Ok(())
    }

    fn parse_decimals(value: &str) -> Result<u8> {
        let decimals = value.parse::<u8>().map_err(|err| Error::custom(format!("invalid decimals value: {err}")))?;
        if decimals > CAT_MAX_DECIMALS {
            return Err(Error::custom(format!("decimals must be <= {}", CAT_MAX_DECIMALS)));
        }
        Ok(decimals)
    }

    fn parse_u128(value: &str, field_name: &str) -> Result<u128> {
        value.parse::<u128>().map_err(|err| Error::custom(format!("{field_name} must be an unsigned integer: {err}")))
    }

    fn parse_positive_u128(value: &str, field_name: &str) -> Result<u128> {
        let parsed = Self::parse_u128(value, field_name)?;
        if parsed == 0 {
            return Err(Error::custom(format!("{field_name} must be greater than zero")));
        }
        Ok(parsed)
    }

    fn parse_u64(value: &str, field_name: &str) -> Result<u64> {
        value.parse::<u64>().map_err(|err| Error::custom(format!("{field_name} must be an unsigned integer: {err}")))
    }

    fn parse_positive_u64(value: &str, field_name: &str) -> Result<u64> {
        let parsed = Self::parse_u64(value, field_name)?;
        if parsed == 0 {
            return Err(Error::custom(format!("{field_name} must be greater than zero")));
        }
        Ok(parsed)
    }

    fn parse_hex_32(value: &str, field_name: &str) -> Result<[u8; 32]> {
        let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        let bytes = Vec::<u8>::from_hex(normalized)
            .map_err(|err| Error::custom(format!("{field_name} must be valid hex (optional 0x prefix): {err}")))?;
        if bytes.len() != 32 {
            return Err(Error::custom(format!("{field_name} must be exactly 32 bytes (64 hex chars), got {} bytes", bytes.len())));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes.as_slice());
        Ok(out)
    }

    fn normalize_asset_id(value: &str) -> String {
        value.trim().strip_prefix("0x").unwrap_or(value.trim()).to_lowercase()
    }

    fn build_header(op: u8, nonce: u64, auth_input_index: u16) -> Result<Vec<u8>> {
        if nonce == 0 {
            return Err(Error::custom("nonce must be greater than zero"));
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
    ) -> Result<()> {
        let mint_authority_owner_id = Self::parse_hex_32(mint_authority_owner_id, "mintAuthorityOwnerId")?;
        payload.push(CAT_CURRENT_TOKEN_VERSION);
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

    fn build_transfer_payload(asset_id: &str, to_owner_id: &str, amount: u128, nonce: u64, auth_input_index: u16) -> Result<Vec<u8>> {
        let asset_id = Self::parse_hex_32(asset_id, "assetId")?;
        let to_owner_id = Self::parse_hex_32(to_owner_id, "toOwnerId")?;
        let mut payload = Self::build_header(CAT_OP_TRANSFER, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&to_owner_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        Ok(payload)
    }

    fn build_mint_payload(asset_id: &str, to_owner_id: &str, amount: u128, nonce: u64, auth_input_index: u16) -> Result<Vec<u8>> {
        let asset_id = Self::parse_hex_32(asset_id, "assetId")?;
        let to_owner_id = Self::parse_hex_32(to_owner_id, "toOwnerId")?;
        let mut payload = Self::build_header(CAT_OP_MINT, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&to_owner_id);
        payload.extend_from_slice(&amount.to_le_bytes());
        Ok(payload)
    }

    fn build_burn_payload(asset_id: &str, amount: u128, nonce: u64, auth_input_index: u16) -> Result<Vec<u8>> {
        let asset_id = Self::parse_hex_32(asset_id, "assetId")?;
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
    ) -> Result<Vec<u8>> {
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
    ) -> Result<Vec<u8>> {
        let initial_mint_to_owner_id = Self::parse_hex_32(initial_mint_to_owner_id, "initialMintToOwnerId")?;
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
    ) -> Result<Vec<u8>> {
        if max_supply == 0 {
            return Err(Error::custom("maxSupplyRaw must be greater than zero"));
        }
        if seed_reserve_sompi == 0 {
            return Err(Error::custom("seedReserveSompi must be greater than zero"));
        }
        Self::validate_platform_tag(platform_tag)?;
        if liquidity_unlock_target_sompi > MAX_SOMPI {
            return Err(Error::custom(format!("liquidityUnlockTargetSompi must be 0 or <= MAX_SOMPI ({MAX_SOMPI})")));
        }
        Self::validate_liquidity_create_parameters(decimals, max_supply, seed_reserve_sompi)?;
        if recipients.len() > CAT_MAX_LIQUIDITY_RECIPIENTS {
            return Err(Error::custom(format!("recipient list supports at most {CAT_MAX_LIQUIDITY_RECIPIENTS} entries")));
        }

        let mut payload = Self::build_header(CAT_OP_CREATE_LIQUIDITY_ASSET, nonce, auth_input_index)?;
        payload.push(CAT_CURRENT_TOKEN_VERSION);
        payload.push(CAT_CURRENT_LIQUIDITY_CURVE_VERSION);
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

    fn validate_liquidity_create_parameters(decimals: u8, max_supply: u128, seed_reserve_sompi: u64) -> Result<()> {
        if decimals != LIQUIDITY_TOKEN_DECIMALS {
            return Err(Error::custom(format!("liquidity token decimals must be {LIQUIDITY_TOKEN_DECIMALS}")));
        }
        if !(MIN_LIQUIDITY_TOKEN_SUPPLY_RAW..=MAX_LIQUIDITY_TOKEN_SUPPLY_RAW).contains(&max_supply) {
            return Err(Error::custom(format!(
                "maxSupplyRaw for liquidity tokens must be between {MIN_LIQUIDITY_TOKEN_SUPPLY_RAW} and {MAX_LIQUIDITY_TOKEN_SUPPLY_RAW}"
            )));
        }
        if seed_reserve_sompi != MIN_LIQUIDITY_SEED_RESERVE_SOMPI {
            return Err(Error::custom(format!("seedReserveSompi must be exactly {MIN_LIQUIDITY_SEED_RESERVE_SOMPI} (1 CPAY)")));
        }
        Ok(())
    }

    fn initial_liquidity_virtual_token_reserves(max_supply: u128) -> Result<u128> {
        if !(MIN_LIQUIDITY_TOKEN_SUPPLY_RAW..=MAX_LIQUIDITY_TOKEN_SUPPLY_RAW).contains(&max_supply) {
            return Err(Error::custom(format!(
                "maxSupplyRaw for liquidity tokens must be between {MIN_LIQUIDITY_TOKEN_SUPPLY_RAW} and {MAX_LIQUIDITY_TOKEN_SUPPLY_RAW}"
            )));
        }
        max_supply
            .checked_mul(6)
            .and_then(|value| value.checked_div(5))
            .ok_or_else(|| Error::custom("liquidity virtual token reserve overflow"))
    }

    fn liquidity_trade_fee(amount: u64, fee_bps: u16) -> Result<u64> {
        let fee = u128::from(amount)
            .checked_mul(u128::from(fee_bps))
            .ok_or_else(|| Error::custom("liquidity fee multiplication overflow"))?
            / 10_000u128;
        u64::try_from(fee).map_err(|_| Error::custom("liquidity fee does not fit into u64"))
    }

    fn ceil_div_u128(numerator: u128, denominator: u128) -> Result<u128> {
        if denominator == 0 {
            return Err(Error::custom("division by zero"));
        }
        let quotient = numerator / denominator;
        let remainder = numerator % denominator;
        Ok(if remainder == 0 { quotient } else { quotient + 1 })
    }

    fn quote_liquidity_buy_token_out(
        real_token_reserves: u128,
        virtual_cpay_reserves_sompi: u64,
        virtual_token_reserves: u128,
        gross_in_sompi: u64,
        fee_bps: u16,
    ) -> Result<u128> {
        let fee = Self::liquidity_trade_fee(gross_in_sompi, fee_bps)?;
        let net_in = gross_in_sompi.checked_sub(fee).ok_or_else(|| Error::custom("liquidity buy fee underflow"))?;
        if net_in == 0 || real_token_reserves <= MIN_LIQUIDITY_REAL_TOKEN_RESERVE_RAW {
            return Err(Error::custom("liquidity buy produces zero output"));
        }
        let x_before = u128::from(virtual_cpay_reserves_sompi);
        let x_after = x_before.checked_add(u128::from(net_in)).ok_or_else(|| Error::custom("liquidity buy x_after overflow"))?;
        let k = x_before.checked_mul(virtual_token_reserves).ok_or_else(|| Error::custom("liquidity buy invariant overflow"))?;
        let y_after = Self::ceil_div_u128(k, x_after)?;
        let token_out =
            virtual_token_reserves.checked_sub(y_after).ok_or_else(|| Error::custom("liquidity buy token_out underflow"))?;
        if token_out == 0 || token_out > real_token_reserves.saturating_sub(MIN_LIQUIDITY_REAL_TOKEN_RESERVE_RAW) {
            return Err(Error::custom("liquidity buy produces zero output"));
        }
        Ok(token_out)
    }

    fn quote_initial_liquidity_buy_token_out(max_supply: u128, gross_in_sompi: u64, fee_bps: u16) -> Result<u128> {
        Self::quote_liquidity_buy_token_out(
            max_supply,
            INITIAL_VIRTUAL_CPAY_RESERVES_SOMPI,
            Self::initial_liquidity_virtual_token_reserves(max_supply)?,
            gross_in_sompi,
            fee_bps,
        )
    }

    fn min_liquidity_gross_input_for_net_input(net_in_sompi: u64, fee_bps: u16) -> Result<u64> {
        if net_in_sompi == 0 || fee_bps >= 10_000 {
            return Err(Error::custom("invalid liquidity net input or feeBps"));
        }
        if fee_bps == 0 {
            return Ok(net_in_sompi);
        }
        let fee_denominator =
            10_000u128.checked_sub(u128::from(fee_bps)).ok_or_else(|| Error::custom("liquidity fee denominator underflow"))?;
        let gross = (u128::from(net_in_sompi).checked_sub(1).ok_or_else(|| Error::custom("liquidity net input underflow"))?)
            .checked_mul(10_000u128)
            .ok_or_else(|| Error::custom("liquidity gross input overflow"))?
            .checked_div(fee_denominator)
            .ok_or_else(|| Error::custom("liquidity fee denominator is zero"))?
            .checked_add(1)
            .ok_or_else(|| Error::custom("liquidity gross input overflow"))?;
        u64::try_from(gross).map_err(|_| Error::custom("liquidity gross input does not fit into u64"))
    }

    fn min_liquidity_gross_input_for_token_out(
        real_token_reserves: u128,
        virtual_cpay_reserves_sompi: u64,
        virtual_token_reserves: u128,
        token_out: u128,
        fee_bps: u16,
    ) -> Result<u64> {
        if token_out == 0 || token_out > real_token_reserves.saturating_sub(MIN_LIQUIDITY_REAL_TOKEN_RESERVE_RAW) {
            return Err(Error::custom("invalid liquidity token_out"));
        }
        let y_after = virtual_token_reserves.checked_sub(token_out).ok_or_else(|| Error::custom("liquidity y_after underflow"))?;
        if y_after == 0 {
            return Err(Error::custom("liquidity y_after cannot be zero"));
        }
        let x_before = u128::from(virtual_cpay_reserves_sompi);
        let k = x_before.checked_mul(virtual_token_reserves).ok_or_else(|| Error::custom("liquidity invariant overflow"))?;
        let x_after = Self::ceil_div_u128(k, y_after)?;
        if x_after <= x_before {
            return Err(Error::custom("liquidity buy produces zero input"));
        }
        let net_in = u64::try_from(x_after - x_before).map_err(|_| Error::custom("liquidity net input does not fit into u64"))?;
        Self::min_liquidity_gross_input_for_net_input(net_in, fee_bps)
    }

    fn build_buy_liquidity_payload(
        asset_id: &str,
        expected_pool_nonce: u64,
        cpay_in_sompi: u64,
        min_token_out: u128,
        nonce: u64,
        auth_input_index: u16,
    ) -> Result<Vec<u8>> {
        let asset_id = Self::parse_hex_32(asset_id, "assetId")?;
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
    ) -> Result<Vec<u8>> {
        let asset_id = Self::parse_hex_32(asset_id, "assetId")?;
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
    ) -> Result<Vec<u8>> {
        let asset_id = Self::parse_hex_32(asset_id, "assetId")?;
        let mut payload = Self::build_header(CAT_OP_CLAIM_LIQUIDITY_FEES, nonce, auth_input_index)?;
        payload.extend_from_slice(&asset_id);
        payload.extend_from_slice(&expected_pool_nonce.to_le_bytes());
        payload.push(recipient_index);
        payload.extend_from_slice(&claim_amount_sompi.to_le_bytes());
        payload.extend_from_slice(&claim_receive_output_index.to_le_bytes());
        Ok(payload)
    }

    async fn display_help(self: Arc<Self>, ctx: Arc<CryptixCli>, _argv: Vec<String>) -> Result<()> {
        tprintln!(ctx, "Token operations:");
        tprintln!(ctx, "  send <assetId> <toAddress> <amountRaw> [senderAddress]");
        tprintln!(ctx, "    Send CAT tokens from an optional specific sender address.");
        tprintln!(ctx, "  mint <assetId> <toAddress> <amountRaw> [senderAddress]");
        tprintln!(ctx, "    Mint CAT tokens to an address (sender must be mint authority).");
        tprintln!(ctx, "  burn <assetId> <amountRaw> [senderAddress]");
        tprintln!(ctx, "    Burn CAT tokens from sender authority.");
        tprintln!(
            ctx,
            "  create <name> <symbol> <decimals> <uncapped|capped> <maxSupplyRaw> [--sender=<address>] [--mint-authority=<address>] [--metadata-hex=<hex>] [--platform-tag=<tag>]"
        );
        tprintln!(ctx, "    Create CAT token (no initial mint). Asset id equals create txid.");
        tprintln!(
            ctx,
            "  create-mint <name> <symbol> <decimals> <uncapped|capped> <maxSupplyRaw> <initialMintAmountRaw> <initialMintToAddress> [--sender=<address>] [--mint-authority=<address>] [--metadata-hex=<hex>] [--platform-tag=<tag>]"
        );
        tprintln!(ctx, "    Create CAT token and mint in same operation. Asset id equals create txid.");
        tprintln!(
            ctx,
            "  create-liquidity <name> <symbol> <decimals> <maxSupplyRaw> <seedReserveSompi> <feeBps> [recipientAddress[,recipientAddress2]] [--launch-buy-sompi=<sompi>] [--launch-buy-min-token-out=<amountRaw>] [--sender=<address>] [--metadata-hex=<hex>] [--platform-tag=<tag>] [--liquidity-unlock-target-sompi=<sompi>]"
        );
        tprintln!(ctx, "    Create CAT liquidity asset (vault value = seedReserveSompi + launchBuySompi).");
        tprintln!(ctx, "  buy-liquidity <assetId> <cpayInSompi> <minTokenOutRaw> [senderAddress]");
        tprintln!(ctx, "    Buy liquidity tokens with exact CPAY input using the current vault UTXO.");
        tprintln!(ctx, "  sell-liquidity <assetId> <tokenInRaw> <minCpayOutSompi> [senderAddress]");
        tprintln!(ctx, "    Sell exact liquidity-token input and receive CPAY payout.");
        tprintln!(ctx, "  claim-liquidity <assetId> <recipientIndex> <claimAmountSompi> [senderAddress]");
        tprintln!(ctx, "    Claim accrued liquidity fees for a configured fee recipient.");
        tprintln!(ctx, "  balances <address> [address2 ...] [--assets=<assetId,assetId2>]");
        tprintln!(ctx, "    Query one-shot token balances across multiple addresses, optionally filtered by asset ids.");
        tprintln!(ctx, "  monitor <address> [address2 ...] [--assets=<assetId,assetId2>] [--interval=<seconds>] [--watch]");
        tprintln!(
            ctx,
            "    Poll token balances and highlight incoming deltas. Use `--watch` for continuous loop mode; wallet daemon startup is `--start-daemon`."
        );
        tprintln!(ctx);
        Ok(())
    }
}
