use crate::helpers::{try_convert_option_to_token_address, option_string_to_display, ask_convert_address};
use crate::imports::*;
use std::sync::{Arc, Mutex};

pub async fn secure_token_transfer(
    ctx: Arc<CryptixCli>,
    instance_id: String,
    from_hash: [u8; 32],
    to_hash: [u8; 32],
    amount: u64,
    action_id: u16,
    fee: Option<i64>,
    from_address: Option<String>,
    to_address: Option<String>,
    amount_display: String,
) -> Result<()> {
    // Check if wallet is open
    let wallet = ctx.wallet();
    if !wallet.is_open() {
        return Err("Wallet must be open to transfer tokens securely".into());
    }

    // Get the account
    let account = ctx.account().await?;
    
    // Ask for wallet secret
    let abortable = Abortable::default();
    let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;
    
    // Prepare token data
    let mut token_data = Vec::new();
    token_data.extend_from_slice(&from_hash);
    token_data.extend_from_slice(&to_hash);
    token_data.extend_from_slice(&amount.to_le_bytes());
    
    // Create a token transfer payload using the proper format with magic bytes "CX\x01"
    // followed by CBOR-encoded contract payload
    let contract_payload = cryptix_consensus_core::contract::ContractPayload {
        v: 1,
        c: instance_id.parse::<u64>().unwrap_or_else(|_| {
            // If instance_id contains a colon (txid:vout format), extract the contract ID
            if let Some(contract_id_str) = instance_id.split(':').next() {
                contract_id_str.parse::<u64>().unwrap_or(0)
            } else {
                0 // Default to 0 if parsing fails
            }
        }),
        a: action_id as u64,
        d: token_data,
    };
    let payload = contract_payload.encode().expect("Failed to encode contract payload");
    
    // Clone the context for use in the notifier
    let ctx_clone = ctx.clone();
    
    // Create a vector to collect transaction IDs during processing
    let tx_ids_during_processing = Arc::new(Mutex::new(Vec::new()));
    let tx_ids_for_notifier = tx_ids_during_processing.clone();
    
    // Use the wallet's send method to create and sign the transaction
    let priority_fee_sompi = fee.unwrap_or(0);
    
    tprintln!(ctx, "Signing and sending token transfer transaction...");
    
    // Send to a dummy address with minimal amount, the real work is in the payload
    let dummy_address = account.receive_address()?; // Use own address as dummy
    let minimal_amount = 100_000_000; // 1 CPAY to avoid storage mass issues
    let outputs = PaymentOutputs::from((dummy_address.clone(), minimal_amount));
    
    let (summary, tx_ids) = account
        .send(
            outputs.into(),
            priority_fee_sompi.into(),
            Some(payload),
            wallet_secret,
            payment_secret,
            &abortable,
            Some(Arc::new(move |ptx| {
                let id = ptx.id();
                tprintln!(ctx_clone, "Processing transaction: {}", id);
                tx_ids_for_notifier.lock().unwrap().push(id);
            })),
        )
        .await?;

    tprintln!(ctx, "Token transfer - {summary}");
    tprintln!(ctx, "\nTransferring tokens with secure transaction, tx ids:");
    
    // Display the transaction IDs
    let ids_during_processing = tx_ids_during_processing.lock().unwrap();
    if !ids_during_processing.is_empty() {
        for id in ids_during_processing.iter() {
            tprintln!(ctx, "  {}", id);
        }
    } else if !tx_ids.is_empty() {
        for tx_id in tx_ids.iter() {
            tprintln!(ctx, "  {}", tx_id);
        }
    } else {
        tprintln!(ctx, "  No transaction IDs available to display");
    }
    
    tprintln!(ctx, "\nToken transfer details:");
    tprintln!(ctx, "  From: {}", from_address.unwrap_or_else(|| "Default account".to_string()));
    tprintln!(ctx, "  To: {}", to_address.unwrap_or_else(|| "Unknown".to_string()));
    tprintln!(ctx, "  Amount: {}", amount_display);
    tprintln!(ctx, "  Instance ID: {}", instance_id);
    tprintln!(ctx, "\nNote: The token transfer transaction has been securely signed with your wallet's private key.");

    Ok(())
}
