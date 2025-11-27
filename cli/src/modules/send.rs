use crate::imports::*;

#[derive(Default, Handler)]
#[help("Send a Cryptix transaction to a public address")]
pub struct Send;

impl Send {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        // address, amount, priority fee
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        let account = ctx.wallet().account()?;

        if argv.len() < 2 {
            tprintln!(ctx, "usage: send <address> <amount> [priority fee] [--payload <hex>] [--payload-file <path>]");
            return Ok(());
        }

        let address = Address::try_from(argv.first().unwrap().as_str())?;
        let amount_sompi = try_parse_required_nonzero_cryptix_as_sompi_u64(argv.get(1))?;
        let priority_fee_sompi = try_parse_optional_cryptix_as_sompi_i64(argv.get(2))?.unwrap_or(0);

        // Parse payload options
        let mut payload: Option<Vec<u8>> = None;
        let mut i = 3; // After address, amount, priority_fee

        while i < argv.len() {
            match argv[i].as_str() {
                "--payload" => {
                    if i + 1 >= argv.len() {
                        return Err("Missing hex payload after --payload".into());
                    }
                    let hex_payload = &argv[i + 1];
                    payload = Some(hex::decode(hex_payload)
                        .map_err(|_| "Invalid hex payload format")?);
                    i += 2;
                }
                "--payload-file" => {
                    if i + 1 >= argv.len() {
                        return Err("Missing file path after --payload-file".into());
                    }
                    let file_path = &argv[i + 1];
                    let file_payload = std::fs::read(file_path)
                        .map_err(|_| "Failed to read payload file")?;
                    payload = Some(file_payload);
                    i += 2;
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        // Interactive payload input if no payload arguments provided
        if payload.is_none() {
            let term = ctx.term();
            tprintln!(ctx);
            let add_payload = term.ask(false, "Do you want to add a payload to this transaction? (y/N): ").await?;
            if matches!(add_payload.trim(), "y" | "Y" | "yes" | "YES") {
                tprintln!(ctx);
                let payload_type = term.ask(false, "Choose payload input method: (1) Hex string, (2) File path: ").await?;
                match payload_type.trim() {
                    "1" => {
                        tprintln!(ctx);
                        let hex_payload = term.ask(false, "Enter payload as hex string: ").await?;
                        payload = Some(hex::decode(hex_payload.trim())
                            .map_err(|_| "Invalid hex payload format")?);
                    }
                    "2" => {
                        tprintln!(ctx);
                        let file_path = term.ask(false, "Enter file path: ").await?;
                        let file_payload = std::fs::read(file_path.trim())
                            .map_err(|_| "Failed to read payload file")?;
                        payload = Some(file_payload);
                    }
                    _ => {
                        return Err("Invalid choice. Use '1' for hex string or '2' for file path.".into());
                    }
                }
            }
        }

        // Validate payload size (35 KB limit for non-coinbase transactions)
        if let Some(ref p) = payload {
            if p.len() > 35 * 1024 {
                return Err("Payload too large (max 35 KB)".into());
            }
        }

        let outputs = PaymentOutputs::from((address.clone(), amount_sompi));
        let abortable = Abortable::default();
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;

        // let ctx_ = ctx.clone();
        // Clone the context for use in the notifier
        let ctx_clone = ctx.clone();
        
        // Create a vector to collect transaction IDs during processing
        let tx_ids_during_processing = Arc::new(Mutex::new(Vec::new()));
        let tx_ids_for_notifier = tx_ids_during_processing.clone();
        
        let (summary, tx_ids) = account
            .send(
                outputs.into(),
                priority_fee_sompi.into(),
                payload,
                wallet_secret,
                payment_secret,
                &abortable,
                Some(Arc::new(move |ptx| {
                    // Capture transaction IDs as they're being processed
                    let id = ptx.id();
                    tprintln!(ctx_clone, "Processing transaction: {}", id);
                    tx_ids_for_notifier.lock().unwrap().push(id);
                })),
            )
            .await?;

        tprintln!(ctx, "Send - {summary}");
        tprintln!(ctx, "\nSending {} CPAY to {address}, tx ids:", sompi_to_cryptix_string(amount_sompi));
        
        // First try to display the IDs collected during processing
        let ids_during_processing = tx_ids_during_processing.lock().unwrap();
        if !ids_during_processing.is_empty() {
            for id in ids_during_processing.iter() {
                tprintln!(ctx, "{}", id);
            }
        }
        // Then try to display the IDs returned from the function
        else if !tx_ids.is_empty() {
            for tx_id in tx_ids.iter() {
                tprintln!(ctx, "{}", tx_id);
            }
        } 
        // If no IDs are available, show a message
        else {
            tprintln!(ctx, "No transaction IDs available to display");
        }
        tprintln!(ctx, "");

        Ok(())
    }
}
