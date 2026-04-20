use crate::imports::*;
use cryptix_wallet_core::account::GenerationNotifier;

#[derive(Default, Handler)]
#[help("Send a Cryptix transaction to a public address")]
pub struct Send;

impl Send {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        // address, amount, priority fee
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        let account = ctx.wallet().account()?;

        if argv.len() < 2 {
            tprintln!(ctx, "usage: send <address> <amount> <priority fee> [senderAddress] [payloadHex]");
            return Ok(());
        }

        let address = Address::try_from(argv.first().unwrap().as_str())?;
        let amount_sompi = try_parse_required_nonzero_cryptix_as_sompi_u64(argv.get(1))?;
        let priority_fee_sompi = try_parse_optional_cryptix_as_sompi_i64(argv.get(2))?.unwrap_or(0);
        let sender_address = argv.get(3).map(|value| Address::try_from(value.as_str())).transpose()?;
        let payload = argv
            .get(4)
            .map(|value| {
                let normalized = value.strip_prefix("0x").unwrap_or(value.as_str());
                hex::decode(normalized)
                    .map_err(|err| Error::Custom(format!("payloadHex must be valid hex (optional 0x prefix is allowed): {err}")))
            })
            .transpose()?;
        let outputs = PaymentOutputs::from((address.clone(), amount_sompi));
        let abortable = Abortable::default();
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;

        // let ctx_ = ctx.clone();
        let notifier: GenerationNotifier = Arc::new(move |_ptx| {
            // tprintln!(ctx_, "Sending transaction: {}", ptx.id());
        });
        let (summary, _ids, _fast_summary) = account
            .send(
                outputs.into(),
                priority_fee_sompi.into(),
                payload,
                sender_address,
                None,
                wallet_secret,
                payment_secret,
                &abortable,
                Some(notifier),
            )
            .await?;

        tprintln!(ctx, "Send - {summary}");
        tprintln!(ctx, "\nSending {} CPAY to {address}, tx ids:", sompi_to_cryptix_string(amount_sompi));
        // tprintln!(ctx, "{}\n", ids.into_iter().map(|a| a.to_string()).collect::<Vec<_>>().join("\n"));

        Ok(())
    }
}
