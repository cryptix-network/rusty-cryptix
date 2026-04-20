use crate::imports::*;
use cryptix_wallet_core::account::GenerationNotifier;

#[derive(Default, Handler)]
#[help("Transfer funds between wallet accounts")]
pub struct Transfer;

impl Transfer {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        let account = ctx.wallet().account()?;

        if argv.len() < 2 {
            tprintln!(ctx, "usage: transfer <account> <amount> <priority fee> [senderAddress] [payloadHex]");
            return Ok(());
        }

        let target_account = argv.first().unwrap();
        let target_account = ctx.find_accounts_by_name_or_id(target_account).await?;
        if target_account.id() == account.id() {
            return Err("Cannot transfer to the same account".into());
        }
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
        let target_address = target_account.receive_address()?;
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;

        let abortable = Abortable::default();
        let outputs = PaymentOutputs::from((target_address.clone(), amount_sompi));

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

        tprintln!(ctx, "Transfer - {summary}");

        Ok(())
    }
}
