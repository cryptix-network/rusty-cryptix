use crate::imports::*;

#[derive(Default, Handler)]
#[help("Create an unsigned PSKB transaction bundle")]
pub struct CreateUnsignedTx;

impl CreateUnsignedTx {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;
        let account = ctx.wallet().account()?;

        if argv.len() < 2 {
            tprintln!(ctx, "usage: create-unsigned-tx <address> <amount> [priority fee] [payloadHex]");
            return Ok(());
        }

        let address = Address::try_from(argv.first().unwrap().as_str())?;
        let amount_sompi = try_parse_required_nonzero_cryptix_as_sompi_u64(argv.get(1))?;
        let priority_fee_sompi = try_parse_optional_cryptix_as_sompi_i64(argv.get(2))?.unwrap_or(0);
        let payload = argv
            .get(3)
            .map(|value| {
                let normalized = value.strip_prefix("0x").unwrap_or(value.as_str());
                hex::decode(normalized)
                    .map_err(|err| Error::Custom(format!("payloadHex must be valid hex (optional 0x prefix is allowed): {err}")))
            })
            .transpose()?;

        let outputs = PaymentOutputs::from((address, amount_sompi));
        let abortable = Abortable::default();
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;
        let bundle = account
            .pskb_from_send_generator(outputs.into(), priority_fee_sompi.into(), payload, wallet_secret, payment_secret, &abortable)
            .await?;
        let encoded = bundle.serialize()?;
        tprintln!(ctx, "{encoded}");
        Ok(())
    }
}
