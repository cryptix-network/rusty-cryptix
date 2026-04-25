use crate::imports::*;

#[derive(Default, Handler)]
#[help("Reduces account UTXO size by re-sending all funds to the account's default address")]
pub struct Sweep;

impl Sweep {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, _argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        let account = ctx.wallet().account()?;
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;
        let abortable = Abortable::default();
        // let ctx_ = ctx.clone();
        let (summary, ids) = account
            .sweep(
                wallet_secret,
                payment_secret,
                &abortable,
                Some(Arc::new(move |_ptx| {
                    // tprintln!(ctx_, "Sending transaction: {}", ptx.id());
                })),
            )
            .await?;

        tprintln!(ctx, "Sweep: {summary}");
        tprintln!(ctx, "tx ids:");
        if ids.is_empty() {
            tprintln!(ctx, "  (none)");
        } else {
            for id in ids {
                tprintln!(ctx, "  {id}");
            }
        }
        tprintln!(ctx);

        Ok(())
    }
}
