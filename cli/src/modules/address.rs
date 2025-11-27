use crate::imports::*;
use cryptix_addresses::Address as CryptixAddress;

#[derive(Default, Handler)]
#[help("Show or generate a new address for the current wallet account")]
pub struct Address;

impl Address {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        if argv.is_empty() {
            let address = ctx.account().await?.receive_address()?.to_string();
            tprintln!(ctx, "\n{address}\n");
        } else {
            let op = argv.first().unwrap();
            match op.as_str() {
                "new" => {
                    let account = ctx.wallet().account()?.as_derivation_capable()?;
                    let ident = account.name_with_id();
                    let new_address = account.new_receive_address().await?;
                    tprintln!(ctx, "Generating new address for account {}", style(ident).cyan());
                    tprintln!(ctx, "{}", style(new_address).blue());
                }
                "token" => {
                    // Get the address to convert (either from argument or current account)
                    let address_str = if argv.len() > 1 {
                        argv[1].clone()
                    } else {
                        ctx.account().await?.receive_address()?.to_string()
                    };
                    
                    self.show_token_address(ctx, &address_str).await?;
                }
                v => {
                    tprintln!(ctx, "unknown command: '{v}'\r\n");
                    return self.display_help(ctx, argv).await;
                }
            }
        }

        Ok(())
    }

    async fn show_token_address(self: Arc<Self>, ctx: Arc<CryptixCli>, address_str: &str) -> Result<()> {
        // Parse the address
        let address = CryptixAddress::try_from(address_str)
            .map_err(|e| Error::Custom(format!("Invalid address format: {}", e)))?;
        
        // Extract the payload (public key hash) from the address
        let payload = address.payload.as_slice();
        
        // Convert to hex string
        let token_address = hex::encode(payload);
        
        tprintln!(ctx, "\nWallet Address:");
        tprintln!(ctx, "  {}", style(address_str).blue());
        tprintln!(ctx, "\nToken Address (32-byte hex for contracts):");
        tprintln!(ctx, "  {}", style(&token_address).green());
        tprintln!(ctx, "\nUse this token address for:");
        tprintln!(ctx, "  - Deploying token contracts (--admin parameter)");
        tprintln!(ctx, "  - Checking token balances (--address parameter)");
        tprintln!(ctx, "  - Sending tokens (--from/--to parameters)");
        tprintln!(ctx, "");
        
        Ok(())
    }

    async fn display_help(self: Arc<Self>, ctx: Arc<CryptixCli>, _argv: Vec<String>) -> Result<()> {
        ctx.term().help(
            &[
                ("address", "Show current account address"),
                ("address new", "Generate a new account address"),
                ("address token [address]", "Convert wallet address to token address (32-byte hex format)"),
            ],
            None,
        )?;

        Ok(())
    }
}
