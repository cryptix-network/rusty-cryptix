use cryptix_cli_lib::cryptix_cli;
use wasm_bindgen::prelude::*;
use workflow_terminal::Options;
use workflow_terminal::Result;

#[wasm_bindgen]
pub async fn load_cryptix_wallet_cli() -> Result<()> {
    let options = Options { ..Options::default() };
    cryptix_cli(options, None).await?;
    Ok(())
}
