use cryptix_cli_lib::{cryptix_cli, TerminalOptions};

#[tokio::main]
async fn main() {
    let result = cryptix_cli(TerminalOptions::new().with_prompt("$ "), None).await;
    if let Err(err) = result {
        println!("{err}");
    }
}
