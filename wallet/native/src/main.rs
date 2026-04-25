mod daemon;

use cryptix_cli_lib::{cryptix_cli, cryptix_cli_command, TerminalOptions};

#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if daemon::handles_command(args.first().map(String::as_str)) {
        daemon::run_with_args(args).await.map_err(Into::into)
    } else if !args.is_empty() {
        cryptix_cli_command(TerminalOptions::new().with_prompt("$ "), None, args).await
    } else {
        cryptix_cli(TerminalOptions::new().with_prompt("$ "), None).await
    };

    if let Err(err) = result {
        println!("{err}");
    }
}
