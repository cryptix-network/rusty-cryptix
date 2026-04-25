cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        fn main() {}
    } else {
        use cryptix_cli_lib::{cryptix_cli, cryptix_cli_command, TerminalOptions};

        #[tokio::main]
        async fn main() {
            let args = std::env::args().skip(1).collect::<Vec<_>>();
            let result = if args.is_empty() {
                cryptix_cli(TerminalOptions::new().with_prompt("$ "), None).await
            } else {
                cryptix_cli_command(TerminalOptions::new().with_prompt("$ "), None, args).await
            };

            if let Err(err) = result {
                println!("{err}");
            }
        }
    }
}
