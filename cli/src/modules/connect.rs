use crate::imports::*;

const DEFAULT_PUBLIC_BORSH_ENDPOINT: &str = "45.145.225.141:19301";

#[derive(Default, Handler)]
#[help("Connect to a Cryptix network")]
pub struct Connect;

impl Connect {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;
        if let Some(wrpc_client) = ctx.wallet().try_wrpc_client().as_ref() {
            let network_id = ctx.wallet().network_id()?;

            let arg_or_server_address = argv.first().cloned().or_else(|| ctx.wallet().settings().get(WalletSettings::Server));
            let (is_default_seed, url) = match arg_or_server_address.as_deref() {
                Some("public") => {
                    let url = wrpc_client
                        .parse_url_with_network_type(DEFAULT_PUBLIC_BORSH_ENDPOINT.to_string(), network_id.into())
                        .map_err(|e| e.to_string())?;
                    tprintln!(ctx, "Connecting to default public seed: {url}");
                    (true, url)
                }
                None => {
                    let url = wrpc_client
                        .parse_url_with_network_type(DEFAULT_PUBLIC_BORSH_ENDPOINT.to_string(), network_id.into())
                        .map_err(|e| e.to_string())?;
                    tprintln!(ctx, "No server set, connecting to default public seed: {url}");
                    (true, url)
                }
                Some(url) => {
                    (false, wrpc_client.parse_url_with_network_type(url.to_string(), network_id.into()).map_err(|e| e.to_string())?)
                }
            };

            if is_default_seed {
                static WARNING: AtomicBool = AtomicBool::new(false);
                if !WARNING.load(Ordering::Relaxed) {
                    WARNING.store(true, Ordering::Relaxed);

                    tprintln!(ctx);

                    tpara!(
                        ctx,
                        "Please note that public node infrastructure is operated by contributors and \
                        accessing it may expose your IP address to different node providers. \
                        Consider running your own node for better privacy. \
                        ",
                    );
                    tprintln!(ctx);
                    tpara!(ctx, "Please do not connect to public nodes directly as they are load-balanced.");
                    tprintln!(ctx);
                }
            }

            let options = ConnectOptions {
                block_async_connect: true,
                strategy: ConnectStrategy::Fallback,
                url: Some(url.clone()),
                ..Default::default()
            };
            wrpc_client.connect(Some(options)).await.map_err(|e| format!("Unable to connect to {url}: {e}"))?;
        } else {
            terrorln!(ctx, "Unable to connect with non-wRPC client");
        }
        Ok(())
    }
}
