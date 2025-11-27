use crate::imports::*;

#[derive(Default, Handler)]
#[help("Manage smart contracts")]
pub struct Contract;

impl Contract {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<CryptixCli>()?;

        if argv.is_empty() {
            return self.print_help(ctx).await;
        }

        match argv[0].as_str() {
            "deploy" => self.deploy(ctx, argv[1..].to_vec()).await,
            "call" => self.call(ctx, argv[1..].to_vec()).await,
            "state" => self.state(ctx, argv[1..].to_vec()).await,
            "list" => self.list(ctx, argv[1..].to_vec()).await,
            "simulate" => self.simulate(ctx, argv[1..].to_vec()).await,
            _ => {
                tprintln!(ctx, "Unknown contract command: {}", argv[0]);
                self.print_help(ctx).await
            }
        }
    }

    async fn print_help(self: Arc<Self>, ctx: Arc<CryptixCli>) -> Result<()> {
        tprintln!(ctx, "Contract Commands:");
        tprintln!(ctx, "  deploy --contract <id> --data <file> [--fee <amount>]");
        tprintln!(ctx, "  call --instance <id> --action <id> [--data <file>]");
        tprintln!(ctx, "  state --instance <id>");
        tprintln!(ctx, "  list");
        tprintln!(ctx, "  simulate --instance <id> --action <id> [--data <file>]");
        tprintln!(ctx, "");
        tprintln!(ctx, "Note: For token operations, use the 'token' command");
        Ok(())
    }

    async fn deploy(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut contract_id: Option<u64> = None;
        let mut data_file: Option<String> = None;
        let mut fee: Option<i64> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--contract" => {
                    if i + 1 < argv.len() {
                        contract_id = Some(argv[i + 1].parse::<u64>().map_err(|_| "Invalid contract ID")?);
                        i += 2;
                    } else {
                        return Err("Missing contract ID".into());
                    }
                }
                "--data" => {
                    if i + 1 < argv.len() {
                        data_file = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing data file".into());
                    }
                }
                "--fee" => {
                    if i + 1 < argv.len() {
                        fee = Some(try_parse_optional_cryptix_as_sompi_i64(Some(&argv[i + 1]))?.unwrap_or(0));
                        i += 2;
                    } else {
                        return Err("Missing fee amount".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let contract_id = contract_id.ok_or("Contract ID is required")?;
        
        // Read initial state from file
        let initial_state = if let Some(file) = data_file {
            std::fs::read(&file).map_err(|e| format!("Failed to read data file: {}", e))?
        } else {
            return Err("Data file is required".into());
        };

        // Deploy the contract
        let rpc = ctx.rpc_api();
        let response = rpc.deploy_contract(contract_id, initial_state).await?;

        // Check if transaction needs signing (mainnet/testnet)
        if response.needs_signing {
            if let Some(unsigned_tx) = response.unsigned_transaction {
                tprintln!(ctx, "Transaction needs wallet signing (mainnet/testnet mode)");
                tprintln!(ctx, "Signing with wallet...");
                
                // NOTE: On mainnet, the unsigned transaction needs to be signed by the wallet
                // before submission. For now, we inform the user that manual signing is required.
                tprintln!(ctx, "MAINNET/TESTNET: Transaction requires wallet signing");
                tprintln!(ctx, "");
                tprintln!(ctx, "The RPC has prepared an unsigned transaction.");
                tprintln!(ctx, "To complete the deployment, you need to:");
                tprintln!(ctx, "  1. Sign the transaction with your wallet");
                tprintln!(ctx, "  2. Submit the signed transaction using 'rpc submit-transaction'");
                tprintln!(ctx, "");
                tprintln!(ctx, "Transaction ID (unsigned): {}", response.transaction_id);
                if let Some(instance_id) = response.instance_id {
                    tprintln!(ctx, "Instance ID (will be active after signing): {}", instance_id);
                }
                tprintln!(ctx, "");
                tprintln!(ctx, "NOTE: Wallet-based signing integration is in development.");
                tprintln!(ctx, "For now, contracts work on SIMNET only.");
            } else {
                return Err("Transaction needs signing but no unsigned transaction provided".into());
            }
        } else {
            // Simnet: Transaction was auto-submitted
            tprintln!(ctx, "Contract deployed successfully (auto-submitted on simnet):");
            tprintln!(ctx, "  Transaction ID: {}", response.transaction_id);
            if let Some(instance_id) = response.instance_id {
                tprintln!(ctx, "  Instance ID: {}", instance_id);
            }
            if let Some(outpoint) = response.state_outpoint {
                tprintln!(ctx, "  State Outpoint: {}:{}", outpoint.transaction_id, outpoint.index);
            }
        }

        Ok(())
    }

    async fn call(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut instance_id: Option<String> = None;
        let mut action_id: Option<u16> = None;
        let mut data_file: Option<String> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                "--action" => {
                    if i + 1 < argv.len() {
                        action_id = Some(argv[i + 1].parse::<u16>().map_err(|_| "Invalid action ID")?);
                        i += 2;
                    } else {
                        return Err("Missing action ID".into());
                    }
                }
                "--data" => {
                    if i + 1 < argv.len() {
                        data_file = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing data file".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let instance_id = instance_id.ok_or("Instance ID is required")?;
        let action_id = action_id.ok_or("Action ID is required")?;
        
        // Read call data from file or use empty if omitted
        let data = if let Some(file) = data_file {
            std::fs::read(&file).map_err(|e| format!("Failed to read data file: {}", e))?
        } else {
            Vec::new()
        };

        // Call the contract
        let rpc = ctx.rpc_api();
        let response = rpc.submit_contract_call(instance_id, action_id, data).await?;

        tprintln!(ctx, "Contract call submitted successfully:");
        tprintln!(ctx, "  Transaction ID: {}", response.transaction_id);
        if let Some(outpoint) = response.state_outpoint {
            tprintln!(ctx, "  New State Outpoint: {}:{}", outpoint.transaction_id, outpoint.index);
        }

        Ok(())
    }

    async fn state(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut instance_id: Option<String> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let instance_id = instance_id.ok_or("Instance ID is required")?;

        // Get contract state
        let rpc = ctx.rpc_api();
        let response = rpc.get_contract_state(instance_id).await?;

        if response.has_state {
            tprintln!(ctx, "Contract state:");
            tprintln!(ctx, "  State (hex): {}", hex::encode(&response.state));
            tprintln!(ctx, "  State size: {} bytes", response.state.len());
            if let Some(outpoint) = response.state_outpoint {
                tprintln!(ctx, "  State Outpoint: {}:{}", outpoint.transaction_id, outpoint.index);
            }
        } else {
            tprintln!(ctx, "No state found for the specified instance ID");
        }

        Ok(())
    }

    async fn list(self: Arc<Self>, ctx: Arc<CryptixCli>, _argv: Vec<String>) -> Result<()> {
        // List all contracts
        let rpc = ctx.rpc_api();
        let response = rpc.list_contracts().await?;

        if response.contracts.is_empty() {
            tprintln!(ctx, "No contract instances found");
            return Ok(());
        }

        tprintln!(ctx, "Contract instances:");
        for contract in response.contracts {
            tprintln!(ctx, "  Instance ID: {}", contract.instance_id);
            tprintln!(ctx, "    Contract ID: {}", contract.contract_id);
            tprintln!(ctx, "    State Size: {} bytes", contract.state_size);
            tprintln!(ctx, "    State Hash: {}", contract.state_hash);
            tprintln!(ctx, "    State Outpoint: {}:{}", contract.state_outpoint.transaction_id, contract.state_outpoint.index);
            tprintln!(ctx, "");
        }

        Ok(())
    }

    async fn simulate(self: Arc<Self>, ctx: Arc<CryptixCli>, argv: Vec<String>) -> Result<()> {
        let mut instance_id: Option<String> = None;
        let mut action_id: Option<u16> = None;
        let mut data_file: Option<String> = None;

        let mut i = 0;
        while i < argv.len() {
            match argv[i].as_str() {
                "--instance" => {
                    if i + 1 < argv.len() {
                        instance_id = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing instance ID".into());
                    }
                }
                "--action" => {
                    if i + 1 < argv.len() {
                        action_id = Some(argv[i + 1].parse::<u16>().map_err(|_| "Invalid action ID")?);
                        i += 2;
                    } else {
                        return Err("Missing action ID".into());
                    }
                }
                "--data" => {
                    if i + 1 < argv.len() {
                        data_file = Some(argv[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("Missing data file".into());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", argv[i]).into());
                }
            }
        }

        let instance_id = instance_id.ok_or("Instance ID is required")?;
        let action_id = action_id.ok_or("Action ID is required")?;
        
        // Read call data from file or use empty if omitted
        let data = if let Some(file) = data_file {
            std::fs::read(&file).map_err(|e| format!("Failed to read data file: {}", e))?
        } else {
            Vec::new()
        };

        // Simulate the contract call
        let rpc = ctx.rpc_api();
        let response = rpc.simulate_contract_call(instance_id, action_id, data, None).await?;

        tprintln!(ctx, "Contract call simulation results:");
        if let Some(new_state) = response.new_state {
            tprintln!(ctx, "  New State (hex): {}", hex::encode(&new_state));
            tprintln!(ctx, "  New State Size: {} bytes", new_state.len());
        } else {
            tprintln!(ctx, "  No new state produced");
        }
        
        if let Some(error_code) = response.error_code {
            tprintln!(ctx, "  Error Code: {}", error_code);
        }
        
        tprintln!(ctx, "  State Size OK: {}", if response.state_size_ok { "Yes" } else { "No" });
        tprintln!(ctx, "  Would Be Valid TX: {}", if response.would_be_valid_tx { "Yes" } else { "No" });

        Ok(())
    }
}
