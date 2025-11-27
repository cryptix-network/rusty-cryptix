use crate::prelude::{RpcHash};
use crate::model::{RpcTransactionId, RpcTransaction};
use crate::model::tx::RpcTransactionOutpoint;
use serde::{Serialize, Deserialize};
use workflow_serializer::prelude::*;

/// Request to deploy a contract (a == 0) with initial state `initial_state` for contract id `contract_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployContractRequest {
    pub contract_id: u64,
    #[serde(with = "hex::serde")]
    pub initial_state: Vec<u8>,
}

impl Serializer for DeployContractRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(u64, &self.contract_id, writer)?;
        store!(Vec<u8>, &self.initial_state, writer)?;
        Ok(())
    }
}

impl Deserializer for DeployContractRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let contract_id = load!(u64, reader)?;
        let initial_state = load!(Vec<u8>, reader)?;
        Ok(Self { contract_id, initial_state })
    }
}

/// Response for deployContract: returns created transaction id and optional state outpoint if known.
/// On mainnet/testnet, may return an unsigned transaction that needs wallet signing before submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployContractResponse {
    pub transaction_id: RpcTransactionId,
    pub state_outpoint: Option<RpcTransactionOutpoint>,
    // New: explicit instance id "<txid>:<vout>" if known
    pub instance_id: Option<String>,
    // Indicates if the transaction needs signing before submission
    pub needs_signing: bool,
    // The unsigned transaction (if needs_signing is true)
    pub unsigned_transaction: Option<RpcTransaction>,
}

impl Serializer for DeployContractResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &2, writer)?; // Version 2 to support new fields
        store!(RpcTransactionId, &self.transaction_id, writer)?;
        serialize!(Option<RpcTransactionOutpoint>, &self.state_outpoint, writer)?;
        serialize!(Option<String>, &self.instance_id, writer)?;
        store!(bool, &self.needs_signing, writer)?;
        serialize!(Option<RpcTransaction>, &self.unsigned_transaction, writer)?;
        Ok(())
    }
}

impl Deserializer for DeployContractResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let version = load!(u8, reader)?;
        let transaction_id = load!(RpcTransactionId, reader)?;
        let state_outpoint = deserialize!(Option<RpcTransactionOutpoint>, reader)?;
        let instance_id = deserialize!(Option<String>, reader)?;
        
        // Handle backward compatibility
        let (needs_signing, unsigned_transaction) = if version >= 2 {
            let needs_signing = load!(bool, reader)?;
            let unsigned_transaction = deserialize!(Option<RpcTransaction>, reader)?;
            (needs_signing, unsigned_transaction)
        } else {
            (false, None)
        };
        
        Ok(Self { transaction_id, state_outpoint, instance_id, needs_signing, unsigned_transaction })
    }
}

/// Request to execute a contract call (a > 0).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitContractCallRequest {
    // Instance id string "<txid>:<vout>"
    pub instance_id: String,
    pub action_id: u16,
    #[serde(with = "hex::serde")]
    pub data: Vec<u8>,
}

impl Serializer for SubmitContractCallRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(String, &self.instance_id, writer)?;
        store!(u16, &self.action_id, writer)?;
        store!(Vec<u8>, &self.data, writer)?;
        Ok(())
    }
}

impl Deserializer for SubmitContractCallRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let instance_id = load!(String, reader)?;
        let action_id = load!(u16, reader)?;
        let data = load!(Vec<u8>, reader)?;
        Ok(Self { instance_id, action_id, data })
    }
}

/// Response for submitContractCall: returns tx id and new state outpoint if known.
/// On mainnet/testnet, may return an unsigned transaction that needs wallet signing before submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitContractCallResponse {
    pub transaction_id: RpcTransactionId,
    pub state_outpoint: Option<RpcTransactionOutpoint>,
    // Indicates if the transaction needs signing before submission
    pub needs_signing: bool,
    // The unsigned transaction (if needs_signing is true)
    pub unsigned_transaction: Option<RpcTransaction>,
}

impl Serializer for SubmitContractCallResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &2, writer)?; // Version 2 to support new fields
        store!(RpcTransactionId, &self.transaction_id, writer)?;
        serialize!(Option<RpcTransactionOutpoint>, &self.state_outpoint, writer)?;
        store!(bool, &self.needs_signing, writer)?;
        serialize!(Option<RpcTransaction>, &self.unsigned_transaction, writer)?;
        Ok(())
    }
}

impl Deserializer for SubmitContractCallResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let version = load!(u8, reader)?;
        let transaction_id = load!(RpcTransactionId, reader)?;
        let state_outpoint = deserialize!(Option<RpcTransactionOutpoint>, reader)?;
        
        // Handle backward compatibility
        let (needs_signing, unsigned_transaction) = if version >= 2 {
            let needs_signing = load!(bool, reader)?;
            let unsigned_transaction = deserialize!(Option<RpcTransaction>, reader)?;
            (needs_signing, unsigned_transaction)
        } else {
            (false, None)
        };
        
        Ok(Self { transaction_id, state_outpoint, needs_signing, unsigned_transaction })
    }
}

/// Request to fetch current contract state by contract id.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetContractStateRequest {
    // Instance id string "<txid>:<vout>"
    pub instance_id: String,
}

impl Serializer for GetContractStateRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(String, &self.instance_id, writer)?;
        Ok(())
    }
}

impl Deserializer for GetContractStateRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let instance_id = load!(String, reader)?;
        Ok(Self { instance_id })
    }
}

/// Response for getContractState: has_state indicates presence; state and outpoint returned if found.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetContractStateResponse {
    pub has_state: bool,
    #[serde(with = "hex::serde")]
    pub state: Vec<u8>,
    pub state_outpoint: Option<RpcTransactionOutpoint>,
}

impl Serializer for GetContractStateResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(bool, &self.has_state, writer)?;
        store!(Vec<u8>, &self.state, writer)?;
        serialize!(Option<RpcTransactionOutpoint>, &self.state_outpoint, writer)?;
        Ok(())
    }
}

impl Deserializer for GetContractStateResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let has_state = load!(bool, reader)?;
        let state = load!(Vec<u8>, reader)?;
        let state_outpoint = deserialize!(Option<RpcTransactionOutpoint>, reader)?;
        Ok(Self { has_state, state, state_outpoint })
    }
}

/// Request for listing all contract states present in the UTXO set.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContractsRequest {}

impl Serializer for ListContractsRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        Ok(())
    }
}

impl Deserializer for ListContractsRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        Ok(Self {})
    }
}

/// Single contract state entry summary for listContracts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcContractStateEntry {
    pub contract_id: u64,
    pub state_size: u32,
    pub state_hash: RpcHash,
    pub state_outpoint: RpcTransactionOutpoint,
    // Instance id string "<txid>:<vout>"
    pub instance_id: String,
}

impl Serializer for RpcContractStateEntry {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(u64, &self.contract_id, writer)?;
        store!(u32, &self.state_size, writer)?;
        store!(RpcHash, &self.state_hash, writer)?;
        serialize!(RpcTransactionOutpoint, &self.state_outpoint, writer)?;
        store!(String, &self.instance_id, writer)?;
        Ok(())
    }
}

impl Deserializer for RpcContractStateEntry {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let contract_id = load!(u64, reader)?;
        let state_size = load!(u32, reader)?;
        let state_hash = load!(RpcHash, reader)?;
        let state_outpoint = deserialize!(RpcTransactionOutpoint, reader)?;
        let instance_id = load!(String, reader)?;
        Ok(Self { contract_id, state_size, state_hash, state_outpoint, instance_id })
    }
}

/// Response for listContracts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContractsResponse {
    pub contracts: Vec<RpcContractStateEntry>,
}

impl Serializer for ListContractsResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        serialize!(Vec<RpcContractStateEntry>, &self.contracts, writer)?;
        Ok(())
    }
}

impl Deserializer for ListContractsResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let contracts = deserialize!(Vec<RpcContractStateEntry>, reader)?;
        Ok(Self { contracts })
    }
}

/// Request to simulate a contract call off-chain (no TX).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateContractCallRequest {
    // Instance id string "<txid>:<vout>"
    pub instance_id: String,
    pub action_id: u16,
    #[serde(with = "hex::serde")]
    pub data: Vec<u8>,
    pub hypothetical_state: Option<Vec<u8>>,
}

impl Serializer for SimulateContractCallRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(String, &self.instance_id, writer)?;
        store!(u16, &self.action_id, writer)?;
        store!(Vec<u8>, &self.data, writer)?;
        // Option<Vec<u8>> manual encoding (presence byte + data)
        match &self.hypothetical_state {
            Some(v) => {
                store!(u8, &1, writer)?;
                store!(Vec<u8>, v, writer)?;
            }
            None => {
                store!(u8, &0, writer)?;
            }
        }
        Ok(())
    }
}

impl Deserializer for SimulateContractCallRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        let instance_id = load!(String, reader)?;
        let action_id = load!(u16, reader)?;
        let data = load!(Vec<u8>, reader)?;
        // Option<Vec<u8>> manual decoding
        let hypothetical_state = {
            let present = load!(u8, reader)?;
            if present != 0 {
                Some(load!(Vec<u8>, reader)?)
            } else {
                None
            }
        };
        Ok(Self { instance_id, action_id, data, hypothetical_state })
    }
}

/// Response for simulateContractCall.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateContractCallResponse {
    pub new_state: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub state_size_ok: bool,
    pub would_be_valid_tx: bool,
}

impl Serializer for SimulateContractCallResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        // Option<Vec<u8>> new_state
        match &self.new_state {
            Some(v) => {
                store!(u8, &1, writer)?;
                store!(Vec<u8>, v, writer)?;
            }
            None => {
                store!(u8, &0, writer)?;
            }
        }
        // Option<u32> error_code
        match &self.error_code {
            Some(v) => {
                store!(u8, &1, writer)?;
                store!(u32, v, writer)?;
            }
            None => {
                store!(u8, &0, writer)?;
            }
        }
        store!(bool, &self.state_size_ok, writer)?;
        store!(bool, &self.would_be_valid_tx, writer)?;
        Ok(())
    }
}

impl Deserializer for SimulateContractCallResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _v = load!(u8, reader)?;
        // Option<Vec<u8>> new_state
        let new_state = {
            let present = load!(u8, reader)?;
            if present != 0 {
                Some(load!(Vec<u8>, reader)?)
            } else {
                None
            }
        };
        // Option<u32> error_code
        let error_code = {
            let present = load!(u8, reader)?;
            if present != 0 {
                Some(load!(u32, reader)?)
            } else {
                None
            }
        };
        let state_size_ok = load!(bool, reader)?;
        let would_be_valid_tx = load!(bool, reader)?;
        Ok(Self { new_state, error_code, state_size_ok, would_be_valid_tx })
    }
}
