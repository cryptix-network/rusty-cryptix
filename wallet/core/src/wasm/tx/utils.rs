use crate::imports::*;
use crate::result::Result;
use crate::tx::{default_fast_max_fee_cap, validate_wallet_payload, IPaymentOutputArray, PaymentOutputs};
use crate::wasm::tx::generator::*;
use cryptix_consensus_client::*;
use cryptix_consensus_core::subnets::{SUBNETWORK_ID_NATIVE, SUBNETWORK_ID_PAYLOAD};
use cryptix_wallet_macros::declare_typescript_wasm_interface as declare;
use cryptix_wasm_core::types::BinaryT;
use workflow_core::runtime::is_web;

declare! {
    IFastFeeRecommendation,
    r#"
    /**
     * Recommended fee values for fast-path submission.
     *
     * @category Wallet SDK
     */
    export interface IFastFeeRecommendation {
        txMass: bigint;
        isPayload: boolean;
        estimateFeerate: number;
        requiredFeerate: number;
        requiredFeeSompi: bigint;
        recommendedMaxFeeSompi: bigint;
        minimumRelayFeerate?: number;
        payloadOvercapFeerateFloor?: number;
        effectiveHfaFeerateFloor?: number;
    }
    "#,
}

fn validate_optional_feerate(label: &str, value: Option<f64>) -> Result<Option<f64>> {
    match value {
        Some(v) if !v.is_finite() || v < 0.0 => Err(Error::custom(format!("{label} must be a finite non-negative number"))),
        Some(v) => Ok(Some(v)),
        None => Ok(None),
    }
}

fn ceil_fee_from_feerate(feerate: f64, tx_mass: u64) -> Result<u64> {
    if tx_mass == 0 || feerate <= 0.0 {
        return Ok(0);
    }

    let fee = (feerate * tx_mass as f64).ceil();
    if !fee.is_finite() || fee < 0.0 || fee > u64::MAX as f64 {
        return Err(Error::custom("unable to compute fee from feerate and tx mass"));
    }

    Ok(fee as u64)
}

/// Build a conservative fast-path fee recommendation from tx mass, a base estimate and optional node-provided floors.
/// @category Wallet SDK
#[wasm_bindgen(js_name = recommendFastFees)]
pub fn recommend_fast_fees_js(
    tx_mass: BigInt,
    estimate_feerate: f64,
    is_payload: Option<bool>,
    minimum_relay_feerate: Option<f64>,
    payload_overcap_feerate_floor: Option<f64>,
    effective_hfa_feerate_floor: Option<f64>,
) -> Result<IFastFeeRecommendation> {
    if !estimate_feerate.is_finite() || estimate_feerate < 0.0 {
        return Err(Error::custom("estimateFeerate must be a finite non-negative number"));
    }

    let tx_mass: u64 = tx_mass.try_into().map_err(|err| Error::custom(format!("invalid txMass value: {err}")))?;
    let is_payload = is_payload.unwrap_or(false);
    let minimum_relay_feerate = validate_optional_feerate("minimumRelayFeerate", minimum_relay_feerate)?;
    let payload_overcap_feerate_floor = validate_optional_feerate("payloadOvercapFeerateFloor", payload_overcap_feerate_floor)?;
    let effective_hfa_feerate_floor = validate_optional_feerate("effectiveHfaFeerateFloor", effective_hfa_feerate_floor)?;

    let mut required_feerate = estimate_feerate;
    if let Some(v) = minimum_relay_feerate {
        required_feerate = required_feerate.max(v);
    }
    if let Some(v) = effective_hfa_feerate_floor {
        required_feerate = required_feerate.max(v);
    }
    if is_payload {
        let payload_floor = payload_overcap_feerate_floor.or_else(|| minimum_relay_feerate.map(|min| min * 2.0)).unwrap_or(0.0);
        required_feerate = required_feerate.max(payload_floor);
    }

    let required_fee_sompi = ceil_fee_from_feerate(required_feerate, tx_mass)?;
    let recommended_max_fee_sompi = default_fast_max_fee_cap(required_fee_sompi);

    let object = IFastFeeRecommendation::default();
    object.set("txMass", &js_sys::BigInt::from(tx_mass).into())?;
    object.set("isPayload", &is_payload.into())?;
    object.set("estimateFeerate", &estimate_feerate.into())?;
    object.set("requiredFeerate", &required_feerate.into())?;
    object.set("requiredFeeSompi", &js_sys::BigInt::from(required_fee_sompi).into())?;
    object.set("recommendedMaxFeeSompi", &js_sys::BigInt::from(recommended_max_fee_sompi).into())?;
    if let Some(v) = minimum_relay_feerate {
        object.set("minimumRelayFeerate", &v.into())?;
    }
    if let Some(v) = payload_overcap_feerate_floor {
        object.set("payloadOvercapFeerateFloor", &v.into())?;
    } else if is_payload {
        if let Some(v) = minimum_relay_feerate.map(|min| min * 2.0) {
            object.set("payloadOvercapFeerateFloor", &v.into())?;
        }
    }
    if let Some(v) = effective_hfa_feerate_floor {
        object.set("effectiveHfaFeerateFloor", &v.into())?;
    }

    Ok(object)
}

/// Create a basic transaction without any mass limit checks.
/// @category Wallet SDK
#[wasm_bindgen(js_name=createTransaction)]
pub fn create_transaction_js(
    utxo_entry_source: IUtxoEntryArray,
    outputs: IPaymentOutputArray,
    priority_fee: BigInt,
    payload: Option<BinaryT>,
    sig_op_count: Option<u8>,
) -> crate::result::Result<Transaction> {
    let utxo_entries = if let Some(utxo_entries) = utxo_entry_source.dyn_ref::<js_sys::Array>() {
        utxo_entries.to_vec().iter().map(UtxoEntryReference::try_owned_from).collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(Error::custom("utxo_entries must be an array"));
    };
    let priority_fee: u64 = priority_fee.try_into().map_err(|err| Error::custom(format!("invalid fee value: {err}")))?;
    let payload = payload.and_then(|payload| payload.try_as_vec_u8().ok()).unwrap_or_default();
    validate_wallet_payload(Some(&payload))?;
    let outputs = PaymentOutputs::try_owned_from(outputs)?;
    let sig_op_count = sig_op_count.unwrap_or(1);

    // ---

    let mut total_input_amount = 0;
    let mut entries = vec![];

    let inputs = utxo_entries
        .into_iter()
        .enumerate()
        .map(|(sequence, reference)| {
            let UtxoEntryReference { utxo } = &reference;
            total_input_amount += utxo.amount();
            entries.push(reference.clone());
            TransactionInput::new(utxo.outpoint.clone(), None, sequence as u64, sig_op_count, Some(reference))
        })
        .collect::<Vec<TransactionInput>>();

    if priority_fee > total_input_amount {
        return Err(format!("priority fee({priority_fee}) > amount({total_input_amount})").into());
    }

    let outputs: Vec<TransactionOutput> = outputs.into();
    let subnetwork_id = if payload.is_empty() { SUBNETWORK_ID_NATIVE } else { SUBNETWORK_ID_PAYLOAD };
    let transaction = Transaction::new(None, 0, inputs, outputs, 0, subnetwork_id, 0, payload, 0)?;

    Ok(transaction)
}

declare! {
    ICreateTransactions,
    r#"
    /**
     * Interface defining response from the {@link createTransactions} function.
     * 
     * @category Wallet SDK
     */
    export interface ICreateTransactions {
        /**
         * Array of pending unsigned transactions.
         */
        transactions : PendingTransaction[];
        /**
         * Summary of the transaction generation process.
         */
        summary : GeneratorSummary;
    }
    "#,
}

#[wasm_bindgen(typescript_custom_section)]
const TS_CREATE_TRANSACTIONS: &'static str = r#"
"#;

/// Helper function that creates a set of transactions using the transaction {@link Generator}.
/// @see {@link IGeneratorSettingsObject}, {@link Generator}, {@link estimateTransactions}
/// @category Wallet SDK
#[wasm_bindgen(js_name=createTransactions)]
pub async fn create_transactions_js(settings: IGeneratorSettingsObject) -> Result<ICreateTransactions> {
    let generator = Generator::ctor(settings)?;
    if is_web() {
        // yield after each generated transaction if operating in the browser
        let mut stream = generator.stream();
        let mut transactions = vec![];
        while let Some(transaction) = stream.try_next().await? {
            transactions.push(PendingTransaction::from(transaction));
            yield_executor().await;
        }
        let transactions = Array::from_iter(transactions.into_iter().map(JsValue::from)); //.collect::<Array>();
        let summary = JsValue::from(generator.summary());
        let object = ICreateTransactions::default();
        object.set("transactions", &transactions)?;
        object.set("summary", &summary)?;
        Ok(object)
    } else {
        let transactions = generator.iter().map(|r| r.map(PendingTransaction::from)).collect::<Result<Vec<_>>>()?;
        let transactions = Array::from_iter(transactions.into_iter().map(JsValue::from)); //.collect::<Array>();
        let summary = JsValue::from(generator.summary());
        let object = ICreateTransactions::default();
        object.set("transactions", &transactions)?;
        object.set("summary", &summary)?;
        Ok(object)
    }
}

/// Helper function that creates an estimate using the transaction {@link Generator}
/// by producing only the {@link GeneratorSummary} containing the estimate.
/// @see {@link IGeneratorSettingsObject}, {@link Generator}, {@link createTransactions}
/// @category Wallet SDK
#[wasm_bindgen(js_name=estimateTransactions)]
pub async fn estimate_transactions_js(settings: IGeneratorSettingsObject) -> Result<GeneratorSummary> {
    let generator = Generator::ctor(settings)?;
    if is_web() {
        // yield after each generated transaction if operating in the browser
        let mut stream = generator.stream();
        while stream.try_next().await?.is_some() {
            yield_executor().await;
        }
        Ok(generator.summary())
    } else {
        // use iterator to aggregate all transactions
        generator.iter().collect::<Result<Vec<_>>>()?;
        Ok(generator.summary())
    }
}
