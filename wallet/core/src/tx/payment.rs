//!
//! Primitives for declaring transaction payment destinations.
//!

use crate::imports::*;
use cryptix_consensus_client::{TransactionOutput, TransactionOutputInner};
use cryptix_txscript::pay_to_address_script;

#[wasm_bindgen(typescript_custom_section)]
const TS_PAYMENT_OUTPUTS: &'static str = r#"
/**
 * 
 * Defines a single payment output.
 * 
 * @see {@link IGeneratorSettingsObject}, {@link Generator}
 * @category Wallet SDK
 */
export interface IPaymentOutput {
    /**
     * Destination address. The address prefix must match the network
     * you are transacting on (e.g. `cryptix:` for mainnet, `cryptixtest:` for testnet, etc).
     */
    address: Address | string;
    /**
     * Output amount in SOMPI.
     */
    amount: bigint;
}

/**
 *
 * Defines a single script payment output.
 *
 * @see {@link IGeneratorSettingsObject}, {@link Generator}
 * @category Wallet SDK
 */
export interface IScriptPaymentOutput {
    /**
     * Destination script public key. This can be a ScriptPublicKey object or
     * a version-prefixed script-public-key hex string.
     */
    scriptPublicKey: IScriptPublicKey | HexString;
    /**
     * Output amount in SOMPI.
     */
    amount: bigint;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IPaymentOutput")]
    pub type IPaymentOutput;
    #[wasm_bindgen(typescript_type = "IPaymentOutput[]")]
    pub type IPaymentOutputArray;
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum PaymentDestination {
    Change,
    PaymentOutputs(PaymentOutputs),
    ScriptOutputs(ScriptPaymentOutputs),
}

impl PaymentDestination {
    pub fn amount(&self) -> Option<u64> {
        match self {
            Self::Change => None,
            Self::PaymentOutputs(payment_outputs) => Some(payment_outputs.amount()),
            Self::ScriptOutputs(outputs) => Some(outputs.amount()),
        }
    }
}

/// @category Wallet SDK
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, CastFromJs)]
#[wasm_bindgen(inspectable)]
pub struct PaymentOutput {
    #[wasm_bindgen(getter_with_clone)]
    pub address: Address,
    pub amount: u64,
}

impl TryCastFromJs for PaymentOutput {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Self::resolve(value, || {
            if let Some(array) = value.as_ref().dyn_ref::<Array>() {
                let length = array.length();
                if length != 2 {
                    Err(Error::Custom("Invalid payment output".to_string()))
                } else {
                    let address = Address::try_owned_from(array.get(0))?;
                    let amount = array.get(1).try_as_u64()?;
                    Ok(Self { address, amount })
                }
            } else if let Some(object) = Object::try_from(value.as_ref()) {
                let address = object.cast_into::<Address>("address")?;
                let amount = object.get_u64("amount")?;
                Ok(Self { address, amount })
            } else {
                Err(Error::Custom("Invalid payment output".to_string()))
            }
        })
    }
}

#[wasm_bindgen]
impl PaymentOutput {
    #[wasm_bindgen(constructor)]
    pub fn new(address: Address, amount: u64) -> Self {
        Self { address, amount }
    }
}

impl From<PaymentOutput> for TransactionOutput {
    fn from(value: PaymentOutput) -> Self {
        Self::new_with_inner(TransactionOutputInner { script_public_key: pay_to_address_script(&value.address), value: value.amount })
    }
}

impl From<PaymentOutput> for PaymentDestination {
    fn from(output: PaymentOutput) -> Self {
        Self::PaymentOutputs(PaymentOutputs { outputs: vec![output] })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ScriptPaymentOutput {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey,
}

impl ScriptPaymentOutput {
    pub fn new(amount: u64, script_public_key: ScriptPublicKey) -> Self {
        Self { amount, script_public_key }
    }
}

fn script_payment_output_from_js(value: impl AsRef<JsValue>) -> Result<ScriptPaymentOutput> {
    if let Some(array) = value.as_ref().dyn_ref::<Array>() {
        let length = array.length();
        if length != 2 {
            Err(Error::Custom("Invalid script payment output".to_string()))
        } else {
            let script_public_key = ScriptPublicKey::try_owned_from(array.get(0))
                .map_err(|err| Error::custom(format!("Invalid script payment output scriptPublicKey: {err}")))?;
            let amount = array.get(1).try_as_u64()?;
            Ok(ScriptPaymentOutput { amount, script_public_key })
        }
    } else if let Some(object) = Object::try_from(value.as_ref()) {
        if let Some(script_public_key_value) = object.try_get_value("scriptPublicKey")? {
            let script_public_key = ScriptPublicKey::try_owned_from(script_public_key_value)
                .map_err(|err| Error::custom(format!("Invalid script payment output scriptPublicKey: {err}")))?;
            let amount = object.get_u64("amount")?;
            Ok(ScriptPaymentOutput { amount, script_public_key })
        } else {
            let payment_output = PaymentOutput::try_owned_from(value)?;
            Ok(ScriptPaymentOutput { amount: payment_output.amount, script_public_key: pay_to_address_script(&payment_output.address) })
        }
    } else {
        Err(Error::Custom("Invalid script payment output".to_string()))
    }
}

impl From<ScriptPaymentOutput> for TransactionOutput {
    fn from(value: ScriptPaymentOutput) -> Self {
        Self::new_with_inner(TransactionOutputInner { script_public_key: value.script_public_key, value: value.amount })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ScriptPaymentOutputs {
    pub outputs: Vec<ScriptPaymentOutput>,
}

impl ScriptPaymentOutputs {
    pub fn amount(&self) -> u64 {
        self.outputs.iter().map(|output| output.amount).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ScriptPaymentOutput> {
        self.outputs.iter()
    }
}

impl From<ScriptPaymentOutputs> for PaymentDestination {
    fn from(outputs: ScriptPaymentOutputs) -> Self {
        Self::ScriptOutputs(outputs)
    }
}

impl From<ScriptPaymentOutput> for PaymentDestination {
    fn from(output: ScriptPaymentOutput) -> Self {
        Self::ScriptOutputs(ScriptPaymentOutputs { outputs: vec![output] })
    }
}

fn script_payment_outputs_from_js(value: impl AsRef<JsValue>) -> Result<ScriptPaymentOutputs> {
    let outputs = if let Some(output_array) = value.as_ref().dyn_ref::<js_sys::Array>() {
        output_array
            .to_vec()
            .into_iter()
            .map(script_payment_output_from_js)
            .collect::<Result<Vec<_>>>()?
    } else if let Some(object) = value.as_ref().dyn_ref::<js_sys::Object>() {
        Object::entries(object)
            .iter()
            .map(script_payment_output_from_js)
            .collect::<Result<Vec<_>>>()?
    } else if let Some(map) = value.as_ref().dyn_ref::<js_sys::Map>() {
        map.entries()
            .into_iter()
            .flat_map(|v| v.map(script_payment_output_from_js))
            .collect::<Result<Vec<_>>>()?
    } else {
        return Err(Error::Custom("script payment outputs must be an array or an object".to_string()));
    };

    Ok(ScriptPaymentOutputs { outputs })
}

pub fn payment_destination_from_js_outputs(outputs: JsValue) -> Result<PaymentDestination> {
    if outputs.is_undefined() {
        return Ok(PaymentDestination::Change);
    }

    let contains_script_output = if let Some(output_array) = outputs.dyn_ref::<js_sys::Array>() {
        output_array.to_vec().iter().any(|value| {
            Object::try_from(value).and_then(|object| object.try_get_value("scriptPublicKey").ok().flatten()).is_some()
        })
    } else if let Some(object) = outputs.dyn_ref::<js_sys::Object>() {
        object.try_get_value("scriptPublicKey").ok().flatten().is_some()
    } else {
        false
    };

    if contains_script_output {
        Ok(script_payment_outputs_from_js(outputs)?.into())
    } else {
        Ok(PaymentOutputs::try_owned_from(outputs)?.into())
    }
}

/// @category Wallet SDK
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, CastFromJs)]
#[wasm_bindgen]
pub struct PaymentOutputs {
    #[wasm_bindgen(skip)]
    pub outputs: Vec<PaymentOutput>,
}

impl PaymentOutputs {
    pub fn amount(&self) -> u64 {
        self.outputs.iter().map(|payment_output| payment_output.amount).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PaymentOutput> {
        self.outputs.iter()
    }
}

impl From<PaymentOutputs> for PaymentDestination {
    fn from(outputs: PaymentOutputs) -> Self {
        Self::PaymentOutputs(outputs)
    }
}

#[wasm_bindgen]
impl PaymentOutputs {
    #[wasm_bindgen(constructor)]
    pub fn constructor(output_array: IPaymentOutputArray) -> crate::result::Result<PaymentOutputs> {
        let mut outputs = vec![];
        let iterator = js_sys::try_iter(&output_array)?.ok_or("need to pass iterable JS values!")?;
        for x in iterator {
            // outputs.push((x?).try_into_cast()?);
            outputs.push(PaymentOutput::try_owned_from(x?)?);
        }

        Ok(Self { outputs })
    }
}

impl TryCastFromJs for PaymentOutputs {
    type Error = Error;
    fn try_cast_from<'a, R>(value: &'a R) -> Result<Cast<Self>, Self::Error>
    where
        R: AsRef<JsValue> + 'a,
    {
        Self::resolve(value, || {
            let outputs = if let Some(output_array) = value.as_ref().dyn_ref::<js_sys::Array>() {
                let vec = output_array.to_vec();
                vec.into_iter().map(PaymentOutput::try_owned_from).collect::<Result<Vec<_>, _>>()?
            } else if let Some(object) = value.as_ref().dyn_ref::<js_sys::Object>() {
                Object::entries(object).iter().map(PaymentOutput::try_owned_from).collect::<Result<Vec<_>, _>>()?
            } else if let Some(map) = value.as_ref().dyn_ref::<js_sys::Map>() {
                map.entries().into_iter().flat_map(|v| v.map(PaymentOutput::try_owned_from)).collect::<Result<Vec<_>, _>>()?
            } else {
                return Err(Error::Custom("payment outputs must be an array or an object".to_string()));
            };

            Ok(Self { outputs })
        })
    }
}

impl From<PaymentOutputs> for Vec<TransactionOutput> {
    fn from(value: PaymentOutputs) -> Self {
        value.outputs.into_iter().map(TransactionOutput::from).collect()
    }
}

impl From<(Address, u64)> for PaymentOutputs {
    fn from((address, amount): (Address, u64)) -> Self {
        PaymentOutputs { outputs: vec![PaymentOutput::new(address, amount)] }
    }
}

impl From<(&Address, u64)> for PaymentOutputs {
    fn from((address, amount): (&Address, u64)) -> Self {
        PaymentOutputs { outputs: vec![PaymentOutput::new(address.clone(), amount)] }
    }
}

impl From<&[(Address, u64)]> for PaymentOutputs {
    fn from(outputs: &[(Address, u64)]) -> Self {
        let outputs = outputs.iter().map(|(address, amount)| PaymentOutput::new(address.clone(), *amount)).collect();
        PaymentOutputs { outputs }
    }
}

impl From<&[(&Address, u64)]> for PaymentOutputs {
    fn from(outputs: &[(&Address, u64)]) -> Self {
        let outputs = outputs.iter().map(|(address, amount)| PaymentOutput::new((*address).clone(), *amount)).collect();
        PaymentOutputs { outputs }
    }
}
