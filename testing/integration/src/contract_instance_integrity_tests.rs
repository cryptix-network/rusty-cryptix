//! Instance Integrity Tests (skeleton)
//! These tests document and assert existence of core rule errors that protect instance integrity.
//! Full end-to-end transaction-pipeline tests will be added in the next iteration.
//!
//! Covered error types (construction and matching):
//! - MissingContractState
//! - MultipleStateUtxos
//! - MissingContractStateOutput
//! - InvalidContractAction
//! - InvalidContractState
//! - ContractCustomError
//!
//! Rationale: Keep initial tests green and non-invasive while wiring additional
//! pipeline harness in a follow-up step as approved.
//!
//! 
//! 
//! @Cryptis: All Passed: Test link removed, test no longer needed. Relink for testing.
//! Later delete it complete
//! 
//! 
//! 
use cryptix_consensus_core::errors::tx::TxRuleError;

#[test]
fn instance_integrity_error_variants_exist_and_display() {
    // Construct main integrity-related variants
    let e1 = TxRuleError::MissingContractState(100);
    let e2 = TxRuleError::MultipleStateUtxos(100);
    let e3 = TxRuleError::MissingContractStateOutput;

    // Also include action/state validation related ones for completeness
    let e4 = TxRuleError::InvalidContractAction(100, 42);
    let e5 = TxRuleError::InvalidContractState(100);
    let e6 = TxRuleError::ContractCustomError(100, 7);

    // Ensure Display is implemented and yields non-empty strings
    let s1 = format!("{}", e1);
    let s2 = format!("{}", e2);
    let s3 = format!("{}", e3);
    let s4 = format!("{}", e4);
    let s5 = format!("{}", e5);
    let s6 = format!("{}", e6);

    assert!(!s1.is_empty());
    assert!(!s2.is_empty());
    assert!(!s3.is_empty());
    assert!(!s4.is_empty());
    assert!(!s5.is_empty());
    assert!(!s6.is_empty());

    // Basic pattern matching to guarantee type stability
    match e1 {
        TxRuleError::MissingContractState(cid) => assert_eq!(cid, 100),
        _ => panic!("unexpected variant"),
    }
    match e2 {
        TxRuleError::MultipleStateUtxos(cid) => assert_eq!(cid, 100),
        _ => panic!("unexpected variant"),
    }
    match e3 {
        TxRuleError::MissingContractStateOutput => {}
        _ => panic!("unexpected variant"),
    }
    match e4 {
        TxRuleError::InvalidContractAction(cid, a) => {
            assert_eq!(cid, 100);
            assert_eq!(a, 42);
        }
        _ => panic!("unexpected"),
    }
    match e5 {
        TxRuleError::InvalidContractState(cid) => assert_eq!(cid, 100),
        _ => panic!("unexpected"),
    }
    match e6 {
        TxRuleError::ContractCustomError(cid, code) => {
            assert_eq!(cid, 100);
            assert_eq!(code, 7);
        }
        _ => panic!("unexpected"),
    }
}
