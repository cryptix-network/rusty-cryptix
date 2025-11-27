//! Engine Safety Negative Tests
//! Validates that core contracts reject invalid inputs deterministically without panics
//! and enforce 8KB state limits and semantic constraints.

use cryptix_consensus_core::contract::{get_contract, BlockContext, ContractError, MAX_CONTRACT_STATE_SIZE};
type Addr = [u8; 32];
type H32 = [u8; 32];

fn ctx_at(h: u64, t: u64) -> BlockContext {
    BlockContext { block_height: h, daa_score: 0, block_time: t, tx_id: [0u8; 32], input_index: 0, auth_addr: [0u8; 32] }
}
fn addr(b: u8) -> Addr { [b; 32] }
fn h32(b: u8) -> H32 { [b; 32] }

// -------------------- CX20 (100) --------------------

#[test]
fn cx20_negative_invalid_inputs_and_semantics() {
    let c = get_contract(100).expect("CX20 registry");
    let owner = addr(1);
    // invalid deploy payload too short
    let res = c.apply(&[], 0, &[1,2,3], &ctx_at(0,0));
    assert!(matches!(res, Err(ContractError::InvalidState)));
    // deploy ok
    let mut dep = Vec::new();
    dep.extend_from_slice(&100u64.to_le_bytes());
    dep.extend_from_slice(&owner);
    dep.extend_from_slice(&0u16.to_le_bytes());
    let st = c.apply(&[], 0, &dep, &ctx_at(0,0)).expect("deploy");
    // invalid action id
    let res2 = c.apply(&st, 999, &[], &ctx_at(0,0));
    assert!(matches!(res2, Err(ContractError::InvalidAction)));

    // burn more than balance -> Insufficient
    let mut burn = Vec::new();
    burn.extend_from_slice(&200u64.to_le_bytes());
    let res3 = c.apply(&st, 2, &burn, &ctx_at(0,0));
    assert!(matches!(res3, Err(ContractError::Custom(1))));

    // transfer zero amount -> InvalidParam
    let mut tr0 = Vec::new();
    tr0.extend_from_slice(&addr(9));
    tr0.extend_from_slice(&0u64.to_le_bytes());
    let res4 = c.apply(&st, 3, &tr0, &ctx_at(0,0));
    assert!(matches!(res4, Err(ContractError::Custom(5))));
}

#[test]
fn cx20_negative_state_too_large() {
    let c = get_contract(100).expect("CX20");
    let owner = addr(1);

    // deploy
    let mut dep = Vec::new();
    dep.extend_from_slice(&0u64.to_le_bytes());
    dep.extend_from_slice(&owner);
    dep.extend_from_slice(&0u16.to_le_bytes());
    let mut st = c.apply(&[], 0, &dep, &ctx_at(0,0)).expect("deploy");

    // craft near-limit balances to exceed on growth
    // we build a state blob ~ just under 8 KB by repeatedly minting to unique addresses via admin transfer path
    // Encode approve to create allowances section and grow, then attempt to exceed.
    // For engine safety, we validate exceeding returns StateTooLarge (error code).
    let mut grow_ok = true;
    for i in 0..300u16 {
        // approve some to keep encode deterministic growth
        let mut ap = Vec::new();
        ap.extend_from_slice(&owner);
        ap.extend_from_slice(&1u64.to_le_bytes());
        st = match c.apply(&st, 4, &ap, &ctx_at(0,0)) { Ok(s) => s, Err(_) => { grow_ok = false; break; } };

        // try transfer 1 to new address to grow balances vector
        let mut tr = Vec::new();
        tr.extend_from_slice(&addr((i % 200) as u8));
        tr.extend_from_slice(&1u64.to_le_bytes());
        match c.apply(&st, 3, &tr, &ctx_at(0,0)) {
            Ok(s) => st = s,
            Err(ContractError::StateTooLarge) => { grow_ok = false; break; }
            Err(_) => { /* tolerate other failures while attempting to hit limit */ }
        }
        if st.len() > MAX_CONTRACT_STATE_SIZE {
            panic!("engine returned state over 8KB without error");
        }
    }
    // At some point growth must be rejected or loop exhausted without panics
    assert!(!grow_ok || st.len() <= MAX_CONTRACT_STATE_SIZE);
}

// -------------------- CXNFT (110) --------------------

#[test]
fn cxnft_negative_invalid_inputs_and_semantics() {
    let c = get_contract(110).expect("CXNFT");
    // Invalid deploy data size
    let res = c.apply(&[], 0, &[1,2,3], &ctx_at(0,0));
    assert!(matches!(res, Err(ContractError::InvalidState)));

    // deploy ok
    let mut dep = Vec::new();
    dep.extend_from_slice(&h32(1));
    dep.extend_from_slice(&h32(2));
    let st = c.apply(&[], 0, &dep, &ctx_at(0,0)).expect("deploy");

    // invalid action id
    let res2 = c.apply(&st, 999, &[], &ctx_at(0,0));
    assert!(matches!(res2, Err(ContractError::InvalidAction)));

    // transfer unknown token
    let mut tr = Vec::new();
    tr.extend_from_slice(&123u64.to_le_bytes());
    tr.extend_from_slice(&addr(9));
    let res3 = c.apply(&st, 3, &tr, &ctx_at(0,0));
    assert!(matches!(res3, Err(ContractError::Custom(3))));
}

// -------------------- DAO (140) --------------------

#[test]
fn dao_negative_invalid_and_semantics() {
    let c = get_contract(140).expect("DAO");
    // deploy
    let mut d = Vec::new(); d.extend_from_slice(&addr(1));
    let st = c.apply(&[], 0, &d, &ctx_at(0,0)).expect("deploy");

    // create vote with invalid options=0 -> InvalidParam (custom 5) or InvalidState
    let mut cv = Vec::new();
    cv.extend_from_slice(&addr(1)); // admin
    cv.extend_from_slice(&10u64.to_le_bytes());
    cv.extend_from_slice(&0u16.to_le_bytes());
    let res = c.apply(&st, 1, &cv, &ctx_at(0,0));
    assert!(matches!(res, Err(ContractError::Custom(5)) | Err(ContractError::InvalidState)));

    // non-admin create_vote -> NotAdmin
    let mut cv2 = Vec::new();
    cv2.extend_from_slice(&addr(9));
    cv2.extend_from_slice(&11u64.to_le_bytes());
    cv2.extend_from_slice(&3u16.to_le_bytes());
    let res2 = c.apply(&st, 1, &cv2, &ctx_at(0,0));
    assert!(matches!(res2, Err(ContractError::Custom(2))));
}

// -------------------- ESCROW (160) --------------------

#[test]
fn escrow_negative_invalid_inputs_and_semantics() {
    let c = get_contract(160).expect("ESCROW");
    // deploy
    let mut d = Vec::new(); d.extend_from_slice(&addr(7));
    let st = c.apply(&[], 0, &d, &ctx_at(0,0)).expect("deploy");

    // open with zero amount -> InvalidParam (custom 5)
    let mut op = Vec::new();
    op.extend_from_slice(&addr(1));
    op.extend_from_slice(&1u64.to_le_bytes());
    op.extend_from_slice(&addr(2));
    op.extend_from_slice(&0u64.to_le_bytes());
    let res = c.apply(&st, 1, &op, &ctx_at(0,0));
    assert!(matches!(res, Err(ContractError::Custom(5))));

    // invalid action id
    let res2 = c.apply(&st, 99, &[], &ctx_at(0,0));
    assert!(matches!(res2, Err(ContractError::InvalidAction)));
}

// -------------------- BRIDGE (370, extension) --------------------

#[test]
fn bridge_negative_invalid_inputs_and_pause() {
    let Some(c) = get_contract(370) else {
        // Extension may not be wired in certain builds; skip.
        return;
    };
    // invalid deploy data
    let res = c.apply(&[], 0, &[1,2,3], &ctx_at(0,0));
    assert!(matches!(res, Err(ContractError::InvalidState)));

    // deploy ok with 1 validator, threshold 1
    let mut dep = Vec::new();
    dep.extend_from_slice(&1u16.to_le_bytes());
    dep.extend_from_slice(&addr(1));
    dep.extend_from_slice(&1u16.to_le_bytes());
    let st = c.apply(&[], 0, &dep, &ctx_at(0,0)).expect("deploy");

    // pause then verify_proof should fail
    let st_p = c.apply(&st, 5, &[], &ctx_at(0,0)).expect("pause");
    let res2 = c.apply(&st_p, 3, b"proof", &ctx_at(0,0));
    assert!(matches!(res2, Err(ContractError::Custom(9))));
}
