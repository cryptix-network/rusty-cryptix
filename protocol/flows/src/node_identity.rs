use cryptix_connectionmanager::AntiFraudNetwork;
use cryptix_core::{info, warn};
use hex::{decode as hex_decode, encode as hex_encode};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use secp256k1::{schnorr::Signature as SchnorrSignature, Keypair, Message as SecpMessage, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const NODE_IDENTITY_SCHEMA_VERSION: u32 = 1;
const NODE_IDENTITY_FILE_MAX_BYTES: usize = 16 * 1024;
const STRONG_NODES_DIR: &str = "strong-nodes";
const NODE_IDENTITY_FILE: &str = "node_identity.json";
const NODE_POW_DOMAIN_TAG: &[u8] = b"cryptix-node-id-pow-v1";
const NODE_AUTH_DOMAIN_TAG: &[u8] = b"cryptix-node-id-auth-v1";
const MAINNET_NODE_POW_DIFFICULTY: u8 = 24;
const TESTNET_DEVNET_NODE_POW_DIFFICULTY: u8 = 22;
const SIMNET_NODE_POW_DIFFICULTY: u8 = 8;

#[derive(Clone, Debug)]
pub struct UnifiedNodeIdentity {
    pub secret_key: SecretKey,
    pub pubkey_xonly: [u8; 32],
    pub node_id: [u8; 32],
    pub pow_nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeIdentityDisk {
    schema_version: u32,
    secret_key: String,
    public_key_xonly: String,
    static_id_raw: String,
    #[serde(default)]
    last_seq_no: u64,
    #[serde(default)]
    pow_nonce: Option<u64>,
}

pub fn load_or_create_identity(app_data_dir: &Path, network_name: &str) -> Result<UnifiedNodeIdentity, String> {
    let network_code = network_code_from_name(network_name).ok_or_else(|| format!("unsupported network name `{network_name}`"))?;
    let difficulty = node_pow_difficulty(network_code).ok_or_else(|| format!("unsupported network code `{network_code}`"))?;
    let node_identity_dir = app_data_dir.join(STRONG_NODES_DIR);
    fs::create_dir_all(&node_identity_dir).map_err(|err| format!("failed creating node identity directory: {err}"))?;
    let node_identity_path = node_identity_dir.join(NODE_IDENTITY_FILE);

    if node_identity_path.exists() {
        match load_identity_file(&node_identity_path, network_code) {
            Ok(identity) => {
                info!(
                    "Unified node identity loaded from disk (path: {}, pubkey_xonly: {}, node_id: {}, pow_nonce: {}, difficulty: {})",
                    node_identity_path.display(),
                    hex_encode(identity.pubkey_xonly),
                    hex_encode(identity.node_id),
                    identity.pow_nonce,
                    difficulty
                );
                return Ok(identity);
            }
            Err(err) => {
                warn!(
                    "Unified node identity file invalid/corrupt (path: {}, reason: {}), quarantining and regenerating",
                    node_identity_path.display(),
                    err
                );
                quarantine_corrupted_identity(&node_identity_path);
            }
        }
    }

    info!(
        "Unified node identity generation started (path: {}, network: {}, network_code: {}, difficulty: {})",
        node_identity_path.display(),
        network_name,
        network_code,
        difficulty
    );
    create_and_persist_identity(&node_identity_path, network_code)
}

pub fn create_ephemeral_identity(network_name: &str) -> Result<UnifiedNodeIdentity, String> {
    let network_code = network_code_from_name(network_name).ok_or_else(|| format!("unsupported network name `{network_name}`"))?;
    let mut rng = rand::thread_rng();
    let secret_key = SecretKey::new(&mut rng);
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
    let pubkey_xonly = keypair.x_only_public_key().0.serialize();
    let node_id = compute_node_id(&pubkey_xonly);
    let pow_nonce = mine_pow_nonce(network_code, &pubkey_xonly);
    Ok(UnifiedNodeIdentity { secret_key, pubkey_xonly, node_id, pow_nonce })
}

pub fn network_code_from_name(network_name: &str) -> Option<u8> {
    AntiFraudNetwork::from_network_name(network_name).map(|network| network as u8)
}

pub fn node_pow_difficulty(network_code: u8) -> Option<u8> {
    match network_code {
        0 => Some(MAINNET_NODE_POW_DIFFICULTY),
        1 | 2 => Some(TESTNET_DEVNET_NODE_POW_DIFFICULTY),
        3 => Some(SIMNET_NODE_POW_DIFFICULTY),
        _ => None,
    }
}

pub fn compute_node_id(pubkey_xonly: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(pubkey_xonly).as_bytes()
}

pub fn compute_pow_hash(network_code: u8, pubkey_xonly: &[u8; 32], pow_nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_POW_DOMAIN_TAG);
    hasher.update([network_code]);
    hasher.update(pubkey_xonly);
    hasher.update(pow_nonce.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

pub fn build_node_auth_digest(
    network_code: u8,
    signer_node_id: &[u8; 32],
    verifier_node_id: &[u8; 32],
    signer_challenge_nonce: u64,
    verifier_challenge_nonce: u64,
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(NODE_AUTH_DOMAIN_TAG.len() + 1 + 32 + 32 + 8 + 8);
    payload.extend_from_slice(NODE_AUTH_DOMAIN_TAG);
    payload.push(network_code);
    payload.extend_from_slice(signer_node_id);
    payload.extend_from_slice(verifier_node_id);
    payload.extend_from_slice(&signer_challenge_nonce.to_be_bytes());
    payload.extend_from_slice(&verifier_challenge_nonce.to_be_bytes());
    *blake3::hash(&payload).as_bytes()
}

pub fn sign_node_auth_proof(
    identity: &UnifiedNodeIdentity,
    network_code: u8,
    verifier_node_id: &[u8; 32],
    signer_challenge_nonce: u64,
    verifier_challenge_nonce: u64,
) -> Result<[u8; 64], String> {
    let digest =
        build_node_auth_digest(network_code, &identity.node_id, verifier_node_id, signer_challenge_nonce, verifier_challenge_nonce);
    let message = SecpMessage::from_digest_slice(&digest).map_err(|err| format!("invalid auth digest: {err}"))?;
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &identity.secret_key);
    Ok(*keypair.sign_schnorr(message).as_ref())
}

pub fn verify_node_auth_proof(
    network_code: u8,
    signer_pubkey_xonly: &[u8; 32],
    signer_node_id: &[u8; 32],
    verifier_node_id: &[u8; 32],
    signer_challenge_nonce: u64,
    verifier_challenge_nonce: u64,
    signature: &[u8; 64],
) -> bool {
    let digest =
        build_node_auth_digest(network_code, signer_node_id, verifier_node_id, signer_challenge_nonce, verifier_challenge_nonce);
    let Ok(message) = SecpMessage::from_digest_slice(&digest) else {
        return false;
    };
    let Ok(pubkey) = XOnlyPublicKey::from_slice(signer_pubkey_xonly) else {
        return false;
    };
    let Ok(signature) = SchnorrSignature::from_slice(signature) else {
        return false;
    };
    signature.verify(&message, &pubkey).is_ok()
}

pub fn is_valid_pow_nonce(network_code: u8, pubkey_xonly: &[u8; 32], pow_nonce: u64) -> bool {
    let Some(required_zero_bits) = node_pow_difficulty(network_code) else {
        return false;
    };
    leading_zero_bits(&compute_pow_hash(network_code, pubkey_xonly, pow_nonce)) >= required_zero_bits
}

pub fn leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut count = 0u8;
    for byte in hash {
        if *byte == 0 {
            count = count.saturating_add(8);
            continue;
        }
        count = count.saturating_add(byte.leading_zeros() as u8);
        break;
    }
    count
}

fn create_and_persist_identity(identity_path: &Path, network_code: u8) -> Result<UnifiedNodeIdentity, String> {
    let difficulty = node_pow_difficulty(network_code).ok_or_else(|| format!("unsupported network code `{network_code}`"))?;
    let mut rng = rand::thread_rng();
    let secret_key = SecretKey::new(&mut rng);
    let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
    let pubkey_xonly = keypair.x_only_public_key().0.serialize();
    let node_id = compute_node_id(&pubkey_xonly);
    let mine_started_at = Instant::now();
    let pow_nonce = mine_pow_nonce(network_code, &pubkey_xonly);
    let disk = NodeIdentityDisk {
        schema_version: NODE_IDENTITY_SCHEMA_VERSION,
        secret_key: hex_encode(secret_key.secret_bytes()),
        public_key_xonly: hex_encode(pubkey_xonly),
        static_id_raw: hex_encode(node_id),
        last_seq_no: 0,
        pow_nonce: Some(pow_nonce),
    };
    persist_identity_file(identity_path, &disk)?;
    info!(
        "Unified node identity generation finished (path: {}, pubkey_xonly: {}, node_id: {}, pow_nonce: {}, difficulty: {}, elapsed_ms: {})",
        identity_path.display(),
        hex_encode(pubkey_xonly),
        hex_encode(node_id),
        pow_nonce,
        difficulty,
        mine_started_at.elapsed().as_millis()
    );
    Ok(UnifiedNodeIdentity { secret_key, pubkey_xonly, node_id, pow_nonce })
}

fn load_identity_file(identity_path: &Path, network_code: u8) -> Result<UnifiedNodeIdentity, String> {
    let bytes = fs::read(identity_path).map_err(|err| format!("failed reading identity file: {err}"))?;
    if bytes.len() > NODE_IDENTITY_FILE_MAX_BYTES {
        return Err(format!("identity file exceeded max size of {NODE_IDENTITY_FILE_MAX_BYTES} bytes"));
    }

    let mut disk: NodeIdentityDisk = serde_json::from_slice(&bytes).map_err(|err| format!("invalid identity JSON: {err}"))?;
    if disk.schema_version != NODE_IDENTITY_SCHEMA_VERSION {
        return Err(format!("unsupported identity schema version {}", disk.schema_version));
    }

    let secret_key_bytes = decode_hex_32(&disk.secret_key)?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).map_err(|err| format!("invalid secret key: {err}"))?;
    let expected_pubkey = Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key).x_only_public_key().0.serialize();
    let stored_pubkey = decode_hex_32(&disk.public_key_xonly)?;
    if stored_pubkey != expected_pubkey {
        return Err("public_key_xonly does not match secret key".to_string());
    }

    let node_id = compute_node_id(&stored_pubkey);
    let stored_node_id = decode_hex_32(&disk.static_id_raw)?;
    if stored_node_id != node_id {
        return Err("static_id_raw does not match blake3(public_key_xonly)".to_string());
    }

    let mut pow_nonce = disk.pow_nonce.unwrap_or(0);
    if !is_valid_pow_nonce(network_code, &stored_pubkey, pow_nonce) {
        let difficulty = node_pow_difficulty(network_code).unwrap_or(0);
        info!(
            "Unified node identity PoW is missing/invalid; re-mining (path: {}, pubkey_xonly: {}, old_pow_nonce: {}, difficulty: {})",
            identity_path.display(),
            hex_encode(stored_pubkey),
            pow_nonce,
            difficulty
        );
        let mine_started_at = Instant::now();
        pow_nonce = mine_pow_nonce(network_code, &stored_pubkey);
        disk.public_key_xonly = hex_encode(stored_pubkey);
        disk.static_id_raw = hex_encode(node_id);
        disk.pow_nonce = Some(pow_nonce);
        persist_identity_file(identity_path, &disk)?;
        info!(
            "Unified node identity PoW re-mined (path: {}, pubkey_xonly: {}, node_id: {}, pow_nonce: {}, difficulty: {}, elapsed_ms: {})",
            identity_path.display(),
            hex_encode(stored_pubkey),
            hex_encode(node_id),
            pow_nonce,
            difficulty,
            mine_started_at.elapsed().as_millis()
        );
    }

    Ok(UnifiedNodeIdentity { secret_key, pubkey_xonly: stored_pubkey, node_id, pow_nonce })
}

fn mine_pow_nonce(network_code: u8, pubkey_xonly: &[u8; 32]) -> u64 {
    let mut seed_material = [0u8; 32];
    seed_material.copy_from_slice(compute_node_id(pubkey_xonly).as_slice());
    let mut seeded_rng = StdRng::from_seed(seed_material);
    let mut nonce = seeded_rng.next_u64();
    loop {
        if is_valid_pow_nonce(network_code, pubkey_xonly, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn persist_identity_file(identity_path: &Path, disk: &NodeIdentityDisk) -> Result<(), String> {
    let parent = identity_path.parent().ok_or_else(|| format!("identity path has no parent: {}", identity_path.display()))?;
    fs::create_dir_all(parent).map_err(|err| format!("failed creating identity dir: {err}"))?;

    let bytes = serde_json::to_vec_pretty(disk).map_err(|err| format!("failed serializing identity: {err}"))?;
    let mut payload = bytes;
    payload.push(b'\n');

    let tmp_path = identity_path.with_extension("tmp");
    {
        let mut file = File::create(&tmp_path).map_err(|err| format!("failed creating temp identity file: {err}"))?;
        file.write_all(&payload).map_err(|err| format!("failed writing temp identity file: {err}"))?;
        file.sync_all().map_err(|err| format!("failed syncing temp identity file: {err}"))?;
    }
    fs::rename(&tmp_path, identity_path).map_err(|err| format!("failed replacing identity file: {err}"))?;
    Ok(())
}

fn decode_hex_32(raw: &str) -> Result<[u8; 32], String> {
    let decoded = hex_decode(raw.trim()).map_err(|err| format!("invalid hex string: {err}"))?;
    decoded.as_slice().try_into().map_err(|_| "hex value must be exactly 32 bytes".to_string())
}

fn quarantine_corrupted_identity(identity_path: &Path) {
    if !identity_path.exists() {
        return;
    }
    let quarantine_path = identity_path.with_extension(format!("corrupt-{}", unix_timestamp_ms()));
    let _ = fs::rename(identity_path, quarantine_path);
}

fn unix_timestamp_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_nonce(network_code: u8, pubkey_xonly: [u8; 32], difficulty: u8) -> u64 {
        let mut nonce = 0u64;
        loop {
            let zeros = leading_zero_bits(&compute_pow_hash(network_code, &pubkey_xonly, nonce));
            if zeros >= difficulty {
                return nonce;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    #[test]
    fn compute_node_id_is_deterministic() {
        let pubkey = [7u8; 32];
        let expected = compute_node_id(&pubkey);
        assert_eq!(expected, compute_node_id(&pubkey));
    }

    #[test]
    fn pow_hash_changes_with_nonce() {
        let pubkey = [3u8; 32];
        let h1 = compute_pow_hash(0, &pubkey, 1);
        let h2 = compute_pow_hash(0, &pubkey, 2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn pow_nonce_validation_works() {
        let pubkey = [9u8; 32];
        let nonce = find_nonce(1, pubkey, 10);
        let zero_bits = leading_zero_bits(&compute_pow_hash(1, &pubkey, nonce));
        assert!(zero_bits >= 10);
    }

    #[test]
    fn pow_difficulty_constants_are_locked() {
        assert_eq!(MAINNET_NODE_POW_DIFFICULTY, 24);
        assert_eq!(TESTNET_DEVNET_NODE_POW_DIFFICULTY, 22);
        assert_eq!(SIMNET_NODE_POW_DIFFICULTY, 8);
    }

    #[test]
    fn cross_language_vectors_match() {
        let vectors = [
            (
                0u8,
                "6d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
                "1b393963bd75edc656dbc0207e35416c509d27a2bf83119c4b4f916bedbab3a2",
                35392942u64,
                "000000b2f399876eaed4de3156fe4aafa1b451e1a1ea2b3fa245e310dc9022ad",
            ),
            (
                0u8,
                "5f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
                "53240c1f9d4506e30994f69fbbf8feb97f3d2e0d89330cf76207b41fef73d994",
                13829020u64,
                "000000e250482b9640b31048b25776572deb49e45de48217938b2003ee4ef731",
            ),
            (
                1u8,
                "fc10777c57060195c83e9885c790c8a26496d305b366b8e5fbf475203c680f79",
                "e28077604051f2d4cc5218b7d57e81164203ccfb2b503b2aa0dd8fd30c19e274",
                8894582u64,
                "000003867828f13ad967b222c180b6f75d5db14ca6e4804395113b93896cca15",
            ),
            (
                2u8,
                "c93b4ed533a76866a3c3ea1cc0bc3e70c0dbe32a945057b5dff95b88ce9280dd",
                "524988b85b8b6ba0d4e24b934cc5b129c628f70609932cd4509e82eb6a22556a",
                1588910u64,
                "000002136045d006fa98697640fed65804859d1d96342298c17c019243b61d97",
            ),
            (
                3u8,
                "01ea552a43712c4c96771ce1e9f83a877a735b31b3e200df94c661153c7dcb4b",
                "570a7eadd0f105a27fd5530dd175a8d8d21c38b657206afdd37e6cd644b4b84f",
                9081845u64,
                "0000000f4fce90bc93a2644f41cee1aa4774b367e49fce64a8d8fb49e160fe99",
            ),
        ];

        for (network, pubkey_hex, node_id_hex, nonce, pow_hash_hex) in vectors {
            let pubkey = decode_hex_32(pubkey_hex).unwrap();
            let expected_node_id = decode_hex_32(node_id_hex).unwrap();
            let expected_pow_hash = decode_hex_32(pow_hash_hex).unwrap();

            assert_eq!(compute_node_id(&pubkey), expected_node_id);
            assert_eq!(compute_pow_hash(network, &pubkey, nonce), expected_pow_hash);
            assert!(is_valid_pow_nonce(network, &pubkey, nonce));
        }
    }
}
