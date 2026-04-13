use kem::{Decapsulate, Encapsulate};
use ml_kem::{
    kem::{DecapsulationKey, EncapsulationKey},
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};

pub const PQ_MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;
pub const PQ_MLKEM1024_PRIVATE_KEY_SIZE: usize = 3168;
pub const PQ_MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;
pub const PQ_MLKEM1024_SHARED_SECRET_SIZE: usize = 32;
pub const PQ_HANDSHAKE_PROOF_SIZE: usize = 32;

const PQ_HANDSHAKE_DOMAIN_TAG: &[u8] = b"cryptix-pq-mlkem1024-ready-v1";

type MlKem1024DecapsulationKey = DecapsulationKey<MlKem1024Params>;
type MlKem1024EncapsulationKey = EncapsulationKey<MlKem1024Params>;

pub fn generate_mlkem1024_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let (local_decapsulation_key, local_encapsulation_key) = MlKem1024::generate(&mut rng);
    let public_key = local_encapsulation_key.as_bytes().as_slice().to_vec();
    let private_key = local_decapsulation_key.as_bytes().as_slice().to_vec();
    (public_key, private_key)
}

pub fn encapsulate_mlkem1024(peer_public_key: &[u8]) -> Result<(Vec<u8>, [u8; PQ_MLKEM1024_SHARED_SECRET_SIZE]), String> {
    let encoded_peer_public_key = Encoded::<MlKem1024EncapsulationKey>::try_from(peer_public_key)
        .map_err(|_| format!("peer ML-KEM-1024 public key must be exactly {PQ_MLKEM1024_PUBLIC_KEY_SIZE} bytes"))?;
    let peer_encapsulation_key = MlKem1024EncapsulationKey::from_bytes(&encoded_peer_public_key);
    let mut rng = rand::thread_rng();
    let (ciphertext, shared_secret) =
        peer_encapsulation_key.encapsulate(&mut rng).map_err(|err| format!("ML-KEM-1024 encapsulation failed: {err:?}"))?;

    let mut shared_secret_bytes = [0u8; PQ_MLKEM1024_SHARED_SECRET_SIZE];
    shared_secret_bytes.copy_from_slice(shared_secret.as_slice());
    Ok((ciphertext.as_slice().to_vec(), shared_secret_bytes))
}

pub fn decapsulate_mlkem1024(local_private_key: &[u8], ciphertext: &[u8]) -> Result<[u8; PQ_MLKEM1024_SHARED_SECRET_SIZE], String> {
    let encoded_local_private_key = Encoded::<MlKem1024DecapsulationKey>::try_from(local_private_key)
        .map_err(|_| format!("local ML-KEM-1024 private key must be exactly {PQ_MLKEM1024_PRIVATE_KEY_SIZE} bytes"))?;
    let local_decapsulation_key = MlKem1024DecapsulationKey::from_bytes(&encoded_local_private_key);
    let encoded_ciphertext = Ciphertext::<MlKem1024>::try_from(ciphertext)
        .map_err(|_| format!("peer ML-KEM-1024 ciphertext must be exactly {PQ_MLKEM1024_CIPHERTEXT_SIZE} bytes"))?;
    let shared_secret = local_decapsulation_key
        .decapsulate(&encoded_ciphertext)
        .map_err(|err| format!("ML-KEM-1024 decapsulation failed: {err:?}"))?;

    let mut shared_secret_bytes = [0u8; PQ_MLKEM1024_SHARED_SECRET_SIZE];
    shared_secret_bytes.copy_from_slice(shared_secret.as_slice());
    Ok(shared_secret_bytes)
}

pub fn compute_pq_handshake_proof(
    network_code: u8,
    signer_node_id: &[u8; 32],
    verifier_node_id: &[u8; 32],
    signer_challenge_nonce: u64,
    verifier_challenge_nonce: u64,
    shared_secret: &[u8; PQ_MLKEM1024_SHARED_SECRET_SIZE],
) -> [u8; PQ_HANDSHAKE_PROOF_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PQ_HANDSHAKE_DOMAIN_TAG);
    hasher.update(&[network_code]);
    hasher.update(signer_node_id);
    hasher.update(verifier_node_id);
    hasher.update(&signer_challenge_nonce.to_be_bytes());
    hasher.update(&verifier_challenge_nonce.to_be_bytes());
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::{
        compute_pq_handshake_proof, decapsulate_mlkem1024, encapsulate_mlkem1024, generate_mlkem1024_keypair, PQ_HANDSHAKE_PROOF_SIZE,
    };

    #[test]
    fn mlkem1024_encapsulation_round_trip() {
        let (public_key, private_key) = generate_mlkem1024_keypair();
        let (ciphertext, sender_shared_secret) = encapsulate_mlkem1024(&public_key).expect("encapsulation should succeed");
        let receiver_shared_secret = decapsulate_mlkem1024(&private_key, &ciphertext).expect("decapsulation should succeed");
        assert_eq!(sender_shared_secret, receiver_shared_secret);
    }

    #[test]
    fn proof_is_stable_and_nonce_bound() {
        let signer_node_id = [0x11u8; 32];
        let verifier_node_id = [0x22u8; 32];
        let shared_secret = [0x55u8; 32];
        let proof_a = compute_pq_handshake_proof(1, &signer_node_id, &verifier_node_id, 10, 20, &shared_secret);
        let proof_b = compute_pq_handshake_proof(1, &signer_node_id, &verifier_node_id, 10, 20, &shared_secret);
        let proof_c = compute_pq_handshake_proof(1, &signer_node_id, &verifier_node_id, 10, 21, &shared_secret);
        assert_eq!(proof_a, proof_b);
        assert_ne!(proof_a, proof_c);
        assert_eq!(proof_a.len(), PQ_HANDSHAKE_PROOF_SIZE);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let encap_err = encapsulate_mlkem1024(&[]).expect_err("invalid public key length must fail");
        assert!(encap_err.contains("public key"));

        let decap_err = decapsulate_mlkem1024(&[], &[]).expect_err("invalid private key length must fail");
        assert!(decap_err.contains("private key"));
    }
}
