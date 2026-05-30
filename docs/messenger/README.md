# Cryptix Messenger Developer Notes

Extended Developer Information:

## Payload Limits

- Wallet payload hard limit: `2048` bytes.
- Recommended target: `1024` bytes.
- Warning threshold: `1536` bytes.
- Messenger v1 header: `80` bytes.
- Maximum v1 body size: `1968` bytes.
- CryptoBox body overhead: `40` bytes (`24` byte encryption nonce + `16` byte auth tag).
- Maximum plaintext size when the body stores a CryptoBox blob: `1928` bytes.

## CXM Envelope v1

Messenger v1 payloads start with `CXM` (`0x43 0x58 0x4d`). Anything that does not start with `CXM` is classified by the wallet as `raw` payload. A payload that starts with `CXM` but has an unsupported version or invalid header is rejected by wallet payload validation.

```text
offset  size  field
0       3     magic = "CXM"
3       1     version = 1
4       1     msgType
5       1     flags
6       16    recipientTag
22      24    envelopeNonce
46      1     senderKind
47      1     senderLen
48      32    senderData
80      var   body
```

`msgType` and `flags` are platform/application fields. Consensus does not interpret them. Keep them stable inside your app so older clients can ignore unknown message types cleanly.

Sender encoding:

- `senderKind=1`: `senderLen=32`, `senderData` is the full 32-byte sender public key.
- `senderKind=2`: `senderLen=16`, `senderData[0..16]` is a sender reference, and `senderData[16..32]` must be zero.

Wallet deduplication uses `sha256(canonicalSender || envelopeNonce)`. For that reason, `envelopeNonce` should be random and unique per logical message. This nonce is not the same as the CryptoBox encryption nonce inside the encrypted body.

## Encryption

Transaction payloads are public on-chain data. If a message should be private, encrypt the `body`. The wallet WASM API exposes `crypto_box::ChaChaBox` helpers:

- Private and public keys are 32 bytes each.
- `CryptoBox.encrypt(plaintext)` returns Base64 of `encryptionNonce || ciphertext || tag`.
- `CryptoBox.decrypt(base64)` expects exactly that format.
- If you store the encrypted value in the CXM body, decode the Base64 string back to bytes first.

Practical flow:

1. Know the receiver public key, or resolve it from your address/profile system.
2. Create `CryptoBox(senderPrivateKey, receiverPublicKey)`.
3. Encrypt the plaintext and use the encrypted bytes as the CXM body.
4. Set `recipientTag` as your routing tag, for example the first 16 bytes of a stable hash over the receiver public key. The node does not validate this tag.
5. Build the CXM payload and send it as normal transaction payload.

Header metadata such as `recipientTag`, `senderKind`, `senderData`, `msgType`, and `flags` stays visible. If your app wants to hide sender metadata better, use `senderKind=2` with an app-level reference and put the real sender key only inside the encrypted body.

## WASM Helpers

```ts
messengerPayloadLimits(): {
  maxPayloadBytes: number;
  headerBytes: number;
  maxBodyBytes: number;
  cryptoboxOverheadBytes: number;
  maxCryptoboxPlaintextBytes: number;
}

serializeMessengerPayloadV1(
  msgType: number,
  flags: number,
  recipientTag: Uint8Array, // 16 bytes
  nonce: Uint8Array,        // 24-byte envelope nonce
  senderKind: number,       // 1 pubkey, 2 ref
  senderData: Uint8Array,   // 32 bytes for kind 1, 16 or padded 32 for kind 2
  body?: Uint8Array
): Uint8Array

parseMessengerPayload(payload: Uint8Array): {
  kind: "raw" | "unsupported" | "v1";
  payloadLength: number;
  payload: Uint8Array;
  version?: number;
  msgType?: number;
  flags?: number;
  recipientTagHex?: string;
  nonceHex?: string;
  senderKind?: number;
  senderLen?: number;
  senderDataHex?: string;
  bodyLength?: number;
  body?: Uint8Array;
}
```

CryptoBox WASM:

```ts
const priv = new CryptoBoxPrivateKey(secretKeyBytes);
const pub = priv.toPublicKey();
const peer = new CryptoBoxPublicKey(peerPublicKeyBytes);
const box = new CryptoBox(priv, peer);

const encryptedBase64 = box.encrypt("hello");
const plaintext = box.decrypt(encryptedBase64);
```

## Sending and Reading

No special node RPC is required for sending Messenger payloads. Build the payload with `serializeMessengerPayloadV1`, pass it into the normal wallet/transaction generator as `payload`, and submit the transaction with the normal `SubmitTransaction` RPC.

For reading, scan transaction payloads in the wallet or indexer. `parseMessengerPayload` returns `kind="v1"` for valid CXM messages, `kind="raw"` for other payloads, and `kind="unsupported"` for newer CXM versions. After a reorg or rescan, the same logical message can appear again; the wallet suppresses duplicates by sender identity plus envelope nonce.
