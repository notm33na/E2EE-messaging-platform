# Key Exchange Protocol (KEP)

## Overview

The Key Exchange Protocol establishes secure session keys between two parties using authenticated ECDH (Elliptic Curve Diffie-Hellman) with digital signatures.

## Protocol Flow

### Step 1: Identity Key Lookup

**Alice** fetches **Bob's** public identity key from the server:

```
GET /api/keys/:bobId
Response: { publicKey: <Bob's IK_pub in JWK format> }
```

**Bob** fetches **Alice's** public identity key:

```
GET /api/keys/:aliceId
Response: { publicKey: <Alice's IK_pub in JWK format> }
```

### Step 2: Ephemeral Key Generation

**Alice** generates ephemeral key pair:
- `EK_priv_A` (private, kept in memory)
- `EK_pub_A` (public, will be sent to Bob)

**Bob** generates ephemeral key pair:
- `EK_priv_B` (private, kept in memory)
- `EK_pub_B` (public, will be sent to Alice)

### Step 3: KEP_INIT Message

**Alice** creates and signs KEP_INIT:

1. Export `EK_pub_A` to JWK format
2. Sign `EK_pub_A` with `IK_priv_A` (identity private key)
3. Create message:
   ```json
   {
     "type": "KEP_INIT",
     "from": "aliceId",
     "to": "bobId",
     "sessionId": "session-123",
     "ephPub": <EK_pub_A as JWK>,
     "signature": <base64 signature>,
     "timestamp": <current timestamp>,
     "seq": 1,
     "nonce": <random nonce>
   }
   ```
4. Send via WebSocket: `socket.emit("kep:init", message)`

### Step 4: KEP_INIT Verification

**Bob** receives KEP_INIT and verifies:

1. Verify timestamp freshness (±2 minutes)
2. Verify signature using Alice's `IK_pub`:
   - Import `IK_pub` from server
   - Verify signature on `ephPub`
3. If valid, proceed to Step 5
4. If invalid, reject and log

### Step 5: Shared Secret Computation

**Bob** computes shared secret:
- `sharedSecret = ECDH(EK_priv_B, EK_pub_A)`

**Alice** will compute (after receiving Bob's key):
- `sharedSecret = ECDH(EK_priv_A, EK_pub_B)`

Both produce the same 256-bit shared secret.

### Step 6: Session Key Derivation

**Bob** derives session keys using HKDF:

```
rootKey = HKDF(sharedSecret, salt="ROOT", info=sessionId, length=256)
sendKey = HKDF(rootKey, salt="SEND", info=bobId, length=256)
recvKey = HKDF(rootKey, salt="RECV", info=aliceId, length=256)
```

### Step 7: KEP_RESPONSE Message

**Bob** creates and signs KEP_RESPONSE:

1. Export `EK_pub_B` to JWK format
2. Sign `EK_pub_B` with `IK_priv_B`
3. Compute key confirmation: `HMAC(rootKey, "CONFIRM:" + aliceId)`
4. Create message:
   ```json
   {
     "type": "KEP_RESPONSE",
     "from": "bobId",
     "to": "aliceId",
     "sessionId": "session-123",
     "ephPub": <EK_pub_B as JWK>,
     "signature": <base64 signature>,
     "keyConfirmation": <base64 HMAC>,
     "timestamp": <current timestamp>,
     "seq": 2,
     "nonce": <random nonce>
   }
   ```
5. Send via WebSocket: `socket.emit("kep:response", message)`

### Step 8: KEP_RESPONSE Verification

**Alice** receives KEP_RESPONSE and verifies:

1. Verify timestamp freshness
2. Verify signature using Bob's `IK_pub`
3. Compute shared secret: `ECDH(EK_priv_A, EK_pub_B)`
4. Derive session keys (same as Bob)
5. Verify key confirmation HMAC
6. If all valid, session established ✓

## Security Properties

### MITM Prevention

- **Digital Signatures**: Ephemeral keys signed with identity keys
- **Signature Verification**: Prevents key substitution attacks
- **Identity Keys**: Long-term keys establish trust

### Forward Secrecy

- **Ephemeral Keys**: Discarded after session establishment
- **Key Rotation**: Periodic rotation maintains forward secrecy
- **Session Keys**: Derived from ephemeral keys only

### Replay Protection

- **Timestamps**: Messages must be fresh (±2 minutes)
- **Sequence Numbers**: Strictly increasing per session
- **Nonces**: Additional randomness for uniqueness

## Message Format

### KEP_INIT

```json
{
  "type": "KEP_INIT",
  "from": "userId",
  "to": "peerId",
  "sessionId": "string",
  "ephPub": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64",
    "y": "base64"
  },
  "signature": "base64",
  "timestamp": 1234567890,
  "seq": 1,
  "nonce": "base64"
}
```

### KEP_RESPONSE

```json
{
  "type": "KEP_RESPONSE",
  "from": "userId",
  "to": "peerId",
  "sessionId": "string",
  "ephPub": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64",
    "y": "base64"
  },
  "signature": "base64",
  "keyConfirmation": "base64",
  "timestamp": 1234567891,
  "seq": 2,
  "nonce": "base64"
}
```

## Error Handling

### Invalid Signature

- Log event: `invalid_signature.log`
- Reject message
- Notify sender of failure

### Stale Timestamp

- Log event: `replay_attempts.log`
- Reject message
- Reason: "Timestamp out of validity window"

### Invalid Sequence

- Log event: `replay_attempts.log`
- Reject message
- Reason: "Sequence number not monotonic"

## Implementation Notes

- All cryptographic operations use Web Crypto API (client)
- Node crypto module used for server-side signature verification
- No external E2EE libraries
- All keys stored client-side only
- Server never sees private keys or session keys

