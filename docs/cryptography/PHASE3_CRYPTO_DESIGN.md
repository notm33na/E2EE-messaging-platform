# Phase 3: End-to-End Encryption Design Document

**Generated:** 2025-11-30  
**Version:** 1.0  
**Status:** Implementation Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Identity Key Design](#identity-key-design)
3. [Storage Strategy](#storage-strategy)
4. [ECDH Protocol Diagram](#ecdh-protocol-diagram)
5. [Message Flow Diagrams](#message-flow-diagrams)
6. [Replay Protection Model](#replay-protection-model)
7. [HKDF Derivation Chain](#hkdf-derivation-chain)
8. [Security Considerations](#security-considerations)
9. [Limitations & Future Improvements](#limitations--future-improvements)

---

## Overview

Phase 3 implements a complete **End-to-End Encryption (E2EE)** foundation using only Web Crypto API (browser) and Node.js crypto module. The system provides:

- **Identity Key Pairs**: Long-lived ECC P-256 keys for signing ephemeral keys
- **Ephemeral Key Exchange**: Authenticated ECDH protocol for session establishment
- **Session Key Derivation**: HKDF-based key derivation for secure communication
- **Replay Protection**: Timestamp, nonce, and sequence number validation
- **Secure Storage**: IndexedDB with password-based encryption for private keys

**No external E2EE libraries are used** - all cryptography is implemented using native Web Crypto API and Node.js crypto.

---

## Identity Key Design

### Purpose

Identity keys are **long-lived** ECC P-256 key pairs that serve as the cryptographic identity of each user. They are used to:

1. Sign ephemeral public keys in the Key Exchange Protocol (KEP)
2. Verify the authenticity of ephemeral keys from peers
3. Establish trust in the key exchange process

### Key Generation

```
┌─────────────────────────────────────────┐
│  User Registration                      │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Generate ECC P-256 Key Pair            │
│  - Algorithm: ECDSA                     │
│  - Curve: P-256 (prime256v1)            │
│  - Usage: sign, verify                  │
└─────────────────────────────────────────┘
              │
        ┌─────┴─────┐
        ▼           ▼
┌──────────┐  ┌──────────┐
│ Private  │  │ Public   │
│ Key      │  │ Key      │
└──────────┘  └──────────┘
     │              │
     │              ▼
     │      ┌──────────────┐
     │      │ Export JWK   │
     │      │ Upload to    │
     │      │ Server       │
     │      └──────────────┘
     │
     ▼
┌─────────────────────────┐
│ Encrypt with Password   │
│ - PBKDF2 (100k iters)   │
│ - AES-GCM               │
│ - Store in IndexedDB    │
└─────────────────────────┘
```

### Key Properties

- **Algorithm**: ECDSA with P-256 curve
- **Format**: JWK (JSON Web Key) for public keys
- **Storage**: 
  - Private key: Encrypted in IndexedDB
  - Public key: Stored on server in plaintext (public by design)

### Security Model

- Private keys **never leave the browser** (except encrypted)
- Public keys are published to server for peer lookup
- Password-based encryption uses PBKDF2 with 100,000 iterations
- AES-GCM provides authenticated encryption

---

## Storage Strategy

### Private Key Storage

Two storage options are supported:

#### Option 1: IndexedDB (Preferred)

```
┌─────────────────────────────────────┐
│  IndexedDB: InfosecCryptoDB         │
│  ┌───────────────────────────────┐ │
│  │ Store: identityKeys           │ │
│  │ ┌───────────────────────────┐ │ │
│  │ │ userId: string            │ │ │
│  │ │ encryptedData: Uint8Array │ │ │
│  │ │ salt: Uint8Array          │ │ │
│  │ │ iv: Uint8Array            │ │ │
│  │ │ createdAt: ISO string     │ │ │
│  │ └───────────────────────────┘ │ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
```

**Encryption Process:**
1. Export private key to JWK format
2. Serialize JWK to ArrayBuffer
3. Generate random salt (16 bytes) and IV (12 bytes)
4. Derive encryption key: `PBKDF2(password, salt, 100000, SHA-256)`
5. Encrypt: `AES-GCM(encryptionKey, iv, jwkData)`
6. Store encrypted data + salt + IV in IndexedDB

**Decryption Process:**
1. Load encrypted data from IndexedDB
2. Derive decryption key using stored salt
3. Decrypt using AES-GCM with stored IV
4. Parse JWK and import as CryptoKey

#### Option 2: Encrypted localStorage (Fallback)

Similar process but stored in localStorage with base64 encoding.

### Session Storage

Sessions are stored in IndexedDB:

```
┌─────────────────────────────────────┐
│  IndexedDB: InfosecCryptoDB         │
│  ┌───────────────────────────────┐ │
│  │ Store: sessions               │ │
│  │ ┌───────────────────────────┐ │ │
│  │ │ sessionId: string         │ │ │
│  │ │ userId: string            │ │ │
│  │ │ peerId: string            │ │ │
│  │ │ rootKey: base64           │ │ │
│  │ │ sendKey: base64            │ │ │
│  │ │ recvKey: base64            │ │ │
│  │ │ lastSeq: number           │ │ │
│  │ │ lastTimestamp: number     │ │ │
│  │ │ createdAt: ISO string     │ │ │
│  │ └───────────────────────────┘ │ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
```

Keys are stored as base64 strings and converted to ArrayBuffer when loaded.

---

## ECDH Protocol Diagram

### Complete Key Exchange Flow

```
┌─────────┐                                    ┌─────────┐
│  Alice  │                                    │   Bob   │
└────┬────┘                                    └────┬────┘
     │                                              │
     │ 1. Fetch Bob's identity public key           │
     │─────────────────────────────────────────────>│
     │                                              │
     │ 2. Generate ephemeral key pair (ephA)       │
     │    - ephA_priv, ephA_pub                    │
     │                                              │
     │ 3. Sign ephA_pub with identity key          │
     │    signatureA = Sign(identityA_priv, ephA_pub)│
     │                                              │
     │ 4. Send KEP_INIT                            │
     │─────────────────────────────────────────────>│
     │    { type: "KEP_INIT",                      │
     │      from: aliceId,                         │
     │      to: bobId,                             │
     │      ephPub: ephA_pub (JWK),                │
     │      signature: signatureA,                 │
     │      timestamp, nonce, seq }                │
     │                                              │
     │                                              │ 5. Verify timestamp
     │                                              │ 6. Verify signatureA
     │                                              │    using Alice's identity key
     │                                              │
     │                                              │ 7. Generate ephemeral key pair
     │                                              │    - ephB_priv, ephB_pub
     │                                              │
     │                                              │ 8. Compute shared secret
     │                                              │    shared = ECDH(ephB_priv, ephA_pub)
     │                                              │
     │                                              │ 9. Derive session keys
     │                                              │    rootKey = HKDF(shared, ...)
     │                                              │    sendKey = HKDF(rootKey, ...)
     │                                              │    recvKey = HKDF(rootKey, ...)
     │                                              │
     │                                              │ 10. Generate key confirmation
     │                                              │     keyConf = HMAC(rootKey, "CONFIRM:"+aliceId)
     │                                              │
     │                                              │ 11. Sign ephB_pub
     │                                              │     signatureB = Sign(identityB_priv, ephB_pub)
     │
     │ 12. Receive KEP_RESPONSE                     │
     │<─────────────────────────────────────────────│
     │    { type: "KEP_RESPONSE",                  │
     │      from: bobId,                           │
     │      to: aliceId,                           │
     │      ephPub: ephB_pub (JWK),                │
     │      signature: signatureB,                 │
     │      keyConfirmation: keyConf,              │
     │      timestamp, nonce, seq }                │
     │                                              │
     │ 13. Verify signatureB                        │
     │ 14. Compute shared secret                    │
     │     shared = ECDH(ephA_priv, ephB_pub)      │
     │                                              │
     │ 15. Derive session keys                     │
     │     rootKey = HKDF(shared, ...)            │
     │     sendKey = HKDF(rootKey, ...)            │
     │     recvKey = HKDF(rootKey, ...)            │
     │                                              │
     │ 16. Verify key confirmation                 │
     │     HMAC(rootKey, "CONFIRM:"+aliceId) == keyConf│
     │                                              │
     │ 17. Store session                            │
     │     { sessionId, rootKey, sendKey, recvKey }│
     │                                              │
     │ 18. Session established ✓                    │
     │                                              │
```

### Protocol Steps

1. **Initiator (Alice)**:
   - Fetches Bob's identity public key from server
   - Generates ephemeral ECDH key pair
   - Signs ephemeral public key with identity private key
   - Sends KEP_INIT message

2. **Responder (Bob)**:
   - Verifies timestamp freshness (±2 minutes)
   - Verifies Alice's signature using her identity public key
   - Generates own ephemeral ECDH key pair
   - Computes shared secret: `ECDH(ephB_priv, ephA_pub)`
   - Derives session keys using HKDF
   - Generates key confirmation HMAC
   - Signs own ephemeral public key
   - Sends KEP_RESPONSE message

3. **Initiator (Alice)**:
   - Verifies Bob's signature
   - Computes shared secret: `ECDH(ephA_priv, ephB_pub)`
   - Derives same session keys using HKDF
   - Verifies key confirmation
   - Stores session

---

## Message Flow Diagrams

### KEP_INIT Message Structure

```
┌─────────────────────────────────────────────┐
│  KEP_INIT Message                          │
├─────────────────────────────────────────────┤
│  type: "KEP_INIT"                          │
│  from: <userId>                            │
│  to: <userId>                              │
│  sessionId: <unique session identifier>    │
│  ephPub: {                                 │
│    kty: "EC",                              │
│    crv: "P-256",                           │
│    x: <base64>,                            │
│    y: <base64>                             │
│  }                                         │
│  signature: <base64 signature>             │
│  timestamp: <milliseconds since epoch>     │
│  nonce: <base64 random nonce>              │
│  seq: <sequence number>                    │
└─────────────────────────────────────────────┘
```

### KEP_RESPONSE Message Structure

```
┌─────────────────────────────────────────────┐
│  KEP_RESPONSE Message                      │
├─────────────────────────────────────────────┤
│  type: "KEP_RESPONSE"                      │
│  from: <userId>                            │
│  to: <userId>                              │
│  sessionId: <unique session identifier>    │
│  ephPub: {                                 │
│    kty: "EC",                              │
│    crv: "P-256",                           │
│    x: <base64>,                            │
│    y: <base64>                             │
│  }                                         │
│  signature: <base64 signature>             │
│  keyConfirmation: <base64 HMAC>            │
│  timestamp: <milliseconds since epoch>     │
│  nonce: <base64 random nonce>              │
│  seq: <sequence number>                    │
└─────────────────────────────────────────────┘
```

### WebSocket Event Flow

```
Client A                    Server                    Client B
   │                          │                          │
   │─── kep:init ────────────>│                          │
   │                          │─── kep:init ───────────>│
   │                          │                          │
   │                          │<── kep:response ────────│
   │<── kep:response ─────────│                          │
   │                          │                          │
```

---

## Replay Protection Model

### Protection Mechanisms

1. **Timestamp Validation**
   - Messages must be within ±2 minutes of current time
   - Prevents replay of old messages
   - Rejects messages from the future (clock skew protection)

2. **Nonce Uniqueness**
   - Each message includes a random nonce
   - Nonces are checked for uniqueness per session
   - Prevents exact message replay

3. **Sequence Numbers**
   - Strictly increasing sequence numbers per session
   - Each message must have seq > lastSeq
   - Prevents out-of-order or duplicate message acceptance

4. **Message ID Uniqueness**
   - Server generates unique message IDs: `sessionId:seq:timestamp`
   - Database enforces uniqueness constraint
   - Duplicate message IDs trigger replay detection

### Replay Detection Flow

```
┌─────────────────────────────────────────┐
│  Incoming Message                       │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Check Timestamp                        │
│  if |now - timestamp| > 2min: REJECT   │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Check Sequence Number                  │
│  if seq <= lastSeq: REJECT             │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Check Message ID Uniqueness            │
│  if messageId exists: REJECT            │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Verify Signature                       │
│  if invalid: REJECT + LOG               │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  ACCEPT & Process                       │
└─────────────────────────────────────────┘
```

### Logging

Replay attempts are logged to:
- `logs/replay_attempts.log` - Timestamp/sequence violations
- `logs/invalid_signature.log` - Signature verification failures
- `logs/invalid_kep_message.log` - Malformed messages

---

## HKDF Derivation Chain

### Key Derivation Process

```
┌─────────────────────────────────────────┐
│  Shared Secret (ECDH)                   │
│  256 bits (32 bytes)                     │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  HKDF Step 1: Derive Root Key           │
│  ─────────────────────────────────────  │
│  Input: sharedSecret                    │
│  Salt: "ROOT" (UTF-8)                   │
│  Info: sessionId (UTF-8)                │
│  Length: 256 bits                       │
│  Hash: SHA-256                          │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Root Key                                │
│  256 bits (32 bytes)                     │
└─────────────────────────────────────────┘
        │                    │
        │                    │
        ▼                    ▼
┌──────────────┐    ┌──────────────┐
│ HKDF Step 2a │    │ HKDF Step 2b │
│ Derive Send  │    │ Derive Recv  │
│ Key          │    │ Key          │
│              │    │              │
│ Input:       │    │ Input:       │
│   rootKey    │    │   rootKey    │
│ Salt:        │    │ Salt:        │
│   "SEND"     │    │   "RECV"     │
│ Info:        │    │ Info:        │
│   userId     │    │   peerId     │
│ Length:      │    │ Length:      │
│   256 bits   │    │   256 bits   │
└──────────────┘    └──────────────┘
        │                    │
        ▼                    ▼
┌──────────────┐    ┌──────────────┐
│  Send Key    │    │  Recv Key    │
│  256 bits    │    │  256 bits    │
└──────────────┘    └──────────────┘
```

### Derivation Details

**Root Key:**
```
rootKey = HKDF(
  inputKeyMaterial: sharedSecret,
  salt: "ROOT",
  info: sessionId,
  length: 256 bits,
  hash: SHA-256
)
```

**Send Key (for messages we send):**
```
sendKey = HKDF(
  inputKeyMaterial: rootKey,
  salt: "SEND",
  info: userId,
  length: 256 bits,
  hash: SHA-256
)
```

**Receive Key (for messages we receive):**
```
recvKey = HKDF(
  inputKeyMaterial: rootKey,
  salt: "RECV",
  info: peerId,
  length: 256 bits,
  hash: SHA-256
)
```

### Key Confirmation

Key confirmation uses HMAC to verify both parties derived the same root key:

```
keyConfirmation = HMAC-SHA256(
  key: rootKey,
  message: "CONFIRM:" + peerUserId
)
```

The responder includes this in KEP_RESPONSE, and the initiator verifies it matches their computed value.

---

## Security Considerations

### Strengths

1. **Forward Secrecy**: Ephemeral keys ensure past sessions cannot be decrypted if long-term keys are compromised
2. **Authenticated Key Exchange**: Identity keys sign ephemeral keys, preventing MITM attacks
3. **Key Confirmation**: HMAC verification ensures both parties derived the same keys
4. **Replay Protection**: Multiple layers (timestamp, nonce, sequence) prevent replay attacks
5. **No Server Decryption**: Server only relays messages, cannot decrypt content
6. **Secure Storage**: Private keys encrypted with password-derived keys

### Threat Model

#### Mitigated Threats

- **Man-in-the-Middle (MITM)**: Identity key signatures prevent MITM
- **Replay Attacks**: Timestamp, nonce, and sequence number validation
- **Key Compromise**: Forward secrecy limits damage from key compromise
- **Message Tampering**: Signatures detect tampering
- **XSS Attacks**: IndexedDB storage more secure than localStorage

#### Remaining Risks

1. **Password Weakness**: Weak passwords compromise encrypted private key storage
   - **Mitigation**: Enforce strong password requirements
   - **Future**: Consider hardware security modules (HSM)

2. **Browser Compromise**: Malicious browser extensions can access keys
   - **Mitigation**: User education, extension whitelisting
   - **Future**: Consider WebAuthn for key storage

3. **Side-Channel Attacks**: Timing attacks on crypto operations
   - **Mitigation**: Use constant-time operations where possible
   - **Note**: Web Crypto API provides some protection

4. **Key Rotation**: No automatic key rotation yet (Phase 4)
   - **Future**: Implement periodic key rotation

5. **Denial of Service**: Replay protection logs could fill disk
   - **Mitigation**: Implement log rotation
   - **Future**: Rate limiting on KEP endpoints

### Cryptographic Assumptions

- **ECDH Security**: Assumes P-256 provides 128 bits of security
- **HKDF Security**: Assumes SHA-256 is collision-resistant
- **AES-GCM Security**: Assumes AES-256-GCM provides authenticated encryption
- **PBKDF2 Security**: 100,000 iterations provide reasonable protection against brute force

---

## Limitations & Future Improvements

### Current Limitations

1. **No Key Rotation**: Identity keys and session keys are not rotated
   - **Impact**: Long-lived keys increase compromise risk
   - **Phase 4**: Implement key rotation protocol

2. **No Perfect Forward Secrecy for Sessions**: If root key is compromised, all session messages can be decrypted
   - **Future**: Implement message-level ephemeral keys

3. **Single Device**: Identity keys stored per browser/device
   - **Future**: Multi-device key synchronization

4. **No Key Backup**: Lost password = lost identity key
   - **Future**: Secure key backup mechanism

5. **No Message Encryption**: Phase 3 only establishes keys, doesn't encrypt messages
   - **Phase 4**: Implement message encryption using session keys

6. **Server Trust**: Server could drop messages (but cannot decrypt)
   - **Future**: Message delivery receipts, end-to-end acknowledgments

### Planned Improvements (Phase 4+)

1. **Key Rotation Protocol**
   - Periodic rotation of identity keys
   - Session key rotation during active sessions
   - Secure key update mechanism

2. **Message Encryption**
   - Encrypt messages using session keys
   - Message authentication codes (MACs)
   - Message ordering and delivery guarantees

3. **Multi-Device Support**
   - Key synchronization across devices
   - Device management and revocation

4. **Enhanced Replay Protection**
   - Bloom filters for nonce tracking
   - Distributed nonce validation

5. **Performance Optimizations**
   - Key caching
   - Batch message processing
   - Web Worker crypto operations

---

## Implementation Notes

### Browser Compatibility

- **Web Crypto API**: Requires modern browsers (Chrome 37+, Firefox 34+, Safari 11+)
- **IndexedDB**: Widely supported
- **ES Modules**: Requires modern JavaScript support

### Server Requirements

- **Node.js**: v18+ (for ES modules and crypto)
- **MongoDB**: For public key directory and message metadata
- **WebSocket**: Socket.IO for real-time message relay

### Testing Considerations

- Test with multiple browsers
- Test key generation and storage
- Test key exchange with multiple users
- Test replay protection mechanisms
- Test error handling and edge cases

---

## Conclusion

Phase 3 provides a complete cryptographic foundation for end-to-end encryption. The implementation uses only native Web Crypto API and Node.js crypto, ensuring no external dependencies and maximum transparency.

The system provides:
- ✅ Secure identity key management
- ✅ Authenticated key exchange protocol
- ✅ Session key derivation
- ✅ Replay protection
- ✅ Secure key storage

**Next Steps**: Phase 4 will implement message encryption using the established session keys.

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-30  
**Author**: Phase 3 Implementation

