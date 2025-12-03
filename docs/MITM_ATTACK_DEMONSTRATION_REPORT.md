# MITM Attack Demonstration Report

## Executive Summary

This report demonstrates a Man-in-the-Middle (MITM) attack on the Diffie-Hellman key exchange protocol, showing:

1. **How MITM successfully breaks DH without signatures** - Demonstrating the vulnerability
2. **How digital signatures prevent MITM** - Demonstrating the mitigation
3. **Replay protection mechanisms** - Nonces, timestamps, and sequence numbers

All attacks are demonstrated with detailed packet captures, logs, and explanations.

---

## Table of Contents

1. [Attack Scenario 1: Breaking Unsigned DH](#attack-scenario-1-breaking-unsigned-dh)
2. [Attack Scenario 2: Digital Signatures Prevent MITM](#attack-scenario-2-digital-signatures-prevent-mitm)
3. [Replay Protection Mechanisms](#replay-protection-mechanisms)
4. [Evidence and Logs](#evidence-and-logs)
5. [Conclusion](#conclusion)

---

## Attack Scenario 1: Breaking Unsigned DH

### Overview

This attack demonstrates the vulnerability when ephemeral keys in the Diffie-Hellman key exchange are **not signed** with identity keys.

### Attack Flow

```
1. Alice generates ephemeral key pair (EK_priv_A, EK_pub_A)
2. Alice sends KEP_INIT with EK_pub_A (UNSIGNED) → Bob
3. [ATTACKER INTERCEPTS]
   - Attacker receives EK_pub_A
   - Attacker generates own key pair (EK_priv_ATTACKER, EK_pub_ATTACKER)
   - Attacker replaces EK_pub_A with EK_pub_ATTACKER
   - Attacker sends modified KEP_INIT → Bob
4. Bob receives EK_pub_ATTACKER (thinks it's from Alice)
5. Bob computes: sharedSecret_BOB = ECDH(EK_priv_B, EK_pub_ATTACKER)
6. Attacker computes: sharedSecret_ATTACKER_BOB = ECDH(EK_priv_ATTACKER, EK_pub_B)
7. [ATTACKER INTERCEPTS Bob's response]
   - Attacker receives EK_pub_B (UNSIGNED)
   - Attacker replaces EK_pub_B with EK_pub_ATTACKER
   - Attacker sends modified KEP_RESPONSE → Alice
8. Alice receives EK_pub_ATTACKER (thinks it's from Bob)
9. Alice computes: sharedSecret_ALICE = ECDH(EK_priv_A, EK_pub_ATTACKER)
10. Attacker computes: sharedSecret_ATTACKER_ALICE = ECDH(EK_priv_ATTACKER, EK_pub_A)

RESULT:
- Alice has shared secret with ATTACKER (not Bob)
- Bob has shared secret with ATTACKER (not Alice)
- Attacker has shared secrets with both Alice and Bob
- Attacker can decrypt all messages between Alice and Bob
```

### Why This Attack Succeeds

1. **No Authentication**: Ephemeral keys are not authenticated
2. **No Signature Verification**: Bob cannot verify that EK_pub_A actually came from Alice
3. **Key Substitution**: Attacker can freely replace keys without detection
4. **Separate Sessions**: Attacker establishes separate sessions with each party

### Packet Capture Evidence

```
Packet #1: ALICE->ATTACKER | KEP_INIT
  - Session ID: session-123
  - From: aliceId
  - To: bobId
  - Ephemeral Public Key: EK_pub_A (JWK)
  - Has Signature: false
  - Description: Alice sends KEP_INIT (UNSIGNED) - intercepted by attacker

Packet #2: ATTACKER | KEY_GENERATION
  - Attacker generates own ephemeral key pair
  - EK_pub_ATTACKER created

Packet #3: ATTACKER->BOB | KEP_INIT_MODIFIED
  - Original Key: EK_pub_A
  - Replaced With: EK_pub_ATTACKER
  - Description: Key substitution attack - Bob receives attacker's key

Packet #4: BOB | SHARED_SECRET_COMPUTED
  - Computed With: ATTACKER
  - Description: Bob computes shared secret with attacker (thinks it's Alice)

Packet #5: ATTACKER | SHARED_SECRET_COMPUTED
  - Computed With: BOB
  - Description: Attacker has shared secret with Bob

[... similar packets for Bob's response ...]

Packet #N: ATTACKER | ATTACK_SUCCESS
  - Attack Successful: true
  - Attacker Can Decrypt: true
  - Alice Compromised: true
  - Bob Compromised: true
  - Reason: No signature verification - unsigned ephemeral keys
```

### Attack Result

- ✅ **Attack Successful**: YES
- ✅ **Attacker Can Decrypt**: YES
- ✅ **Alice Compromised**: YES
- ✅ **Bob Compromised**: YES

---

## Attack Scenario 2: Digital Signatures Prevent MITM

### Overview

This attack demonstrates how **digital signatures** prevent the MITM attack by authenticating ephemeral keys.

### Attack Flow (Blocked)

```
1. Alice generates ephemeral key pair (EK_priv_A, EK_pub_A)
2. Alice signs EK_pub_A with IK_priv_A (identity private key)
3. Alice sends KEP_INIT with EK_pub_A + signature → Bob
4. [ATTACKER INTERCEPTS]
   - Attacker receives EK_pub_A + signature
   - Attacker generates own key pair (EK_priv_ATTACKER, EK_pub_ATTACKER)
   - Attacker tries to replace EK_pub_A with EK_pub_ATTACKER
   - Attacker sends modified KEP_INIT (with original signature) → Bob
5. Bob receives EK_pub_ATTACKER + signature
6. Bob fetches Alice's identity public key (IK_pub_A) from server
7. Bob verifies signature:
   - Computes: verify(IK_pub_A, signature, EK_pub_ATTACKER)
   - Result: FALSE (signature doesn't match modified key)
8. Bob REJECTS the message
9. Attack BLOCKED
```

### Why This Attack Fails

1. **Digital Signatures**: Ephemeral keys are signed with identity keys
2. **Signature Verification**: Bob verifies signature before accepting key
3. **Key Substitution Detected**: Modified key doesn't match signature
4. **Attack Blocked**: Message rejected, no session established

### Packet Capture Evidence

```
Packet #1: ALICE->ATTACKER | KEP_INIT_SIGNED
  - Session ID: session-123-signed
  - From: aliceId
  - To: bobId
  - Ephemeral Public Key: EK_pub_A (JWK)
  - Signature: [base64 signature]
  - Has Signature: true
  - Description: Alice sends KEP_INIT (SIGNED) - intercepted by attacker

Packet #2: ATTACKER | KEY_GENERATION
  - Attacker generates own ephemeral key pair
  - EK_pub_ATTACKER created

Packet #3: ATTACKER->BOB | KEP_INIT_MODIFIED
  - Original Key: EK_pub_A
  - Replaced With: EK_pub_ATTACKER
  - Original Signature: [original signature]
  - Description: Attacker attempts to replace Alice's key with own key

Packet #4: BOB | SIGNATURE_VERIFICATION
  - Signature Valid: false
  - Expected Result: false
  - Description: Bob verifies signature on modified key - VERIFICATION FAILS

Packet #5: BOB | ATTACK_BLOCKED
  - Attack Successful: false
  - Reason: Signature verification failed - key was modified
  - Bob Rejected: true
  - Description: MITM ATTACK BLOCKED - Signature verification prevents key substitution
```

### Attack Result

- ❌ **Attack Successful**: NO
- ❌ **Attacker Can Decrypt**: NO
- ✅ **Signature Verification**: BLOCKED ATTACK
- ✅ **Attack Prevented**: YES

---

## Replay Protection Mechanisms

The system implements **multiple layers** of replay protection:

### 1. Nonces

**Purpose**: Ensure message uniqueness at the cryptographic level

**Implementation**:
- Each message includes a 16-byte random nonce
- Nonces are base64-encoded in message envelopes
- Client-side: Nonce hashes stored in IndexedDB (last 200 per session)
- Server-side: Nonce hashes stored in MongoDB with unique index

**Validation**:
```javascript
// Client-side
const nonceHash = SHA-256(nonceBytes);
if (isNonceUsed(sessionId, nonceHash)) {
  reject("Duplicate nonce for this session");
}

// Server-side
const nonceHash = SHA-256(nonceBytes);
if (await isNonceHashUsed(sessionId, nonceHash)) {
  reject("REPLAY_REJECT: Duplicate nonce detected");
}
```

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-009 and REPLAY-010

### 2. Timestamps

**Purpose**: Ensure message freshness and prevent replay of old messages

**Implementation**:
- Each message includes a timestamp (milliseconds since epoch)
- Acceptance window: ±2 minutes (120,000 ms)
- Messages older than 2 minutes are rejected
- Messages from future (>2 minutes) are rejected

**Validation**:
```javascript
const now = Date.now();
const age = now - message.timestamp;
if (Math.abs(age) > 120000) {
  reject("Timestamp out of validity window");
}
```

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-001, REPLAY-002, REPLAY-003

### 3. Sequence Numbers

**Purpose**: Ensure strict ordering and prevent replay of previous messages

**Implementation**:
- Each message includes a sequence number (`seq`)
- Sequence numbers must be **strictly increasing** per session
- Client tracks `lastSeq` in IndexedDB per session
- Messages with `seq <= lastSeq` are rejected

**Validation**:
```javascript
const lastSeq = await getLastSeq(sessionId);
if (envelope.seq <= lastSeq) {
  reject("Sequence number must be strictly increasing");
}
// After successful processing:
await updateLastSeq(sessionId, envelope.seq);
```

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-004, REPLAY-005, REPLAY-006

### 4. Message ID Uniqueness

**Purpose**: Server-side deduplication and replay detection

**Implementation**:
- Server generates `messageId = sessionId:seq:timestamp`
- MongoDB enforces unique index on `messageId`
- Duplicate messageIds are rejected at database level

**Validation**:
```javascript
const messageId = `${sessionId}:${seq}:${timestamp}`;
const existing = await MessageMeta.findOne({ messageId });
if (existing) {
  reject("Duplicate messageId detected");
}
```

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-007, REPLAY-008

### Multi-Layer Protection

Messages are validated through **multiple layers**:

1. **Structure Validation**: Check required fields exist
2. **Timestamp Validation**: Verify freshness (±2 minutes)
3. **Sequence Validation**: Verify strictly increasing sequence
4. **Nonce Validation**: Verify nonce uniqueness
5. **Message ID Validation**: Verify server-side uniqueness
6. **Decryption**: Only if all checks pass

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-011, REPLAY-012, REPLAY-013

---

## Evidence and Logs

### Packet Captures

Packet captures are available in the following formats:

1. **Text Format** (Wireshark-style):
   - `logs/mitm_attack1_packets.txt`
   - `logs/mitm_attack2_packets.txt`

2. **JSON Format**:
   - `logs/mitm_attack1_packets.json`
   - `logs/mitm_attack2_packets.json`

### Server Logs

Server logs capture replay attempts and security events:

- `logs/replay_attempts.log` - All replay attempts with reasons
- `logs/invalid_signature.log` - Signature verification failures
- `logs/invalid_kep_message.log` - Invalid KEP messages

### Client Logs

Client logs stored in IndexedDB:

- `clientLogs` store - Replay attempts, signature failures, etc.
- Can be synced to server for analysis

### Running the Demonstration

To run the MITM attack demonstration:

```javascript
import { runMITMDemonstration } from './src/attacks/mitmDemonstration.js';

const results = await runMITMDemonstration('aliceId', 'bobId', 'password');
console.log(results);
```

This will:
1. Run Attack 1 (unsigned DH) - demonstrates vulnerability
2. Run Attack 2 (signed DH) - demonstrates protection
3. Generate packet captures and logs
4. Export evidence for analysis

---

## Conclusion

### Key Findings

1. **Unsigned DH is Vulnerable**: Without digital signatures, MITM attacks can successfully intercept and replace ephemeral keys, allowing attackers to decrypt all messages.

2. **Digital Signatures Prevent MITM**: When ephemeral keys are signed with identity keys and signatures are verified, key substitution attacks are detected and blocked.

3. **Replay Protection is Robust**: Multiple layers (nonces, timestamps, sequence numbers, message IDs) ensure comprehensive replay protection.

### Security Recommendations

✅ **Implemented**:
- Digital signatures on ephemeral keys (ECDSA-SHA256)
- Signature verification before accepting keys
- Key confirmation HMAC
- Timestamp validation (±2 minutes)
- Nonce uniqueness (client and server)
- Sequence number enforcement
- Message ID uniqueness

✅ **Best Practices**:
- Identity keys stored securely (encrypted with password)
- Ephemeral keys discarded after use (forward secrecy)
- Comprehensive logging of security events
- Multi-layer validation before message processing

### Attack Demonstration Summary

| Attack Scenario | Signature Protection | Attack Result | Attacker Can Decrypt |
|----------------|---------------------|---------------|---------------------|
| Unsigned DH    | ❌ No               | ✅ Success    | ✅ Yes              |
| Signed DH      | ✅ Yes              | ❌ Blocked    | ❌ No               |

**Conclusion**: Digital signatures effectively prevent MITM attacks on the Diffie-Hellman key exchange protocol.

---

## Appendix: Code References

### Attacker Script
- `client/src/attacks/mitmAttacker.js` - MITM attack implementation
- `client/src/attacks/mitmDemonstration.js` - Demonstration runner

### Signature Implementation
- `client/src/crypto/signatures.js` - Signature operations
- `client/src/crypto/messages.js` - KEP message building/validation

### Replay Protection
- `client/src/crypto/messageFlow.js` - Client-side validation
- `server/src/utils/replayProtection.js` - Server-side validation
- `server/src/controllers/messages.controller.js` - Message handling

### Test Cases
- `REPLAY_PROTECTION_TESTCASE_SUITE.md` - Comprehensive test cases
- `server/tests/mitm_simulation.test.js` - MITM defense tests

---

**Report Generated**: [Current Date]
**System Version**: [Version]
**Demonstration Status**: ✅ Complete

