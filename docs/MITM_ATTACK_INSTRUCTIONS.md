# MITM Attack Demonstration - Instructions

## Overview

This document provides instructions for running the MITM attack demonstration, which shows:

1. **How MITM successfully breaks DH without signatures**
2. **How digital signatures prevent MITM in the final system**
3. **Replay protection mechanisms** (Nonces, Timestamps, Sequence Numbers)

---

## Quick Start

### Option 1: Run the Demonstration Script

```bash
# From the project root
# First, install dependencies if needed
npm install

# Then run the demonstration
node scripts/run-mitm-demonstration.js
```

This will:
- Run both attack scenarios
- Generate packet captures (text and JSON)
- Generate demonstration report
- Save all evidence to `logs/` directory

### Option 2: Run Tests

```bash
# From the client directory
cd client
npm run test:attacks -- mitm_attack_demonstration.test.js

# Or run all attack tests
npm run test:attacks
```

### Option 3: Use in Browser Console

```javascript
// Import the demonstration function
import { runMITMDemonstration } from './src/attacks/mitmDemonstration.js';

// Run the demonstration
const results = await runMITMDemonstration('aliceId', 'bobId', 'password');
console.log(results);
```

---

## Files Created

After running the demonstration, the following files will be created in the `logs/` directory:

### Packet Captures
- `mitm_attack1_packets.txt` - Attack 1 packet log (Wireshark-style text)
- `mitm_attack1_packets.json` - Attack 1 packet log (JSON)
- `mitm_attack2_packets.txt` - Attack 2 packet log (Wireshark-style text)
- `mitm_attack2_packets.json` - Attack 2 packet log (JSON)

### Reports
- `mitm_demonstration_report.json` - Complete demonstration results (JSON)
- `mitm_demonstration_summary.txt` - Human-readable summary

### Server Logs
- `replay_attempts.log` - All replay attempts (if server is running)
- `invalid_signature.log` - Signature verification failures
- `invalid_kep_message.log` - Invalid KEP messages

---

## Attack Scenarios

### Attack 1: Breaking Unsigned DH

**Purpose**: Demonstrate vulnerability when ephemeral keys are not signed

**What Happens**:
1. Alice sends KEP_INIT with unsigned ephemeral key
2. Attacker intercepts and replaces key with own key
3. Bob receives attacker's key (thinks it's from Alice)
4. Attacker establishes separate sessions with both parties
5. **Attack succeeds** - Attacker can decrypt all messages

**Expected Result**: ✅ Attack Successful

**Evidence**: See `logs/mitm_attack1_packets.txt` and `logs/mitm_attack1_packets.json`

### Attack 2: Digital Signatures Prevent MITM

**Purpose**: Demonstrate how signatures prevent the attack

**What Happens**:
1. Alice sends KEP_INIT with signed ephemeral key
2. Attacker intercepts and tries to replace key
3. Bob verifies signature - **VERIFICATION FAILS**
4. Bob rejects the message
5. **Attack blocked** - No session established

**Expected Result**: ❌ Attack Blocked

**Evidence**: See `logs/mitm_attack2_packets.txt` and `logs/mitm_attack2_packets.json`

---

## Replay Protection Mechanisms

The system implements **all mandatory replay protection mechanisms**:

### 1. Nonces ✅
- **Purpose**: Ensure message uniqueness
- **Implementation**: 16-byte random nonce per message
- **Validation**: Client and server track nonce hashes
- **Rejection**: Duplicate nonces rejected immediately

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-009, REPLAY-010

### 2. Timestamps ✅
- **Purpose**: Ensure message freshness
- **Implementation**: Timestamp in each message
- **Validation**: ±2 minute acceptance window
- **Rejection**: Stale or future messages rejected

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-001, REPLAY-002, REPLAY-003

### 3. Sequence Numbers ✅
- **Purpose**: Ensure strict ordering
- **Implementation**: Sequence number per message
- **Validation**: Must be strictly increasing
- **Rejection**: Duplicate or decreasing sequences rejected

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-004, REPLAY-005, REPLAY-006

### 4. Message ID Uniqueness ✅
- **Purpose**: Server-side deduplication
- **Implementation**: `messageId = sessionId:seq:timestamp`
- **Validation**: MongoDB unique index
- **Rejection**: Duplicate messageIds rejected at database level

**Evidence**: See `REPLAY_PROTECTION_TESTCASE_SUITE.md` test cases REPLAY-007, REPLAY-008

---

## Verifying Replay Protection

### Test Replay Rejection

To verify replay protection is working:

1. **Send a message** from Alice to Bob
2. **Capture the message envelope** (from browser console or network tab)
3. **Attempt to replay** the same message
4. **Verify rejection** - Message should be rejected with appropriate reason

### Expected Rejection Reasons

- **Timestamp**: "Timestamp out of validity window"
- **Sequence**: "Sequence number must be strictly increasing"
- **Nonce**: "Duplicate nonce for this session" or "REPLAY_REJECT: Duplicate nonce detected"
- **Message ID**: "Duplicate messageId detected"

### Logs to Check

- **Client-side**: Check browser console for rejection messages
- **Server-side**: Check `logs/replay_attempts.log` for logged attempts
- **Database**: Check MongoDB for duplicate messageId errors

---

## Code References

### Attacker Scripts
- `client/src/attacks/mitmAttacker.js` - MITM attack implementation
- `client/src/attacks/mitmDemonstration.js` - Demonstration runner

### Signature Implementation
- `client/src/crypto/signatures.js` - Signature operations
- `client/src/crypto/messages.js` - KEP message building/validation

### Replay Protection
- `client/src/crypto/messageFlow.js` - Client-side validation
- `server/src/utils/replayProtection.js` - Server-side validation
- `server/src/controllers/messages.controller.js` - Message handling

### Tests
- `client/tests/mitm_attack_demonstration.test.js` - MITM demonstration tests
- `server/tests/mitm_simulation.test.js` - MITM defense tests

---

## Documentation

- **MITM_ATTACK_DEMONSTRATION_REPORT.md** - Comprehensive attack demonstration report
- **MITM_ATTACK_INSTRUCTIONS.md** - This file (instructions)
- **REPLAY_PROTECTION_TESTCASE_SUITE.md** - Replay protection test cases

---

## Screenshots and Evidence

To capture screenshots:

1. **Run the demonstration** using the script
2. **Open packet logs** in a text editor
3. **Take screenshots** of:
   - Packet capture showing attack flow
   - Signature verification failure
   - Replay rejection logs
   - Browser console showing rejections

### Recommended Screenshots

1. **Attack 1 Success**: Packet log showing successful key substitution
2. **Attack 2 Blocked**: Packet log showing signature verification failure
3. **Replay Rejection**: Server log showing replay attempt rejection
4. **Multi-layer Protection**: Client console showing validation layers

---

## Troubleshooting

### Issue: Demonstration script fails

**Solution**: Ensure you're running from the project root and all dependencies are installed:
```bash
npm install
cd client && npm install
```

### Issue: Packet logs not generated

**Solution**: Check that the `logs/` directory exists and is writable:
```bash
mkdir -p logs
chmod 755 logs
```

### Issue: Tests fail

**Solution**: Ensure test environment is set up correctly:
```bash
cd client
npm test -- --setupFilesAfterEnv=./jest.setup.cjs
```

---

## Summary

✅ **MITM Attack Script**: Created (`mitmAttacker.js`)
✅ **Demonstration Runner**: Created (`mitmDemonstration.js`)
✅ **Evidence Capture**: Packet logs in text and JSON formats
✅ **Comprehensive Report**: Detailed analysis and explanations
✅ **Replay Protection**: All mechanisms implemented and documented
✅ **Tests**: Complete test suite for verification

**All requirements met!**

---

**Last Updated**: [Current Date]
**Status**: ✅ Complete

