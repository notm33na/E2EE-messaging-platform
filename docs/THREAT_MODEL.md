# Threat Model (STRIDE)

## Overview

This document outlines the threat model for the E2EE messaging system using the STRIDE framework.

## STRIDE Analysis

### S - Spoofing

**Threat**: Attacker impersonates a legitimate user.

**Mitigation**:
- JWT-based authentication with ECC ES256 signatures
- Identity key signatures on ephemeral keys
- Public key directory for identity verification
- **Status**: ✅ Protected

### T - Tampering

**Threat**: Attacker modifies messages in transit.

**Mitigation**:
- AES-GCM authentication tags (128-bit)
- Digital signatures on key exchange messages
- Sequence numbers prevent message reordering
- **Status**: ✅ Protected

### R - Repudiation

**Threat**: User denies sending a message.

**Mitigation**:
- Digital signatures provide non-repudiation
- Audit logs record all security events
- Message metadata stored with timestamps
- **Status**: ✅ Protected (with logging)

### I - Information Disclosure

**Threat**: Attacker reads plaintext messages.

**Mitigation**:
- End-to-end encryption (AES-256-GCM)
- Server stores only metadata, never plaintext
- Private keys never leave client
- Forward secrecy via key rotation
- **Status**: ✅ Protected

### D - Denial of Service

**Threat**: Attacker prevents legitimate users from accessing the system.

**Mitigation**:
- Rate limiting on authentication endpoints
- Input validation and sanitization
- Replay protection prevents message flooding
- **Status**: ⚠️ Basic protection (can be enhanced)

### E - Elevation of Privilege

**Threat**: Attacker gains unauthorized access to system resources.

**Mitigation**:
- JWT-based authorization
- Protected routes require authentication
- Server never has access to decryption keys
- **Status**: ✅ Protected

## Attack Vectors

### MITM Attack

**Description**: Attacker intercepts and modifies key exchange.

**Vulnerability**: Unsigned ECDH is vulnerable.

**Protection**: Digital signatures on ephemeral keys prevent MITM.

**Status**: ✅ Protected (demonstrated in Phase 7)

### Replay Attack

**Description**: Attacker resends previously captured messages.

**Vulnerability**: Messages without replay protection.

**Protection**: 
- Timestamp freshness checks
- Sequence number monotonicity
- Message ID uniqueness

**Status**: ✅ Protected (demonstrated in Phase 7)

### Key Compromise

**Description**: Attacker gains access to session keys.

**Vulnerability**: Long-lived session keys.

**Protection**: 
- Forward secrecy via key rotation
- Ephemeral keys discarded after use
- Old keys cannot decrypt new messages

**Status**: ✅ Protected (Phase 6)

### Server Compromise

**Description**: Attacker compromises server infrastructure.

**Vulnerability**: Server has access to plaintext.

**Protection**: 
- Server stores only metadata
- Server never sees plaintext
- Server cannot decrypt messages
- Private keys never stored on server

**Status**: ✅ Protected

## Security Assumptions

1. **Client Security**: Browser and device are trusted
2. **Network**: HTTPS/WSS provides transport security
3. **MongoDB Atlas**: Database provider is trusted
4. **Identity Keys**: Long-term identity keys are secure
5. **Password**: User password is strong and secret

## Limitations

1. **Browser Compromise**: Malicious extensions can access keys
2. **XSS Attacks**: Could steal keys from IndexedDB
3. **Key Storage**: Encrypted keys still vulnerable to password theft
4. **Clock Skew**: Timestamp validation assumes synchronized clocks
5. **No Perfect Forward Secrecy**: Initial key exchange uses identity keys

## Future Enhancements

1. **Perfect Forward Secrecy**: Use only ephemeral keys for initial exchange
2. **Key Escrow**: Optional key recovery mechanism
3. **Group Messaging**: Multi-party encryption
4. **Message Deletion**: Secure message deletion protocol
5. **Enhanced DoS Protection**: More sophisticated rate limiting

## Risk Assessment

| Threat | Likelihood | Impact | Risk Level | Mitigation Status |
|--------|-----------|--------|------------|-------------------|
| MITM Attack | Medium | High | Medium | ✅ Protected |
| Replay Attack | Medium | Medium | Medium | ✅ Protected |
| Key Compromise | Low | High | Medium | ✅ Protected |
| Server Compromise | Low | High | Medium | ✅ Protected |
| DoS Attack | Medium | Low | Low | ⚠️ Basic |
| XSS Attack | Medium | High | Medium | ⚠️ Basic |

## Conclusion

The system provides strong protection against most attack vectors, with particular strength in:
- End-to-end encryption
- MITM prevention
- Replay protection
- Forward secrecy

Areas for improvement:
- DoS protection
- XSS mitigation
- Perfect forward secrecy

