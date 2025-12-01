# E2EE Test Suite

This directory contains comprehensive end-to-end encryption tests for the React frontend application.

## Test Files

1. **e2e_key_generation.test.js**
   - Tests identity key creation (ECDSA P-256)
   - Tests ephemeral key creation (ECDH P-256)
   - Tests password-derived encryption for private key storage
   - Tests retrieval from IndexedDB

2. **e2e_session_establishment.test.js**
   - Simulates two users (Alice/Bob)
   - Generates identity keys for both
   - Generates ephemeral keys for both
   - Runs the frontend portion of the custom ECDH + HKDF flow
   - Ensures same session key derived on both ends
   - Ensures different IVs per message

3. **e2e_message_encrypt_decrypt.test.js**
   - Encrypts a text message using AES-256-GCM
   - Decrypts it using the derived session key
   - Verifies authTag / integrity protection
   - Ensures plaintext never appears in logs

4. **e2e_message_flow.test.js**
   - Simulates sending a message through the React messaging UI
   - Ensures:
     - encryption occurs before send()
     - ciphertext only transmitted
     - decrypted message rendered correctly on receiver UI
     - metadata created (timestamp, seq, nonce)

5. **e2e_file_encryption.test.js**
   - Encrypts a test file with AES-GCM
   - Breaks into chunks (256 KB chunks)
   - Ensures chunk ciphertext & IV only are passed to backend
   - Decrypts file and verifies integrity

6. **e2e_key_rotation.test.js**
   - Simulates session expiry + new ephemeral key generation
   - Ensures new session key differs from old session key
   - Ensures messages encrypted after rotation decrypt properly

## Test Helpers

**testHelpers.js** provides utilities for:
- Test user setup (Alice/Bob)
- IndexedDB cleanup
- Crypto key comparison utilities
- Test data generators
- Plaintext detection (security checks)

## Running Tests

```bash
npm run test:e2e
```

## Test Configuration

- **Framework**: Jest + React Testing Library
- **Crypto API**: Web Crypto API (via @peculiar/webcrypto polyfill)
- **Storage**: fake-indexeddb (for IndexedDB testing)
- **Timeout**: 30 seconds (for crypto operations)
- **No Crypto Mocking**: All crypto operations use real Web Crypto API

## Important Notes

- **No Plaintext Logging**: Tests verify that plaintext never appears in logs or transmitted data
- **Real Crypto Operations**: All cryptographic operations use the actual Web Crypto API (no mocking)
- **Network Mocking Only**: Only network calls are mocked, not crypto operations
- **IndexedDB Testing**: Uses fake-indexeddb to test real IndexedDB operations

## Test Coverage

The test suite validates:
- ✅ Key generation (identity and ephemeral)
- ✅ Key storage and retrieval
- ✅ Session establishment (ECDH + HKDF)
- ✅ Message encryption/decryption
- ✅ File encryption/decryption
- ✅ Key rotation
- ✅ Integrity protection (authTag verification)
- ✅ Replay protection (sequence numbers, timestamps)
- ✅ Security properties (no plaintext exposure)

