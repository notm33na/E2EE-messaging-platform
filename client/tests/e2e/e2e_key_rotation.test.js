/**
 * E2EE Key Rotation Tests
 * 
 * Simulate session expiry + new ephemeral key generation.
 * Ensure new session key differs from old session key.
 * Ensure messages encrypted after rotation decrypt properly.
 */

import { createSession, loadSession, initializeSessionEncryption, rotateEphemeralKeys } from '../../src/crypto/sessionManager.js';
import { generateIdentityKeyPair, storePrivateKeyEncrypted } from '../../src/crypto/identityKeys.js';
import { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKeys, exportPublicKey as exportEphPublicKey, importPublicKey as importEphPublicKey } from '../../src/crypto/ecdh.js';
import { encryptAESGCM, decryptAESGCMToString } from '../../src/crypto/aesGcm.js';
import { clearIndexedDB, generateTestUser, arrayBuffersEqual } from './testHelpers.js';

describe('E2EE Key Rotation Tests', () => {
  let alice, bob;
  let aliceSessionId;
  let aliceOldKeys, bobOldKeys;

  beforeEach(async () => {
    await clearIndexedDB();
    alice = generateTestUser('alice');
    bob = generateTestUser('bob');
    aliceSessionId = `session-${alice.userId}-${bob.userId}`;

    // Set up identity keys
    const aliceIdentityKey = await generateIdentityKeyPair();
    await storePrivateKeyEncrypted(alice.userId, aliceIdentityKey.privateKey, alice.password);
    await initializeSessionEncryption(alice.userId, alice.password);

    const bobIdentityKey = await generateIdentityKeyPair();
    await storePrivateKeyEncrypted(bob.userId, bobIdentityKey.privateKey, bob.password);
    await initializeSessionEncryption(bob.userId, bob.password);

    // Establish initial session
    const aliceEphKey1 = await generateEphemeralKeyPair();
    const bobEphKey1 = await generateEphemeralKeyPair();

    const aliceEphPubJWK1 = await exportEphPublicKey(aliceEphKey1.publicKey);
    const bobEphPubJWK1 = await exportEphPublicKey(bobEphKey1.publicKey);

    const bobEphPubKey1 = await importEphPublicKey(bobEphPubJWK1);
    const aliceSharedSecret1 = await computeSharedSecret(aliceEphKey1.privateKey, bobEphPubKey1);
    aliceOldKeys = await deriveSessionKeys(aliceSharedSecret1, aliceSessionId, alice.userId, bob.userId);

    await createSession(
      aliceSessionId,
      alice.userId,
      bob.userId,
      aliceOldKeys.rootKey,
      aliceOldKeys.sendKey,
      aliceOldKeys.recvKey,
      alice.password
    );

    const aliceEphPubKey1 = await importEphPublicKey(aliceEphPubJWK1);
    const bobSharedSecret1 = await computeSharedSecret(bobEphKey1.privateKey, aliceEphPubKey1);
    bobOldKeys = await deriveSessionKeys(bobSharedSecret1, aliceSessionId, bob.userId, alice.userId);

    await createSession(
      aliceSessionId,
      bob.userId,
      alice.userId,
      bobOldKeys.rootKey,
      bobOldKeys.sendKey,
      bobOldKeys.recvKey,
      bob.password
    );
  });

  afterEach(async () => {
    await clearIndexedDB();
  });

  describe('New Ephemeral Key Generation', () => {
    test('should generate new ephemeral keys for rotation', async () => {
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      expect(aliceEphKey2.privateKey).toBeDefined();
      expect(aliceEphKey2.publicKey).toBeDefined();
      expect(bobEphKey2.privateKey).toBeDefined();
      expect(bobEphKey2.publicKey).toBeDefined();

      // New keys should be different from old keys
      const aliceEphPubJWK1 = await exportEphPublicKey(aliceEphKey2.publicKey);
      const bobEphPubJWK1 = await exportEphPublicKey(bobEphKey2.publicKey);

      expect(aliceEphPubJWK1).toBeDefined();
      expect(bobEphPubJWK1).toBeDefined();
    });
  });

  describe('Session Key Rotation', () => {
    test('should derive new session keys after rotation', async () => {
      // Generate new ephemeral keys
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const aliceEphPubJWK2 = await exportEphPublicKey(aliceEphKey2.publicKey);
      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);

      // Compute new shared secret
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);
      const aliceSharedSecret2 = await computeSharedSecret(aliceEphKey2.privateKey, bobEphPubKey2);
      const aliceNewKeys = await deriveSessionKeys(aliceSharedSecret2, aliceSessionId, alice.userId, bob.userId);

      // New keys should be different from old keys
      expect(arrayBuffersEqual(aliceNewKeys.rootKey, aliceOldKeys.rootKey)).toBe(false);
      expect(arrayBuffersEqual(aliceNewKeys.sendKey, aliceOldKeys.sendKey)).toBe(false);
      expect(arrayBuffersEqual(aliceNewKeys.recvKey, aliceOldKeys.recvKey)).toBe(false);
    });

    test('should rotate keys using rotateEphemeralKeys', async () => {
      // Generate new ephemeral keys
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const aliceEphPubJWK2 = await exportEphPublicKey(aliceEphKey2.publicKey);
      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);

      // Alice rotates keys
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);
      const aliceNewKeys = await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      expect(aliceNewKeys).toBeDefined();
      expect(aliceNewKeys.rootKey).toBeDefined();
      expect(aliceNewKeys.sendKey).toBeDefined();
      expect(aliceNewKeys.recvKey).toBeDefined();

      // Verify new keys are different
      expect(arrayBuffersEqual(aliceNewKeys.rootKey, aliceOldKeys.rootKey)).toBe(false);
      expect(arrayBuffersEqual(aliceNewKeys.sendKey, aliceOldKeys.sendKey)).toBe(false);
      expect(arrayBuffersEqual(aliceNewKeys.recvKey, aliceOldKeys.recvKey)).toBe(false);
    });

    test('should update session with new keys after rotation', async () => {
      // Generate new ephemeral keys
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);

      // Rotate keys
      const aliceNewKeys = await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      // Load session and verify new keys
      const session = await loadSession(aliceSessionId, alice.userId, alice.password);
      expect(arrayBuffersEqual(session.rootKey, aliceNewKeys.rootKey)).toBe(true);
      expect(arrayBuffersEqual(session.sendKey, aliceNewKeys.sendKey)).toBe(true);
      expect(arrayBuffersEqual(session.recvKey, aliceNewKeys.recvKey)).toBe(true);
    });
  });

  describe('Message Encryption After Rotation', () => {
    test('should encrypt messages with new keys after rotation', async () => {
      // Rotate keys
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);

      await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      // Encrypt message with new keys
      const plaintext = 'Message after rotation';
      const session = await loadSession(aliceSessionId, alice.userId, alice.password);
      const { ciphertext, iv, authTag } = await encryptAESGCM(session.sendKey, plaintext);

      expect(ciphertext).toBeDefined();
      expect(iv).toBeDefined();
      expect(authTag).toBeDefined();
    });

    test('should decrypt messages encrypted after rotation', async () => {
      // Rotate keys on both sides
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const aliceEphPubJWK2 = await exportEphPublicKey(aliceEphKey2.publicKey);
      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);

      // Alice rotates
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);
      await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      // Bob rotates
      const aliceEphPubKey2 = await importEphPublicKey(aliceEphPubJWK2);
      await rotateEphemeralKeys(
        aliceSessionId,
        bob.userId,
        alice.userId,
        aliceEphPubKey2,
        bobEphKey2.privateKey
      );

      // Alice encrypts message with new sendKey
      const plaintext = 'Message after rotation';
      const aliceSession = await loadSession(aliceSessionId, alice.userId, alice.password);
      const { ciphertext, iv, authTag } = await encryptAESGCM(aliceSession.sendKey, plaintext);

      // Bob decrypts with new recvKey
      const bobSession = await loadSession(aliceSessionId, bob.userId, bob.password);
      const decrypted = await decryptAESGCMToString(bobSession.recvKey, iv, ciphertext, authTag);

      expect(decrypted).toBe(plaintext);
    });

    test('should NOT decrypt old messages with new keys (forward secrecy)', async () => {
      // Encrypt message with old keys
      const plaintext = 'Message before rotation';
      const { ciphertext, iv, authTag } = await encryptAESGCM(aliceOldKeys.sendKey, plaintext);

      // Rotate keys
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);

      await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      // Try to decrypt old message with new keys (should fail)
      const session = await loadSession(aliceSessionId, bob.userId, bob.password);
      await expect(
        decryptAESGCMToString(session.recvKey, iv, ciphertext, authTag)
      ).rejects.toThrow();
    });

    test('should NOT decrypt new messages with old keys', async () => {
      // Rotate keys
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);

      await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      // Encrypt message with new keys
      const plaintext = 'Message after rotation';
      const session = await loadSession(aliceSessionId, alice.userId, alice.password);
      const { ciphertext, iv, authTag } = await encryptAESGCM(session.sendKey, plaintext);

      // Try to decrypt with old keys (should fail)
      await expect(
        decryptAESGCMToString(bobOldKeys.recvKey, iv, ciphertext, authTag)
      ).rejects.toThrow();
    });
  });

  describe('Multiple Rotations', () => {
    test('should handle multiple key rotations', async () => {
      // First rotation
      const aliceEphKey2 = await generateEphemeralKeyPair();
      const bobEphKey2 = await generateEphemeralKeyPair();

      const bobEphPubJWK2 = await exportEphPublicKey(bobEphKey2.publicKey);
      const bobEphPubKey2 = await importEphPublicKey(bobEphPubJWK2);

      const keys1 = await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey2,
        aliceEphKey2.privateKey
      );

      // Second rotation
      const aliceEphKey3 = await generateEphemeralKeyPair();
      const bobEphKey3 = await generateEphemeralKeyPair();

      const bobEphPubJWK3 = await exportEphPublicKey(bobEphKey3.publicKey);
      const bobEphPubKey3 = await importEphPublicKey(bobEphPubJWK3);

      const keys2 = await rotateEphemeralKeys(
        aliceSessionId,
        alice.userId,
        bob.userId,
        bobEphPubKey3,
        aliceEphKey3.privateKey
      );

      // All keys should be different
      expect(arrayBuffersEqual(keys1.rootKey, keys2.rootKey)).toBe(false);
      expect(arrayBuffersEqual(keys1.sendKey, keys2.sendKey)).toBe(false);
      expect(arrayBuffersEqual(keys1.recvKey, keys2.recvKey)).toBe(false);
      expect(arrayBuffersEqual(keys2.rootKey, aliceOldKeys.rootKey)).toBe(false);
    });
  });
});
