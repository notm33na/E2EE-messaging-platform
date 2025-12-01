/**
 * E2EE Session Establishment Tests
 * 
 * Simulates two users (Alice/Bob), generates identity keys for both,
 * generates ephemeral keys for both, runs the frontend portion of the
 * custom ECDH + HKDF flow, ensures same session key derived on both ends,
 * and ensures different IVs per message.
 */

import { generateIdentityKeyPair, storePrivateKeyEncrypted, loadPrivateKey, exportPublicKey } from '../../src/crypto/identityKeys.js';
import { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKeys, exportPublicKey as exportEphPublicKey, importPublicKey as importEphPublicKey } from '../../src/crypto/ecdh.js';
import { createSession, loadSession, initializeSessionEncryption } from '../../src/crypto/sessionManager.js';
import { clearIndexedDB, generateTestUser, arrayBuffersEqual } from './testHelpers.js';

describe('E2EE Session Establishment Tests', () => {
  let alice, bob;
  let aliceIdentityKey, bobIdentityKey;

  beforeEach(async () => {
    await clearIndexedDB();
    alice = generateTestUser('alice');
    bob = generateTestUser('bob');
  });

  afterEach(async () => {
    await clearIndexedDB();
  });

  describe('Two-User Key Exchange Simulation', () => {
    test('should generate identity keys for both users', async () => {
      aliceIdentityKey = await generateIdentityKeyPair();
      bobIdentityKey = await generateIdentityKeyPair();

      expect(aliceIdentityKey.privateKey).toBeDefined();
      expect(aliceIdentityKey.publicKey).toBeDefined();
      expect(bobIdentityKey.privateKey).toBeDefined();
      expect(bobIdentityKey.publicKey).toBeDefined();

      // Store keys
      await storePrivateKeyEncrypted(alice.userId, aliceIdentityKey.privateKey, alice.password);
      await storePrivateKeyEncrypted(bob.userId, bobIdentityKey.privateKey, bob.password);
    });

    test('should generate ephemeral keys for both users', async () => {
      const aliceEphKey = await generateEphemeralKeyPair();
      const bobEphKey = await generateEphemeralKeyPair();

      expect(aliceEphKey.privateKey).toBeDefined();
      expect(aliceEphKey.publicKey).toBeDefined();
      expect(bobEphKey.privateKey).toBeDefined();
      expect(bobEphKey.publicKey).toBeDefined();
    });

    test('should compute same shared secret from both sides', async () => {
      // Alice generates ephemeral key pair
      const aliceEphKey = await generateEphemeralKeyPair();
      const aliceEphPubJWK = await exportEphPublicKey(aliceEphKey.publicKey);

      // Bob generates ephemeral key pair
      const bobEphKey = await generateEphemeralKeyPair();
      const bobEphPubJWK = await exportEphPublicKey(bobEphKey.publicKey);

      // Alice computes shared secret using her private key and Bob's public key
      const bobEphPubKey = await importEphPublicKey(bobEphPubJWK);
      const aliceSharedSecret = await computeSharedSecret(aliceEphKey.privateKey, bobEphPubKey);

      // Bob computes shared secret using his private key and Alice's public key
      const aliceEphPubKey = await importEphPublicKey(aliceEphPubJWK);
      const bobSharedSecret = await computeSharedSecret(bobEphKey.privateKey, aliceEphPubKey);

      // Both should produce the same shared secret
      expect(arrayBuffersEqual(aliceSharedSecret, bobSharedSecret)).toBe(true);
      expect(aliceSharedSecret.byteLength).toBe(32); // 256 bits = 32 bytes
    });

    test('should derive same session keys on both ends using HKDF', async () => {
      // Generate ephemeral keys
      const aliceEphKey = await generateEphemeralKeyPair();
      const bobEphKey = await generateEphemeralKeyPair();

      // Exchange public keys
      const aliceEphPubJWK = await exportEphPublicKey(aliceEphKey.publicKey);
      const bobEphPubJWK = await exportEphPublicKey(bobEphKey.publicKey);

      // Compute shared secrets
      const bobEphPubKey = await importEphPublicKey(bobEphPubJWK);
      const aliceSharedSecret = await computeSharedSecret(aliceEphKey.privateKey, bobEphPubKey);

      const aliceEphPubKey = await importEphPublicKey(aliceEphPubJWK);
      const bobSharedSecret = await computeSharedSecret(bobEphKey.privateKey, aliceEphPubKey);

      // Verify shared secrets are equal
      expect(arrayBuffersEqual(aliceSharedSecret, bobSharedSecret)).toBe(true);

      // Derive session keys on both sides
      const sessionId = `session-${alice.userId}-${bob.userId}`;
      const aliceKeys = await deriveSessionKeys(aliceSharedSecret, sessionId, alice.userId, bob.userId);
      const bobKeys = await deriveSessionKeys(bobSharedSecret, sessionId, bob.userId, alice.userId);

      // Note: sendKey and recvKey are swapped between Alice and Bob
      // Alice's sendKey should equal Bob's recvKey
      // Alice's recvKey should equal Bob's sendKey
      expect(arrayBuffersEqual(aliceKeys.sendKey, bobKeys.recvKey)).toBe(true);
      expect(arrayBuffersEqual(aliceKeys.recvKey, bobKeys.sendKey)).toBe(true);
      expect(arrayBuffersEqual(aliceKeys.rootKey, bobKeys.rootKey)).toBe(true);

      // Verify key lengths
      expect(aliceKeys.rootKey.byteLength).toBe(32); // 256 bits
      expect(aliceKeys.sendKey.byteLength).toBe(32);
      expect(aliceKeys.recvKey.byteLength).toBe(32);
    });

    test('should create and store session with encrypted keys', async () => {
      // Generate identity keys
      aliceIdentityKey = await generateIdentityKeyPair();
      await storePrivateKeyEncrypted(alice.userId, aliceIdentityKey.privateKey, alice.password);

      // Initialize session encryption
      await initializeSessionEncryption(alice.userId, alice.password);

      // Generate ephemeral keys and derive session keys
      const aliceEphKey = await generateEphemeralKeyPair();
      const bobEphKey = await generateEphemeralKeyPair();

      const aliceEphPubJWK = await exportEphPublicKey(aliceEphKey.publicKey);
      const bobEphPubJWK = await exportEphPublicKey(bobEphKey.publicKey);

      const bobEphPubKey = await importEphPublicKey(bobEphPubJWK);
      const aliceSharedSecret = await computeSharedSecret(aliceEphKey.privateKey, bobEphPubKey);

      const sessionId = `session-${alice.userId}-${bob.userId}`;
      const aliceKeys = await deriveSessionKeys(aliceSharedSecret, sessionId, alice.userId, bob.userId);

      // Create session
      await createSession(
        sessionId,
        alice.userId,
        bob.userId,
        aliceKeys.rootKey,
        aliceKeys.sendKey,
        aliceKeys.recvKey,
        alice.password
      );

      // Load session
      const loadedSession = await loadSession(sessionId, alice.userId, alice.password);

      expect(loadedSession).toBeDefined();
      expect(loadedSession.sessionId).toBe(sessionId);
      expect(loadedSession.userId).toBe(alice.userId);
      expect(loadedSession.peerId).toBe(bob.userId);

      // Verify keys are decrypted correctly
      expect(arrayBuffersEqual(loadedSession.rootKey, aliceKeys.rootKey)).toBe(true);
      expect(arrayBuffersEqual(loadedSession.sendKey, aliceKeys.sendKey)).toBe(true);
      expect(arrayBuffersEqual(loadedSession.recvKey, aliceKeys.recvKey)).toBe(true);
    });
  });

  describe('Different IVs Per Message', () => {
    test('should generate different IVs for each encryption', async () => {
      // Set up session
      aliceIdentityKey = await generateIdentityKeyPair();
      await storePrivateKeyEncrypted(alice.userId, aliceIdentityKey.privateKey, alice.password);
      await initializeSessionEncryption(alice.userId, alice.password);

      const aliceEphKey = await generateEphemeralKeyPair();
      const bobEphKey = await generateEphemeralKeyPair();

      const bobEphPubJWK = await exportEphPublicKey(bobEphKey.publicKey);
      const bobEphPubKey = await importEphPublicKey(bobEphPubJWK);
      const aliceSharedSecret = await computeSharedSecret(aliceEphKey.privateKey, bobEphPubKey);

      const sessionId = `session-${alice.userId}-${bob.userId}`;
      const aliceKeys = await deriveSessionKeys(aliceSharedSecret, sessionId, alice.userId, bob.userId);

      await createSession(
        sessionId,
        alice.userId,
        bob.userId,
        aliceKeys.rootKey,
        aliceKeys.sendKey,
        aliceKeys.recvKey,
        alice.password
      );

      // Encrypt multiple messages
      const { encryptAESGCM } = await import('../../src/crypto/aesGcm.js');
      const sendKey = aliceKeys.sendKey;

      const message1 = 'Hello, Bob!';
      const message2 = 'How are you?';
      const message3 = 'This is a test message.';

      const encrypted1 = await encryptAESGCM(sendKey, message1);
      const encrypted2 = await encryptAESGCM(sendKey, message2);
      const encrypted3 = await encryptAESGCM(sendKey, message3);

      // Verify IVs are different
      const iv1 = new Uint8Array(encrypted1.iv);
      const iv2 = new Uint8Array(encrypted2.iv);
      const iv3 = new Uint8Array(encrypted3.iv);

      expect(iv1.length).toBe(12); // 96 bits
      expect(iv2.length).toBe(12);
      expect(iv3.length).toBe(12);

      // IVs should be different
      expect(arrayBuffersEqual(iv1.buffer, iv2.buffer)).toBe(false);
      expect(arrayBuffersEqual(iv1.buffer, iv3.buffer)).toBe(false);
      expect(arrayBuffersEqual(iv2.buffer, iv3.buffer)).toBe(false);
    });
  });

  describe('Session Key Consistency', () => {
    test('should derive consistent session keys from same inputs', async () => {
      // Create a deterministic shared secret (for testing)
      const sharedSecret = new Uint8Array(32).fill(0x42).buffer;
      const sessionId = 'test-session-123';
      const userId = 'user-123';
      const peerId = 'user-456';

      const keys1 = await deriveSessionKeys(sharedSecret, sessionId, userId, peerId);
      const keys2 = await deriveSessionKeys(sharedSecret, sessionId, userId, peerId);

      // Same inputs should produce same keys
      expect(arrayBuffersEqual(keys1.rootKey, keys2.rootKey)).toBe(true);
      expect(arrayBuffersEqual(keys1.sendKey, keys2.sendKey)).toBe(true);
      expect(arrayBuffersEqual(keys1.recvKey, keys2.recvKey)).toBe(true);
    });

    test('should derive different keys for different sessions', async () => {
      const sharedSecret = new Uint8Array(32).fill(0x42).buffer;
      const userId = 'user-123';
      const peerId = 'user-456';

      const keys1 = await deriveSessionKeys(sharedSecret, 'session-1', userId, peerId);
      const keys2 = await deriveSessionKeys(sharedSecret, 'session-2', userId, peerId);

      // Different session IDs should produce different keys
      expect(arrayBuffersEqual(keys1.rootKey, keys2.rootKey)).toBe(false);
    });
  });
});
