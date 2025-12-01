/**
 * E2EE Message Flow Tests
 * 
 * Simulates sending a message through the React messaging UI.
 * Ensures:
 * - encryption occurs before send()
 * - ciphertext only transmitted
 * - decrypted message rendered correctly on receiver UI
 * - metadata created (timestamp, seq, nonce)
 */

import { sendEncryptedMessage, handleIncomingMessage } from '../../src/crypto/messageFlow.js';
import { createSession, initializeSessionEncryption, loadSession } from '../../src/crypto/sessionManager.js';
import { generateIdentityKeyPair, storePrivateKeyEncrypted } from '../../src/crypto/identityKeys.js';
import { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKeys, exportPublicKey as exportEphPublicKey, importPublicKey as importEphPublicKey } from '../../src/crypto/ecdh.js';
import { buildTextMessageEnvelope, validateEnvelopeStructure } from '../../src/crypto/messageEnvelope.js';
import { clearIndexedDB, generateTestUser, ensureNoPlaintext, arrayBuffersEqual } from './testHelpers.js';

describe('E2EE Message Flow Tests', () => {
  let alice, bob;
  let aliceSessionId;
  let mockSocketEmit;

  beforeEach(async () => {
    await clearIndexedDB();
    alice = generateTestUser('alice');
    bob = generateTestUser('bob');
    aliceSessionId = `session-${alice.userId}-${bob.userId}`;

    // Mock socket emit function
    mockSocketEmit = jest.fn();

    // Set up Alice's identity key
    const aliceIdentityKey = await generateIdentityKeyPair();
    await storePrivateKeyEncrypted(alice.userId, aliceIdentityKey.privateKey, alice.password);
    await initializeSessionEncryption(alice.userId, alice.password);

    // Set up Bob's identity key
    const bobIdentityKey = await generateIdentityKeyPair();
    await storePrivateKeyEncrypted(bob.userId, bobIdentityKey.privateKey, bob.password);
    await initializeSessionEncryption(bob.userId, bob.password);

    // Establish session between Alice and Bob
    const aliceEphKey = await generateEphemeralKeyPair();
    const bobEphKey = await generateEphemeralKeyPair();

    const aliceEphPubJWK = await exportEphPublicKey(aliceEphKey.publicKey);
    const bobEphPubJWK = await exportEphPublicKey(bobEphKey.publicKey);

    const bobEphPubKey = await importEphPublicKey(bobEphPubJWK);
    const aliceSharedSecret = await computeSharedSecret(aliceEphKey.privateKey, bobEphPubKey);

    const aliceKeys = await deriveSessionKeys(aliceSharedSecret, aliceSessionId, alice.userId, bob.userId);

    await createSession(
      aliceSessionId,
      alice.userId,
      bob.userId,
      aliceKeys.rootKey,
      aliceKeys.sendKey,
      aliceKeys.recvKey,
      alice.password
    );

    // Set up Bob's session (with swapped keys)
    const aliceEphPubKey = await importEphPublicKey(aliceEphPubJWK);
    const bobSharedSecret = await computeSharedSecret(bobEphKey.privateKey, aliceEphPubKey);
    const bobKeys = await deriveSessionKeys(bobSharedSecret, aliceSessionId, bob.userId, alice.userId);

    await createSession(
      aliceSessionId,
      bob.userId,
      alice.userId,
      bobKeys.rootKey,
      bobKeys.sendKey,
      bobKeys.recvKey,
      bob.password
    );
  });

  afterEach(async () => {
    await clearIndexedDB();
  });

  describe('Message Encryption Before Send', () => {
    test('should encrypt message before sending', async () => {
      const plaintext = 'Hello, Bob! This is a secret message.';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Verify envelope was created
      expect(envelope).toBeDefined();
      expect(envelope.type).toBe('MSG');
      expect(envelope.sessionId).toBe(aliceSessionId);
      expect(envelope.sender).toBe(alice.userId);
      expect(envelope.receiver).toBe(bob.userId);

      // Verify ciphertext is present (not plaintext)
      expect(envelope.ciphertext).toBeDefined();
      expect(typeof envelope.ciphertext).toBe('string'); // Base64 encoded
      expect(ensureNoPlaintext(envelope.ciphertext, plaintext)).toBe(true);

      // Verify socket was called
      expect(mockSocketEmit).toHaveBeenCalledWith('msg:send', envelope);
    });

    test('should not include plaintext in envelope', async () => {
      const plaintext = 'This should never appear in the envelope!';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      const envelopeString = JSON.stringify(envelope);
      expect(ensureNoPlaintext(envelopeString, plaintext)).toBe(true);
    });

    test('should include required metadata in envelope', async () => {
      const plaintext = 'Test message';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Verify envelope structure
      expect(envelope.type).toBe('MSG');
      expect(envelope.sessionId).toBeDefined();
      expect(envelope.sender).toBeDefined();
      expect(envelope.receiver).toBeDefined();
      expect(envelope.ciphertext).toBeDefined();
      expect(envelope.iv).toBeDefined();
      expect(envelope.authTag).toBeDefined();
      expect(envelope.timestamp).toBeDefined();
      expect(envelope.seq).toBeDefined();
      expect(envelope.nonce).toBeDefined();

      // Validate envelope structure
      const validation = validateEnvelopeStructure(envelope);
      expect(validation.valid).toBe(true);
    });
  });

  describe('Ciphertext Only Transmission', () => {
    test('should transmit only ciphertext, IV, and authTag', async () => {
      const plaintext = 'Secret message for transmission test';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Verify only encrypted data is in envelope
      expect(envelope.ciphertext).toBeDefined();
      expect(envelope.iv).toBeDefined();
      expect(envelope.authTag).toBeDefined();

      // Verify plaintext is not present
      expect(envelope.plaintext).toBeUndefined();
      expect(envelope.message).toBeUndefined();
      expect(envelope.content).toBeUndefined();

      // Verify ciphertext is base64 encoded
      expect(typeof envelope.ciphertext).toBe('string');
      expect(() => atob(envelope.ciphertext)).not.toThrow();
    });

    test('should not log plaintext during transmission', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const plaintext = 'This should not appear in console logs!';
      
      await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Check console logs
      const logCalls = consoleSpy.mock.calls.flat().join(' ');
      expect(ensureNoPlaintext(logCalls, plaintext)).toBe(true);

      consoleSpy.mockRestore();
    });
  });

  describe('Message Decryption and Rendering', () => {
    test('should decrypt incoming message correctly', async () => {
      const plaintext = 'Hello from Alice!';
      
      // Alice sends message
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Bob receives and decrypts
      const result = await handleIncomingMessage(envelope, bob.userId);

      expect(result.valid).toBe(true);
      expect(result.plaintext).toBe(plaintext);
      expect(result.envelope).toBeDefined();
    });

    test('should reject message with invalid timestamp', async () => {
      const plaintext = 'Test message';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Tamper with timestamp (make it too old)
      envelope.timestamp = Date.now() - 3 * 60 * 1000; // 3 minutes ago

      const result = await handleIncomingMessage(envelope, bob.userId);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Timestamp');
    });

    test('should reject message with invalid sequence number', async () => {
      const plaintext1 = 'First message';
      const plaintext2 = 'Second message';
      
      // Send first message
      const envelope1 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext1,
        mockSocketEmit,
        alice.userId
      );

      // Send second message
      const envelope2 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext2,
        mockSocketEmit,
        alice.userId
      );

      // Process first message (should succeed)
      const result1 = await handleIncomingMessage(envelope1, bob.userId);
      expect(result1.valid).toBe(true);

      // Try to replay first message (should fail)
      const result2 = await handleIncomingMessage(envelope1, bob.userId);
      expect(result2.valid).toBe(false);
      expect(result2.error).toContain('Sequence');
    });

    test('should update sequence number after successful decryption', async () => {
      const plaintext = 'Test sequence update';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      // Load session before
      const sessionBefore = await loadSession(aliceSessionId, bob.userId, bob.password);
      const seqBefore = sessionBefore.lastSeq;

      // Process message
      await handleIncomingMessage(envelope, bob.userId);

      // Load session after
      const sessionAfter = await loadSession(aliceSessionId, bob.userId, bob.password);
      const seqAfter = sessionAfter.lastSeq;

      expect(seqAfter).toBeGreaterThan(seqBefore);
      expect(seqAfter).toBe(envelope.seq);
    });
  });

  describe('Metadata Creation', () => {
    test('should create timestamp in envelope', async () => {
      const plaintext = 'Test timestamp';
      const beforeTime = Date.now();
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      const afterTime = Date.now();

      expect(envelope.timestamp).toBeDefined();
      expect(typeof envelope.timestamp).toBe('number');
      expect(envelope.timestamp).toBeGreaterThanOrEqual(beforeTime);
      expect(envelope.timestamp).toBeLessThanOrEqual(afterTime);
    });

    test('should create sequence number in envelope', async () => {
      const plaintext1 = 'First';
      const plaintext2 = 'Second';
      const plaintext3 = 'Third';
      
      const envelope1 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext1,
        mockSocketEmit,
        alice.userId
      );

      const envelope2 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext2,
        mockSocketEmit,
        alice.userId
      );

      const envelope3 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext3,
        mockSocketEmit,
        alice.userId
      );

      // Sequence numbers should be increasing
      expect(envelope1.seq).toBeLessThan(envelope2.seq);
      expect(envelope2.seq).toBeLessThan(envelope3.seq);
    });

    test('should create nonce in envelope', async () => {
      const plaintext = 'Test nonce';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      expect(envelope.nonce).toBeDefined();
      expect(typeof envelope.nonce).toBe('string');
      
      // Nonce should be base64 encoded
      expect(() => atob(envelope.nonce)).not.toThrow();
    });

    test('should create different nonces for each message', async () => {
      const plaintext = 'Same message';
      
      const envelope1 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      const envelope2 = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      expect(envelope1.nonce).not.toBe(envelope2.nonce);
    });
  });

  describe('Envelope Validation', () => {
    test('should validate envelope structure', async () => {
      const plaintext = 'Test validation';
      
      const envelope = await sendEncryptedMessage(
        aliceSessionId,
        plaintext,
        mockSocketEmit,
        alice.userId
      );

      const validation = validateEnvelopeStructure(envelope);
      expect(validation.valid).toBe(true);
      expect(validation.error).toBeUndefined();
    });

    test('should reject envelope with missing fields', () => {
      const invalidEnvelope = {
        type: 'MSG',
        sessionId: 'test',
        // Missing required fields
      };

      const validation = validateEnvelopeStructure(invalidEnvelope);
      expect(validation.valid).toBe(false);
      expect(validation.error).toBeDefined();
    });
  });
});
