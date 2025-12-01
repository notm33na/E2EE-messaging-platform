/**
 * E2EE Message Encrypt/Decrypt Tests
 * 
 * Encrypts a text message using AES-256-GCM, decrypts it using the derived session key,
 * verifies authTag / integrity protection, and ensures plaintext never appears in logs.
 */

import { encryptAESGCM, decryptAESGCM, decryptAESGCMToString, generateIV } from '../../src/crypto/aesGcm.js';
import { clearIndexedDB, generateTestUser, arrayBuffersEqual, ensureNoPlaintext } from './testHelpers.js';

describe('E2EE Message Encrypt/Decrypt Tests', () => {
  let testUser;
  let sessionKey;

  beforeEach(async () => {
    await clearIndexedDB();
    testUser = generateTestUser('testuser');
    
    // Generate a test session key (256 bits)
    sessionKey = crypto.getRandomValues(new Uint8Array(32)).buffer;
  });

  afterEach(async () => {
    await clearIndexedDB();
  });

  describe('AES-256-GCM Encryption', () => {
    test('should encrypt text message with AES-256-GCM', async () => {
      const plaintext = 'Hello, this is a secret message!';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      expect(ciphertext).toBeDefined();
      expect(iv).toBeDefined();
      expect(authTag).toBeDefined();

      // Verify sizes
      expect(iv.length).toBe(12); // 96 bits = 12 bytes
      expect(authTag.byteLength).toBe(16); // 128 bits = 16 bytes
      expect(ciphertext.byteLength).toBeGreaterThan(0);
    });

    test('should generate different IVs for each encryption', async () => {
      const plaintext = 'Test message';
      
      const encrypted1 = await encryptAESGCM(sessionKey, plaintext);
      const encrypted2 = await encryptAESGCM(sessionKey, plaintext);
      const encrypted3 = await encryptAESGCM(sessionKey, plaintext);

      // IVs should be different (random)
      expect(arrayBuffersEqual(encrypted1.iv.buffer, encrypted2.iv.buffer)).toBe(false);
      expect(arrayBuffersEqual(encrypted1.iv.buffer, encrypted3.iv.buffer)).toBe(false);
      expect(arrayBuffersEqual(encrypted2.iv.buffer, encrypted3.iv.buffer)).toBe(false);
    });

    test('should produce different ciphertexts for same plaintext (due to different IVs)', async () => {
      const plaintext = 'Same message';
      
      const encrypted1 = await encryptAESGCM(sessionKey, plaintext);
      const encrypted2 = await encryptAESGCM(sessionKey, plaintext);

      // Ciphertexts should be different (probabilistic encryption)
      expect(arrayBuffersEqual(encrypted1.ciphertext, encrypted2.ciphertext)).toBe(false);
    });

    test('should encrypt ArrayBuffer data', async () => {
      const plaintext = new TextEncoder().encode('ArrayBuffer message');
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      expect(ciphertext).toBeDefined();
      expect(iv).toBeDefined();
      expect(authTag).toBeDefined();
    });
  });

  describe('AES-256-GCM Decryption', () => {
    test('should decrypt encrypted message correctly', async () => {
      const plaintext = 'Hello, this is a secret message!';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      const decrypted = await decryptAESGCMToString(sessionKey, iv, ciphertext, authTag);

      expect(decrypted).toBe(plaintext);
    });

    test('should decrypt ArrayBuffer data correctly', async () => {
      const originalData = new TextEncoder().encode('ArrayBuffer test');
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, originalData);

      const decrypted = await decryptAESGCM(sessionKey, iv, ciphertext, authTag);
      const decryptedArray = new Uint8Array(decrypted);
      const originalArray = new Uint8Array(originalData);

      expect(arrayBuffersEqual(decrypted, originalData)).toBe(true);
    });

    test('should fail to decrypt with wrong key', async () => {
      const plaintext = 'Secret message';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Use wrong key
      const wrongKey = crypto.getRandomValues(new Uint8Array(32)).buffer;

      await expect(
        decryptAESGCMToString(wrongKey, iv, ciphertext, authTag)
      ).rejects.toThrow();
    });

    test('should fail to decrypt with wrong IV', async () => {
      const plaintext = 'Secret message';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Use wrong IV
      const wrongIV = crypto.getRandomValues(new Uint8Array(12));

      await expect(
        decryptAESGCMToString(sessionKey, wrongIV, ciphertext, authTag)
      ).rejects.toThrow();
    });

    test('should fail to decrypt with wrong authTag', async () => {
      const plaintext = 'Secret message';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Use wrong auth tag
      const wrongAuthTag = crypto.getRandomValues(new Uint8Array(16)).buffer;

      await expect(
        decryptAESGCMToString(sessionKey, iv, ciphertext, wrongAuthTag)
      ).rejects.toThrow();
    });

    test('should fail to decrypt with tampered ciphertext', async () => {
      const plaintext = 'Secret message';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Tamper with ciphertext
      const tamperedCiphertext = new Uint8Array(ciphertext);
      tamperedCiphertext[0] ^= 0x01; // Flip a bit
      const tamperedBuffer = tamperedCiphertext.buffer;

      await expect(
        decryptAESGCMToString(sessionKey, iv, tamperedBuffer, authTag)
      ).rejects.toThrow();
    });
  });

  describe('AuthTag / Integrity Protection', () => {
    test('should verify integrity with correct authTag', async () => {
      const plaintext = 'Message with integrity check';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Decryption should succeed with correct authTag
      const decrypted = await decryptAESGCMToString(sessionKey, iv, ciphertext, authTag);
      expect(decrypted).toBe(plaintext);
    });

    test('should reject tampered ciphertext (integrity violation)', async () => {
      const plaintext = 'Message to tamper';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Tamper with ciphertext
      const tampered = new Uint8Array(ciphertext);
      tampered[5] ^= 0xFF; // Flip bits

      await expect(
        decryptAESGCMToString(sessionKey, iv, tampered.buffer, authTag)
      ).rejects.toThrow('Authentication tag verification failed');
    });

    test('should reject tampered IV (integrity violation)', async () => {
      const plaintext = 'Message to test IV tampering';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Tamper with IV
      const tamperedIV = new Uint8Array(iv);
      tamperedIV[0] ^= 0x01;

      await expect(
        decryptAESGCMToString(sessionKey, tamperedIV, ciphertext, authTag)
      ).rejects.toThrow();
    });

    test('should generate unique authTags for each encryption', async () => {
      const plaintext = 'Same message, different tags';
      
      const encrypted1 = await encryptAESGCM(sessionKey, plaintext);
      const encrypted2 = await encryptAESGCM(sessionKey, plaintext);

      // Auth tags should be different (due to different IVs)
      expect(arrayBuffersEqual(encrypted1.authTag, encrypted2.authTag)).toBe(false);
    });
  });

  describe('Plaintext Prevention in Logs', () => {
    test('should not expose plaintext in ciphertext', async () => {
      const plaintext = 'This is a very secret message that should never appear in logs!';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Verify plaintext is not in ciphertext
      const ciphertextString = new TextDecoder().decode(ciphertext);
      expect(ensureNoPlaintext(ciphertextString, plaintext)).toBe(true);

      // Verify plaintext is not in IV
      const ivString = new TextDecoder().decode(iv);
      expect(ensureNoPlaintext(ivString, plaintext)).toBe(true);

      // Verify plaintext is not in authTag
      const authTagString = new TextDecoder().decode(authTag);
      expect(ensureNoPlaintext(authTagString, plaintext)).toBe(true);
    });

    test('should not expose plaintext in encrypted envelope', async () => {
      const plaintext = 'Super secret message for envelope test';
      const { ciphertext, iv, authTag } = await encryptAESGCM(sessionKey, plaintext);

      // Create envelope-like structure
      const envelope = {
        type: 'MSG',
        sessionId: 'test-session',
        sender: 'user-1',
        receiver: 'user-2',
        ciphertext: Array.from(new Uint8Array(ciphertext)),
        iv: Array.from(iv),
        authTag: Array.from(new Uint8Array(authTag)),
        timestamp: Date.now(),
        seq: 1
      };

      // Verify plaintext is not in envelope
      const envelopeString = JSON.stringify(envelope);
      expect(ensureNoPlaintext(envelopeString, plaintext)).toBe(true);
    });
  });

  describe('IV Generation', () => {
    test('should generate 96-bit IVs', () => {
      const iv = generateIV();
      expect(iv.length).toBe(12); // 96 bits = 12 bytes
    });

    test('should generate random IVs', () => {
      const iv1 = generateIV();
      const iv2 = generateIV();
      const iv3 = generateIV();

      // All IVs should be different (very high probability)
      expect(arrayBuffersEqual(iv1.buffer, iv2.buffer)).toBe(false);
      expect(arrayBuffersEqual(iv1.buffer, iv3.buffer)).toBe(false);
      expect(arrayBuffersEqual(iv2.buffer, iv3.buffer)).toBe(false);
    });
  });
});
