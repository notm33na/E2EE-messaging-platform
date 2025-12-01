/**
 * E2EE File Encryption Tests
 * 
 * Encrypt a test file with AES-GCM, break into chunks if the app does that,
 * ensure chunk ciphertext & IV only are passed to backend, and decrypt file
 * and verify integrity.
 */

import { encryptFile, getChunkSize } from '../../src/crypto/fileEncryption.js';
import { decryptFile } from '../../src/crypto/fileDecryption.js';
import { createSession, initializeSessionEncryption } from '../../src/crypto/sessionManager.js';
import { generateIdentityKeyPair, storePrivateKeyEncrypted } from '../../src/crypto/identityKeys.js';
import { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKeys, exportPublicKey as exportEphPublicKey, importPublicKey as importEphPublicKey } from '../../src/crypto/ecdh.js';
import { clearIndexedDB, generateTestUser, createTestFile, readFileAsArrayBuffer, ensureNoPlaintext, arrayBuffersEqual } from './testHelpers.js';

describe('E2EE File Encryption Tests', () => {
  let alice, bob;
  let aliceSessionId;

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

    // Establish session
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

  describe('File Encryption with AES-GCM', () => {
    test('should encrypt small file', async () => {
      const fileContent = 'This is a small test file.';
      const file = createTestFile('test.txt', fileContent, 'text/plain');

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(fileMetaEnvelope).toBeDefined();
      expect(chunkEnvelopes).toBeDefined();
      expect(chunkEnvelopes.length).toBe(1); // Small file = 1 chunk
    });

    test('should encrypt large file and split into chunks', async () => {
      // Create a file larger than chunk size (256 KB)
      const chunkSize = getChunkSize();
      const largeContent = 'A'.repeat(chunkSize * 2 + 1000); // 2 chunks + some extra
      const file = createTestFile('large.txt', largeContent, 'text/plain');

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(chunkEnvelopes.length).toBeGreaterThan(1);
      expect(fileMetaEnvelope.meta.totalChunks).toBe(chunkEnvelopes.length);
    });

    test('should encrypt file metadata separately', async () => {
      const fileContent = 'Test file content';
      const file = createTestFile('document.pdf', fileContent, 'application/pdf');

      const { fileMetaEnvelope } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(fileMetaEnvelope.type).toBe('FILE_META');
      expect(fileMetaEnvelope.meta.filename).toBe('document.pdf');
      expect(fileMetaEnvelope.meta.size).toBe(fileContent.length);
      expect(fileMetaEnvelope.meta.mimetype).toBe('application/pdf');
      expect(fileMetaEnvelope.ciphertext).toBeDefined();
      expect(fileMetaEnvelope.iv).toBeDefined();
      expect(fileMetaEnvelope.authTag).toBeDefined();
    });
  });

  describe('Chunk Ciphertext & IV Only', () => {
    test('should pass only ciphertext, IV, and authTag in chunk envelopes', async () => {
      const fileContent = 'Test chunk encryption';
      const file = createTestFile('test.txt', fileContent, 'text/plain');

      const { chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      for (const chunk of chunkEnvelopes) {
        // Should have encrypted data
        expect(chunk.ciphertext).toBeDefined();
        expect(chunk.iv).toBeDefined();
        expect(chunk.authTag).toBeDefined();

        // Should NOT have plaintext
        expect(chunk.plaintext).toBeUndefined();
        expect(chunk.fileData).toBeUndefined();
        expect(chunk.content).toBeUndefined();

        // Verify ciphertext is base64
        expect(typeof chunk.ciphertext).toBe('string');
        expect(() => atob(chunk.ciphertext)).not.toThrow();
      }
    });

    test('should not include file content in chunk envelopes', async () => {
      const fileContent = 'This is secret file content that should never appear in envelopes!';
      const file = createTestFile('secret.txt', fileContent, 'text/plain');

      const { chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      for (const chunk of chunkEnvelopes) {
        const chunkString = JSON.stringify(chunk);
        expect(ensureNoPlaintext(chunkString, fileContent)).toBe(true);
      }
    });

    test('should have different IVs for each chunk', async () => {
      const chunkSize = getChunkSize();
      const largeContent = 'A'.repeat(chunkSize * 3); // 3 chunks
      const file = createTestFile('large.txt', largeContent, 'text/plain');

      const { chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(chunkEnvelopes.length).toBe(3);

      // All IVs should be different
      const ivs = chunkEnvelopes.map(chunk => chunk.iv);
      for (let i = 0; i < ivs.length; i++) {
        for (let j = i + 1; j < ivs.length; j++) {
          expect(ivs[i]).not.toBe(ivs[j]);
        }
      }
    });

    test('should include chunk metadata (chunkIndex, totalChunks)', async () => {
      const chunkSize = getChunkSize();
      const largeContent = 'A'.repeat(chunkSize * 2 + 100);
      const file = createTestFile('large.txt', largeContent, 'text/plain');

      const { chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(chunkEnvelopes.length).toBeGreaterThan(1);

      for (let i = 0; i < chunkEnvelopes.length; i++) {
        const chunk = chunkEnvelopes[i];
        expect(chunk.meta.chunkIndex).toBe(i);
        expect(chunk.meta.totalChunks).toBe(chunkEnvelopes.length);
      }
    });
  });

  describe('File Decryption and Integrity', () => {
    test('should decrypt small file correctly', async () => {
      const fileContent = 'This is a test file.';
      const file = createTestFile('test.txt', fileContent, 'text/plain');
      const originalBuffer = await readFileAsArrayBuffer(file);

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      const decrypted = await decryptFile(
        fileMetaEnvelope,
        chunkEnvelopes,
        aliceSessionId,
        bob.userId
      );

      expect(decrypted.filename).toBe('test.txt');
      expect(decrypted.mimetype).toBe('text/plain');
      expect(decrypted.size).toBe(fileContent.length);

      // Verify content
      const decryptedBuffer = await readFileAsArrayBuffer(decrypted.blob);
      expect(arrayBuffersEqual(decryptedBuffer, originalBuffer)).toBe(true);
    });

    test('should decrypt large file with multiple chunks correctly', async () => {
      const chunkSize = getChunkSize();
      const largeContent = 'A'.repeat(chunkSize * 3 + 500);
      const file = createTestFile('large.txt', largeContent, 'text/plain');
      const originalBuffer = await readFileAsArrayBuffer(file);

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      const decrypted = await decryptFile(
        fileMetaEnvelope,
        chunkEnvelopes,
        aliceSessionId,
        bob.userId
      );

      expect(decrypted.size).toBe(largeContent.length);
      expect(chunkEnvelopes.length).toBeGreaterThan(1);

      // Verify content
      const decryptedBuffer = await readFileAsArrayBuffer(decrypted.blob);
      expect(arrayBuffersEqual(decryptedBuffer, originalBuffer)).toBe(true);
    });

    test('should maintain file integrity after encryption/decryption', async () => {
      const fileContent = 'Important file content that must remain intact!';
      const file = createTestFile('important.txt', fileContent, 'text/plain');
      const originalBuffer = await readFileAsArrayBuffer(file);

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      const decrypted = await decryptFile(
        fileMetaEnvelope,
        chunkEnvelopes,
        aliceSessionId,
        bob.userId
      );

      const decryptedBuffer = await readFileAsArrayBuffer(decrypted.blob);
      const decryptedText = new TextDecoder().decode(decryptedBuffer);

      expect(decryptedText).toBe(fileContent);
      expect(arrayBuffersEqual(decryptedBuffer, originalBuffer)).toBe(true);
    });

    test('should fail to decrypt with wrong key', async () => {
      const fileContent = 'Test file';
      const file = createTestFile('test.txt', fileContent, 'text/plain');

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      // Try to decrypt with wrong session (different keys)
      const wrongSessionId = 'wrong-session';
      await expect(
        decryptFile(fileMetaEnvelope, chunkEnvelopes, wrongSessionId, bob.userId)
      ).rejects.toThrow();
    });

    test('should fail to decrypt with tampered ciphertext', async () => {
      const fileContent = 'Test file';
      const file = createTestFile('test.txt', fileContent, 'text/plain');

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      // Tamper with first chunk's ciphertext
      const tamperedChunks = [...chunkEnvelopes];
      const tamperedCiphertext = atob(tamperedChunks[0].ciphertext);
      const tamperedBytes = new Uint8Array(tamperedCiphertext.length);
      for (let i = 0; i < tamperedBytes.length; i++) {
        tamperedBytes[i] = tamperedCiphertext.charCodeAt(i);
      }
      tamperedBytes[0] ^= 0xFF; // Flip bits
      tamperedChunks[0].ciphertext = btoa(String.fromCharCode(...tamperedBytes));

      await expect(
        decryptFile(fileMetaEnvelope, tamperedChunks, aliceSessionId, bob.userId)
      ).rejects.toThrow();
    });

    test('should fail to decrypt with missing chunks', async () => {
      const chunkSize = getChunkSize();
      const largeContent = 'A'.repeat(chunkSize * 3);
      const file = createTestFile('large.txt', largeContent, 'text/plain');

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      // Remove one chunk
      const incompleteChunks = chunkEnvelopes.slice(0, -1);

      await expect(
        decryptFile(fileMetaEnvelope, incompleteChunks, aliceSessionId, bob.userId)
      ).rejects.toThrow('Missing chunks');
    });

    test('should fail to decrypt with out-of-order chunks', async () => {
      const chunkSize = getChunkSize();
      const largeContent = 'A'.repeat(chunkSize * 3);
      const file = createTestFile('large.txt', largeContent, 'text/plain');

      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      // Reverse chunks
      const reversedChunks = [...chunkEnvelopes].reverse();

      // Should still decrypt (chunks are sorted by index), but verify order matters
      // Actually, decryptFile sorts chunks, so this should work
      // Let's test with wrong chunk indices instead
      const wrongIndices = chunkEnvelopes.map((chunk, i) => ({
        ...chunk,
        meta: { ...chunk.meta, chunkIndex: (i + 1) % chunkEnvelopes.length }
      }));

      await expect(
        decryptFile(fileMetaEnvelope, wrongIndices, aliceSessionId, bob.userId)
      ).rejects.toThrow('Chunk index mismatch');
    });
  });

  describe('File Metadata', () => {
    test('should preserve filename in metadata', async () => {
      const file = createTestFile('my-document.pdf', 'Content', 'application/pdf');

      const { fileMetaEnvelope } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(fileMetaEnvelope.meta.filename).toBe('my-document.pdf');
    });

    test('should preserve file size in metadata', async () => {
      const fileContent = 'A'.repeat(12345);
      const file = createTestFile('test.txt', fileContent, 'text/plain');

      const { fileMetaEnvelope } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(fileMetaEnvelope.meta.size).toBe(12345);
    });

    test('should preserve MIME type in metadata', async () => {
      const file = createTestFile('image.png', 'PNG data', 'image/png');

      const { fileMetaEnvelope } = await encryptFile(
        file,
        aliceSessionId,
        alice.userId,
        bob.userId,
        alice.userId
      );

      expect(fileMetaEnvelope.meta.mimetype).toBe('image/png');
    });
  });
});
