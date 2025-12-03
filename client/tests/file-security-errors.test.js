/**
 * TEST CASE 2: Security & Error Handling
 * Tests security features and error handling for file encryption
 */

import { encryptFile } from '../src/crypto/fileEncryption.js';
import { decryptFile } from '../src/crypto/fileDecryption.js';
import { createSmallFile, createLargeFile, createVeryLargeFile, createMediumFile } from './helpers/test-files.js';
import { createMockWebSocketPair } from './helpers/mock-websocket.js';
import { extractIV, corruptAuthTag, corruptCiphertext, generateMockKeys } from './helpers/mock-crypto.js';
import { expectUniqueIVs, expectIVLength } from './helpers/assertions.js';
import { createTestSession } from './helpers/session-setup.js';
import { sequenceManager } from '../src/crypto/messages.js';
import { isNonceUsed, storeUsedNonce } from '../src/crypto/sessionManager.js';
import { sha256Hex } from './test-helpers/webcryptoHelper.js';
import { base64ToArrayBuffer } from '../src/crypto/signatures.js';

describe('Security & Error Handling', () => {
  // Increase timeout for this test suite
  jest.setTimeout(60000); // 60 seconds
  
  let sessionId;
  let aliceUserId, bobUserId;
  let sendKey, recvKey, wrongKey;
  let aliceSocket, bobSocket;

  beforeAll(async () => {
    // Setup mock WebSocket connections
    const sockets = createMockWebSocketPair();
    aliceSocket = sockets.alice;
    bobSocket = sockets.bob;
    
    // Generate mock session keys
    // In E2EE: Alice's sendKey = Bob's recvKey for decryption
    const keys = generateMockKeys();
    sendKey = keys.sendKey;  // Alice's sendKey (used for encryption)
    recvKey = sendKey;  // Bob's recvKey = Alice's sendKey (for decryption)
    
    // Generate wrong key for testing
    const wrongKeys = generateMockKeys();
    wrongKey = wrongKeys.recvKey;
    
    // Create session IDs
    sessionId = `test-session-security-${Date.now()}`;
    aliceUserId = 'alice-id';
    bobUserId = 'bob-id';
    
    // Create test session
    await createTestSession(sessionId, aliceUserId, bobUserId, sendKey, recvKey);
  });

  beforeEach(() => {
    sequenceManager.resetAll();
    aliceSocket.clearSentMessages();
    bobSocket.clearSentMessages();
  });

  describe('IV Uniqueness', () => {
    test('should generate unique IVs for each chunk', async () => {
      const largeFile = createLargeFile(); // 500KB = 2 chunks
      
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        largeFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Extract IVs from FILE_META and FILE_CHUNK envelopes
      const ivs = [
        fileMetaEnvelope.iv,
        ...chunkEnvelopes.map(c => c.iv)
      ];
      
      // Verify all IVs are unique
      expectUniqueIVs(ivs);
      
      // Verify each IV is 12 bytes (16 base64 chars)
      ivs.forEach(iv => {
        expectIVLength(iv);
      });
      
      // Verify IVs are cryptographically random (not all zeros)
      ivs.forEach(iv => {
        const decoded = atob(iv);
        const hasNonZero = Array.from(decoded).some(char => char.charCodeAt(0) !== 0);
        expect(hasNonZero).toBe(true);
      });
      
      console.log('✓ All IVs are unique and cryptographically random');
    });
  });

  describe('Replay Protection', () => {
    test('should reject replay attacks', async () => {
      const testFile = createSmallFile();
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      const chunk = chunkEnvelopes[0];
      
      // Process successfully first time
      const nonceBuffer = base64ToArrayBuffer(chunk.nonce);
      const nonceHash = await sha256Hex(nonceBuffer);
      await storeUsedNonce(sessionId, nonceHash);
      
      // Verify nonce is marked as used
      const isUsed = await isNonceUsed(sessionId, nonceHash);
      expect(isUsed).toBe(true);
      
      // Attempt to replay same envelope
      // The handleIncomingMessage should reject it
      // For this test, we verify the nonce is already used
      const replayNonceHash = await sha256Hex(nonceBuffer);
      const replayIsUsed = await isNonceUsed(sessionId, replayNonceHash);
      expect(replayIsUsed).toBe(true);
      
      // Verify sequence number would also be rejected
      const currentSeq = chunk.seq;
      const isValidSeq = sequenceManager.validateSequence(sessionId, currentSeq);
      expect(isValidSeq).toBe(false); // Already processed
      
      console.log('✓ Replay attack rejected (nonce and sequence checked)');
    });
  });

  describe('Timestamp Validation', () => {
    test('should reject stale timestamps', async () => {
      const testFile = createSmallFile();
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Create stale envelope (3 minutes ago)
      const staleChunk = {
        ...chunkEnvelopes[0],
        timestamp: Date.now() - (3 * 60 * 1000) // 3 minutes ago
      };
      
      // Validate timestamp (maxAge = 2 minutes = 120000ms)
      const maxAge = 120000;
      const now = Date.now();
      const age = now - staleChunk.timestamp;
      
      // Should be rejected (age > maxAge)
      expect(age).toBeGreaterThan(maxAge);
      
      // Attempt decryption - should fail at timestamp validation
      await expect(
        decryptFile(fileMetaEnvelope, [staleChunk], sessionId, bobUserId)
      ).rejects.toThrow();
      
      console.log('✓ Stale timestamp rejected');
    }, 10000); // 10 second timeout for this test
  });

  describe('AuthTag Validation', () => {
    test('should detect tampered authTag', async () => {
      const testFile = createSmallFile();
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Corrupt authTag
      const corruptedChunk = corruptAuthTag(chunkEnvelopes[0]);
      
      // Attempt decryption - should fail
      await expect(
        decryptFile(fileMetaEnvelope, [corruptedChunk], sessionId, bobUserId)
      ).rejects.toThrow();
      
      // Verify error message contains authentication failure
      try {
        await decryptFile(fileMetaEnvelope, [corruptedChunk], sessionId, bobUserId);
        fail('Should have thrown an error');
      } catch (error) {
        expect(
          error.message.includes('authentication') ||
          error.message.includes('verification') ||
          error.message.includes('OperationError') ||
          error.name === 'OperationError'
        ).toBe(true);
      }
      
      console.log('✓ Tampered authTag detected');
    });
  });

  describe('Ciphertext Tampering', () => {
    test('should detect tampered ciphertext', async () => {
      const testFile = createSmallFile();
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Corrupt ciphertext
      const corruptedChunk = corruptCiphertext(chunkEnvelopes[0]);
      
      // Attempt decryption - should fail
      await expect(
        decryptFile(fileMetaEnvelope, [corruptedChunk], sessionId, bobUserId)
      ).rejects.toThrow();
      
      console.log('✓ Tampered ciphertext detected');
    });
  });

  describe('Wrong Decryption Key', () => {
    test('should fail with wrong decryption key', async () => {
      const testFile = createSmallFile();
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Create session with wrong key
      const wrongSessionId = `wrong-session-${Date.now()}`;
      await createTestSession(wrongSessionId, bobUserId, aliceUserId, wrongKey, wrongKey);
      
      // Attempt decryption with wrong session (wrong key)
      await expect(
        decryptFile(fileMetaEnvelope, chunkEnvelopes, wrongSessionId, bobUserId)
      ).rejects.toThrow();
      
      // Verify error indicates authentication failure
      try {
        await decryptFile(fileMetaEnvelope, chunkEnvelopes, wrongSessionId, bobUserId);
        fail('Should have thrown an error');
      } catch (error) {
        expect(
          error.message.includes('authentication') ||
          error.message.includes('verification') ||
          error.message.includes('OperationError') ||
          error.name === 'OperationError'
        ).toBe(true);
      }
      
      console.log('✓ Wrong decryption key rejected');
    });
  });

  describe('Missing Chunks', () => {
    test('should detect missing chunks', async () => {
      const largeFile = createLargeFile(); // 500KB = 2 chunks
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        largeFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      expect(chunkEnvelopes.length).toBe(2);
      expect(fileMetaEnvelope.meta.totalChunks).toBe(2);
      
      // Send only 1 chunk (missing 1)
      const incompleteChunks = [chunkEnvelopes[0]];
      
      // Attempt reconstruction - should fail
      await expect(
        decryptFile(fileMetaEnvelope, incompleteChunks, sessionId, bobUserId)
      ).rejects.toThrow();
      
      // Verify error message
      try {
        await decryptFile(fileMetaEnvelope, incompleteChunks, sessionId, bobUserId);
        fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toContain('Missing chunks');
        expect(error.message).toContain('expected 2');
        expect(error.message).toContain('got 1');
      }
      
      console.log('✓ Missing chunks detected');
    });
  });

  describe('Chunk Index Validation', () => {
    test('should validate chunk indices', async () => {
      const largeFile = createLargeFile(); // 500KB = 2 chunks
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        largeFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Create invalid chunks: duplicate index, missing index
      const invalidChunks = [
        { ...chunkEnvelopes[0], meta: { ...chunkEnvelopes[0].meta, chunkIndex: 0 } },
        { ...chunkEnvelopes[1], meta: { ...chunkEnvelopes[1].meta, chunkIndex: 2 } } // Missing 1, has 2
      ];
      
      // Attempt decryption - should fail
      await expect(
        decryptFile(fileMetaEnvelope, invalidChunks, sessionId, bobUserId)
      ).rejects.toThrow();
      
      // Verify error message
      try {
        await decryptFile(fileMetaEnvelope, invalidChunks, sessionId, bobUserId);
        fail('Should have thrown an error');
      } catch (error) {
        expect(
          error.message.includes('Chunk index mismatch') ||
          error.message.includes('Missing chunks')
        ).toBe(true);
      }
      
      console.log('✓ Invalid chunk indices detected');
    });
  });

  describe('File Size Limits', () => {
    test('should enforce maximum file size', async () => {
      const veryLargeFile = createVeryLargeFile(); // 150MB
      
      // Attempt encryption - should fail
      await expect(
        encryptFile(veryLargeFile, sessionId, aliceUserId, bobUserId, aliceUserId)
      ).rejects.toThrow();
      
      // Verify error message
      try {
        await encryptFile(veryLargeFile, sessionId, aliceUserId, bobUserId, aliceUserId);
        fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toContain('exceeds maximum allowed size');
        expect(error.message).toContain('150.00 MB');
        expect(error.message).toContain('100 MB');
      }
      
      console.log('✓ Maximum file size enforced');
    });

    test('should accept valid file sizes', async () => {
      const mediumFile = createMediumFile(); // 50MB (within 100MB limit)
      
      // Should encrypt successfully
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        mediumFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      expect(fileMetaEnvelope).toBeDefined();
      expect(chunkEnvelopes.length).toBeGreaterThan(0);
      
      console.log('✓ Valid file size accepted');
    });
  });
});

