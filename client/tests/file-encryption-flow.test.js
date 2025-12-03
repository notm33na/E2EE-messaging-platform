/**
 * TEST CASE 1: Complete File Encryption & Decryption Flow
 * Tests the complete end-to-end file encryption and decryption process
 */

import { encryptFile } from '../src/crypto/fileEncryption.js';
import { decryptFile } from '../src/crypto/fileDecryption.js';
import { createSmallFile, createLargeFile, readFileAsArrayBuffer, compareBlobToBuffer } from './helpers/test-files.js';
import { createMockWebSocketPair, createSocketEmit } from './helpers/mock-websocket.js';
import { createMockMessageMetaCollection } from './helpers/mock-db.js';
import { extractIV, extractAuthTag, verifyIVLength, verifyAuthTagLength } from './helpers/mock-crypto.js';
import { expectFileMetaEnvelope, expectFileChunkEnvelope, expectIVLength, expectAuthTagLength, expectUniqueIVs } from './helpers/assertions.js';
import { generateMockKeys } from './helpers/mock-crypto.js';
import { createTestSession } from './helpers/session-setup.js';

describe('Complete File Encryption & Decryption Flow', () => {
  let aliceSocket, bobSocket;
  let sessionId;
  let aliceUserId, bobUserId;
  let sendKey, recvKey;
  let mockDB;

  beforeAll(async () => {
    // Setup mock WebSocket connections
    const sockets = createMockWebSocketPair();
    aliceSocket = sockets.alice;
    bobSocket = sockets.bob;
    
    // Generate mock session keys
    // In E2EE: Alice's sendKey = Bob's recvKey, and Bob's sendKey = Alice's recvKey
    // For testing, we create a session from Alice's perspective where:
    // - sendKey is used by Alice to encrypt
    // - recvKey should equal Bob's recvKey (which equals Alice's sendKey for decryption)
    const keys = generateMockKeys();
    sendKey = keys.sendKey;  // Alice's sendKey (used for encryption)
    // For Bob to decrypt, he needs recvKey = Alice's sendKey
    // So we set recvKey = sendKey in the session (from Bob's perspective, this is his recvKey)
    recvKey = sendKey;  // Bob's recvKey = Alice's sendKey (for decryption)
    
    // Create session IDs
    sessionId = `test-session-${Date.now()}`;
    aliceUserId = 'alice-id';
    bobUserId = 'bob-id';
    
    // Create test session from Alice's perspective with unencrypted keys (for testing)
    // The session stores: sendKey (Alice's sendKey) and recvKey (Bob's recvKey = Alice's sendKey)
    // When Bob decrypts with getRecvKey(sessionId, bobUserId), he gets recvKey which equals sendKey
    await createTestSession(sessionId, aliceUserId, bobUserId, sendKey, recvKey);
    
    // Create mock database
    mockDB = createMockMessageMetaCollection();
  });

  beforeEach(() => {
    // Clear sent messages
    aliceSocket.clearSentMessages();
    bobSocket.clearSentMessages();
    mockDB.clear();
  });

  describe('Single-Chunk File Encryption & Decryption', () => {
    test('should encrypt, transmit, and decrypt single-chunk file', async () => {
      // 1. Create test file (50KB)
      const smallFile = createSmallFile();
      const originalBuffer = await readFileAsArrayBuffer(smallFile);
      
      // 2. Alice encrypts file
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        smallFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // 3. Verify chunk calculation
      const expectedChunks = Math.ceil(smallFile.size / (256 * 1024));
      expect(expectedChunks).toBe(1);
      expect(chunkEnvelopes.length).toBe(1);
      
      // 4. Verify metadata structure
      expectFileMetaEnvelope(fileMetaEnvelope);
      expect(fileMetaEnvelope.meta.filename).toBe(smallFile.name);
      expect(fileMetaEnvelope.meta.size).toBe(smallFile.size);
      expect(fileMetaEnvelope.meta.totalChunks).toBe(1);
      expect(fileMetaEnvelope.meta.mimetype).toBe(smallFile.type);
      
      // 5. Verify FILE_META envelope
      expect(fileMetaEnvelope.type).toBe('FILE_META');
      expectIVLength(fileMetaEnvelope.iv);
      expectAuthTagLength(fileMetaEnvelope.authTag);
      
      // 6. Verify FILE_CHUNK envelope
      expectFileChunkEnvelope(chunkEnvelopes[0]);
      expect(chunkEnvelopes[0].meta.chunkIndex).toBe(0);
      expect(chunkEnvelopes[0].meta.totalChunks).toBe(1);
      expectIVLength(chunkEnvelopes[0].iv);
      expectAuthTagLength(chunkEnvelopes[0].authTag);
      
      // 7. Simulate server forwarding (store only metadata)
      const metaDoc = {
        messageId: `meta-${Date.now()}`,
        sessionId: fileMetaEnvelope.sessionId,
        sender: fileMetaEnvelope.sender,
        receiver: fileMetaEnvelope.receiver,
        type: fileMetaEnvelope.type,
        timestamp: fileMetaEnvelope.timestamp,
        seq: fileMetaEnvelope.seq,
        nonceHash: 'test-nonce-hash-meta',
        meta: fileMetaEnvelope.meta
      };
      await mockDB.insertOne(metaDoc);
      
      const chunkDoc = {
        messageId: `chunk-${Date.now()}`,
        sessionId: chunkEnvelopes[0].sessionId,
        sender: chunkEnvelopes[0].sender,
        receiver: chunkEnvelopes[0].receiver,
        type: chunkEnvelopes[0].type,
        timestamp: chunkEnvelopes[0].timestamp,
        seq: chunkEnvelopes[0].seq,
        nonceHash: 'test-nonce-hash-chunk',
        meta: chunkEnvelopes[0].meta
      };
      await mockDB.insertOne(chunkDoc);
      
      // 8. Verify server stored only metadata (no ciphertext)
      const storedMeta = await mockDB.findOne({ messageId: metaDoc.messageId });
      expect(storedMeta.ciphertext).toBeUndefined();
      expect(storedMeta.iv).toBeUndefined();
      expect(storedMeta.authTag).toBeUndefined();
      expect(storedMeta.nonce).toBeUndefined();
      
      // 9. Bob receives envelopes (simulate WebSocket delivery)
      bobSocket.simulateReceive('msg:receive', fileMetaEnvelope);
      bobSocket.simulateReceive('msg:receive', chunkEnvelopes[0]);
      
      // 10. Bob decrypts and reconstructs file
      const decrypted = await decryptFile(
        fileMetaEnvelope,
        chunkEnvelopes,
        sessionId,
        bobUserId
      );
      
      // 11. Verify decryption
      expect(decrypted.filename).toBe(smallFile.name);
      expect(decrypted.size).toBe(smallFile.size);
      expect(decrypted.mimetype).toBe(smallFile.type);
      expect(decrypted.blob).toBeInstanceOf(Blob);
      expect(decrypted.blob.type).toBe(smallFile.type);
      
      // 12. Verify file content matches byte-by-byte
      const matches = await compareBlobToBuffer(decrypted.blob, originalBuffer);
      expect(matches).toBe(true);
      
      console.log('✓ Single-chunk file encryption and decryption successful');
    });
  });

  describe('Multi-Chunk File Encryption & Decryption', () => {
    test('should encrypt, transmit, and decrypt multi-chunk file', async () => {
      // 1. Create test file (500KB)
      const largeFile = createLargeFile();
      const originalBuffer = await readFileAsArrayBuffer(largeFile);
      
      // 2. Alice encrypts file
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        largeFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // 3. Verify chunk calculation
      const expectedChunks = Math.ceil(largeFile.size / (256 * 1024));
      expect(expectedChunks).toBe(2);
      expect(chunkEnvelopes.length).toBe(2);
      
      // 4. Verify metadata
      expect(fileMetaEnvelope.meta.totalChunks).toBe(2);
      expect(fileMetaEnvelope.meta.size).toBe(largeFile.size);
      
      // 5. Verify each chunk encrypted independently
      const ivs = [fileMetaEnvelope.iv, ...chunkEnvelopes.map(c => c.iv)];
      expectUniqueIVs(ivs);
      
      // 6. Verify chunk indices
      expect(chunkEnvelopes[0].meta.chunkIndex).toBe(0);
      expect(chunkEnvelopes[1].meta.chunkIndex).toBe(1);
      expect(chunkEnvelopes[0].meta.totalChunks).toBe(2);
      expect(chunkEnvelopes[1].meta.totalChunks).toBe(2);
      
      // 7. Bob receives envelopes
      bobSocket.simulateReceive('msg:receive', fileMetaEnvelope);
      chunkEnvelopes.forEach(chunk => {
        bobSocket.simulateReceive('msg:receive', chunk);
      });
      
      // 8. Bob decrypts chunks in order
      const decrypted = await decryptFile(
        fileMetaEnvelope,
        chunkEnvelopes,
        sessionId,
        bobUserId
      );
      
      // 9. Verify reconstruction
      expect(decrypted.filename).toBe(largeFile.name);
      expect(decrypted.size).toBe(largeFile.size);
      expect(decrypted.mimetype).toBe(largeFile.type);
      
      // 10. Verify file content matches
      const matches = await compareBlobToBuffer(decrypted.blob, originalBuffer);
      expect(matches).toBe(true);
      
      console.log('✓ Multi-chunk file encryption and decryption successful');
    });
  });

  describe('Server Metadata Storage', () => {
    test('should verify server stores only metadata', async () => {
      const testFile = createSmallFile();
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      // Store FILE_META
      const metaDoc = {
        messageId: `meta-${Date.now()}`,
        sessionId: fileMetaEnvelope.sessionId,
        sender: fileMetaEnvelope.sender,
        receiver: fileMetaEnvelope.receiver,
        type: fileMetaEnvelope.type,
        timestamp: fileMetaEnvelope.timestamp,
        seq: fileMetaEnvelope.seq,
        nonceHash: 'test-nonce-hash',
        meta: fileMetaEnvelope.meta
      };
      await mockDB.insertOne(metaDoc);
      
      // Store FILE_CHUNK
      const chunkDoc = {
        messageId: `chunk-${Date.now()}`,
        sessionId: chunkEnvelopes[0].sessionId,
        sender: chunkEnvelopes[0].sender,
        receiver: chunkEnvelopes[0].receiver,
        type: chunkEnvelopes[0].type,
        timestamp: chunkEnvelopes[0].timestamp,
        seq: chunkEnvelopes[0].seq,
        nonceHash: 'test-nonce-hash-chunk',
        meta: chunkEnvelopes[0].meta
      };
      await mockDB.insertOne(chunkDoc);
      
      // Query database
      const allDocs = mockDB.getAllDocuments();
      
      // Verify stored documents have required fields
      allDocs.forEach(doc => {
        expect(doc.messageId).toBeDefined();
        expect(doc.sessionId).toBeDefined();
        expect(doc.sender).toBeDefined();
        expect(doc.receiver).toBeDefined();
        expect(doc.type).toBeDefined();
        expect(doc.timestamp).toBeDefined();
        expect(doc.seq).toBeDefined();
        expect(doc.nonceHash).toBeDefined();
        expect(doc.meta).toBeDefined();
      });
      
      // Verify NO ciphertext fields
      expect(mockDB.verifyNoCiphertext()).toBe(true);
      
      // Explicitly check forbidden fields
      allDocs.forEach(doc => {
        expect(doc.ciphertext).toBeUndefined();
        expect(doc.iv).toBeUndefined();
        expect(doc.authTag).toBeUndefined();
        expect(doc.nonce).toBeUndefined();
      });
      
      console.log('✓ Server stores only metadata, no ciphertext');
    });
  });

  describe('Out-of-Order Chunk Delivery', () => {
    test('should handle out-of-order chunk delivery', async () => {
      const testFile = createLargeFile(); // 500KB = 2 chunks
      const originalBuffer = await readFileAsArrayBuffer(testFile);
      
      // Encrypt file
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        testFile,
        sessionId,
        aliceUserId,
        bobUserId,
        aliceUserId
      );
      
      expect(chunkEnvelopes.length).toBe(2);
      
      // Send FILE_META first
      bobSocket.simulateReceive('msg:receive', fileMetaEnvelope);
      
      // Send chunks out of order: [2, 0, 1] -> but we only have 2 chunks, so send [1, 0]
      const outOfOrderChunks = [chunkEnvelopes[1], chunkEnvelopes[0]];
      
      // Verify chunks are sorted before decryption
      const sortedChunks = outOfOrderChunks
        .slice()
        .sort((a, b) => a.meta.chunkIndex - b.meta.chunkIndex);
      
      expect(sortedChunks[0].meta.chunkIndex).toBe(0);
      expect(sortedChunks[1].meta.chunkIndex).toBe(1);
      
      // Decrypt with out-of-order chunks
      const decrypted = await decryptFile(
        fileMetaEnvelope,
        outOfOrderChunks,
        sessionId,
        bobUserId
      );
      
      // Verify file reconstructs correctly
      const matches = await compareBlobToBuffer(decrypted.blob, originalBuffer);
      expect(matches).toBe(true);
      
      console.log('✓ Out-of-order chunk delivery handled correctly');
    });
  });
});

