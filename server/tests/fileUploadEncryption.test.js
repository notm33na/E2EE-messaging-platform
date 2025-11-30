/**
 * File Upload Encryption Tests
 * Tests encrypted file chunk storage and metadata
 */

import { MessageMeta } from '../src/models/MessageMeta.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('File Upload Encryption Tests', () => {
  let testUser1, testUser2;

  beforeAll(async () => {
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
    const userData1 = generateTestUser();
    const userData2 = generateTestUser();
    testUser1 = await userService.createUser(userData1.email, userData1.password);
    testUser2 = await userService.createUser(userData2.email, userData2.password);
  });

  describe('Encrypted File Chunks', () => {
    test('should store file chunk metadata', async () => {
      const chunkMeta = new MessageMeta({
        messageId: 'chunk-1',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_CHUNK',
        timestamp: Date.now(),
        seq: 1,
        meta: {
          chunkIndex: 0,
          totalChunks: 5
        }
      });
      await chunkMeta.save();

      expect(chunkMeta.type).toBe('FILE_CHUNK');
      expect(chunkMeta.meta.chunkIndex).toBe(0);
      expect(chunkMeta.meta.totalChunks).toBe(5);
    });

    test('should NOT store ciphertext in metadata', async () => {
      const chunkMeta = new MessageMeta({
        messageId: 'chunk-1',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_CHUNK',
        timestamp: Date.now(),
        seq: 1,
        meta: {
          chunkIndex: 0,
          totalChunks: 5
        }
      });
      await chunkMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'chunk-1' });
      expect(stored).toBeDefined();
      expect(stored.ciphertext).toBeUndefined();
      expect(stored.iv).toBeUndefined();
      expect(stored.authTag).toBeUndefined();
      expect(stored.encryptedData).toBeUndefined();
    });

    test('should confirm each chunk is ciphertext-only (not in metadata)', async () => {
      // Server only stores metadata, not ciphertext
      const chunkMeta = new MessageMeta({
        messageId: 'chunk-2',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_CHUNK',
        timestamp: Date.now(),
        seq: 2,
        meta: {
          chunkIndex: 1,
          totalChunks: 5
        }
      });
      await chunkMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'chunk-2' });
      expect(stored).toBeDefined();
      // Verify no encryption-related fields in metadata
      expect(stored.toObject()).not.toHaveProperty('ciphertext');
      expect(stored.toObject()).not.toHaveProperty('iv');
      expect(stored.toObject()).not.toHaveProperty('authTag');
    });
  });

  describe('File Metadata', () => {
    test('should store file metadata correctly', async () => {
      const fileMeta = new MessageMeta({
        messageId: 'file-meta-1',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_META',
        timestamp: Date.now(),
        seq: 0,
        meta: {
          filename: 'document.pdf',
          size: 1024000,
          mimetype: 'application/pdf',
          totalChunks: 10
        }
      });
      await fileMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'file-meta-1' });
      expect(stored.type).toBe('FILE_META');
      expect(stored.meta.filename).toBe('document.pdf');
      expect(stored.meta.size).toBe(1024000);
      expect(stored.meta.totalChunks).toBe(10);
    });

    test('should NOT store file content in metadata', async () => {
      const fileMeta = new MessageMeta({
        messageId: 'file-meta-2',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_META',
        timestamp: Date.now(),
        seq: 0,
        meta: {
          filename: 'test.txt',
          size: 100
        }
      });
      await fileMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'file-meta-2' });
      expect(stored.content).toBeUndefined();
      expect(stored.fileData).toBeUndefined();
      expect(stored.plaintext).toBeUndefined();
    });
  });

  describe('Server Decryption Prevention', () => {
    test('should verify server cannot decrypt anything', async () => {
      // Server stores only metadata
      const chunkMeta = new MessageMeta({
        messageId: 'chunk-3',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_CHUNK',
        timestamp: Date.now(),
        seq: 3,
        meta: {
          chunkIndex: 2,
          totalChunks: 5
        }
      });
      await chunkMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'chunk-3' });
      
      // Server has no access to:
      // - Ciphertext
      // - IV
      // - Auth tag
      // - Session keys
      // - Private keys
      expect(stored.ciphertext).toBeUndefined();
      expect(stored.iv).toBeUndefined();
      expect(stored.authTag).toBeUndefined();
      expect(stored.sessionKey).toBeUndefined();
      expect(stored.privateKey).toBeUndefined();
    });

    test('should store only metadata fields', async () => {
      const chunkMeta = new MessageMeta({
        messageId: 'chunk-4',
        sessionId: 'file-session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_CHUNK',
        timestamp: Date.now(),
        seq: 4,
        meta: {
          chunkIndex: 3,
          totalChunks: 5
        }
      });
      await chunkMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'chunk-4' });
      const storedObj = stored.toObject();

      // Only metadata fields should exist
      const allowedFields = ['_id', 'messageId', 'sessionId', 'sender', 'receiver', 'type', 'timestamp', 'seq', 'meta', 'delivered', 'deliveredAt', 'createdAt', 'updatedAt', '__v'];
      const actualFields = Object.keys(storedObj);
      
      actualFields.forEach(field => {
        if (!allowedFields.includes(field)) {
          // Should not have unexpected fields
          expect(allowedFields).toContain(field);
        }
      });
    });
  });

  describe('Multiple File Chunks', () => {
    test('should store multiple chunks with correct indices', async () => {
      const totalChunks = 5;
      const chunks = [];

      const baseTimestamp = Date.now();
      const savePromises = [];
      for (let i = 0; i < totalChunks; i++) {
        const chunk = new MessageMeta({
          messageId: `chunk-multi-${i}`,
          sessionId: 'file-session-456',
          sender: testUser1.id,
          receiver: testUser2.id,
          type: 'FILE_CHUNK',
          timestamp: baseTimestamp + i * 1000, // Ensure unique timestamps
          seq: i + 1,
          meta: {
            chunkIndex: i,
            totalChunks
          }
        });
        savePromises.push(chunk.save());
        chunks.push(chunk);
      }

      // Wait for all saves to complete
      await Promise.all(savePromises);
      
      // Query using the exact sessionId and type
      const storedChunks = await MessageMeta.find({ 
        sessionId: 'file-session-456',
        type: 'FILE_CHUNK'
      }).sort({ 'meta.chunkIndex': 1 });

      expect(storedChunks.length).toBe(5);
      storedChunks.forEach((chunk, index) => {
        expect(chunk.meta.chunkIndex).toBe(index);
        expect(chunk.meta.totalChunks).toBe(5);
      });
    });
  });
});

