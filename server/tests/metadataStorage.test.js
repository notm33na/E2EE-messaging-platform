/**
 * Metadata Storage Tests
 * Tests message and file metadata storage without plaintext
 */

// Jest globals are available in test environment
import { MessageMeta } from '../src/models/MessageMeta.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Metadata Storage Tests', () => {
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

  describe('Message Metadata Storage', () => {
    test('should store message metadata', async () => {
      const messageMeta = new MessageMeta({
        messageId: 'msg-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1,
        meta: {}
      });
      await messageMeta.save();

      expect(messageMeta.sender.toString()).toBe(testUser1.id.toString());
      expect(messageMeta.receiver.toString()).toBe(testUser2.id.toString());
      expect(messageMeta.type).toBe('MSG');
    });

    test('should NOT store plaintext in metadata', async () => {
      const messageMeta = new MessageMeta({
        messageId: 'msg-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });
      await messageMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'msg-123' });
      expect(stored.plaintext).toBeUndefined();
      expect(stored.message).toBeUndefined();
      expect(stored.content).toBeUndefined();
      expect(stored.ciphertext).toBeUndefined(); // Ciphertext should not be in metadata
    });

    test('should store only metadata fields', async () => {
      const messageMeta = new MessageMeta({
        messageId: 'msg-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1,
        meta: { someMeta: 'value' }
      });
      await messageMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'msg-123' });
      expect(stored.messageId).toBeDefined();
      expect(stored.sessionId).toBeDefined();
      expect(stored.sender).toBeDefined();
      expect(stored.receiver).toBeDefined();
      expect(stored.timestamp).toBeDefined();
      expect(stored.seq).toBeDefined();
    });
  });

  describe('File Metadata Storage', () => {
    test('should store file metadata', async () => {
      const fileMeta = new MessageMeta({
        messageId: 'file-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_META',
        timestamp: Date.now(),
        seq: 1,
        meta: {
          filename: 'test.pdf',
          size: 1024,
          mimetype: 'application/pdf',
          totalChunks: 5
        }
      });
      await fileMeta.save();

      expect(fileMeta.type).toBe('FILE_META');
      expect(fileMeta.meta.filename).toBe('test.pdf');
      expect(fileMeta.meta.size).toBe(1024);
    });

    test('should store file chunk metadata', async () => {
      const chunkMeta = new MessageMeta({
        messageId: 'chunk-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_CHUNK',
        timestamp: Date.now(),
        seq: 2,
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

    test('should NOT store file content in metadata', async () => {
      const fileMeta = new MessageMeta({
        messageId: 'file-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'FILE_META',
        timestamp: Date.now(),
        seq: 1,
        meta: {
          filename: 'test.pdf',
          size: 1024
        }
      });
      await fileMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'file-123' });
      expect(stored).toBeDefined();
      expect(stored.content).toBeUndefined();
      expect(stored.fileData).toBeUndefined();
      expect(stored.plaintext).toBeUndefined();
      expect(stored.ciphertext).toBeUndefined();
    });
  });

  describe('Query and Pagination', () => {
    test('should query messages by receiver', async () => {
      // Create multiple messages
      const baseTimestamp = Date.now();
      const savePromises = [];
      for (let i = 0; i < 5; i++) {
        const messageMeta = new MessageMeta({
          messageId: `msg-query-${i}`,
          sessionId: 'session-abc',
          sender: testUser1.id,
          receiver: testUser2.id,
          type: 'MSG',
          timestamp: baseTimestamp + i * 1000, // Ensure unique timestamps
          seq: i + 1
        });
        savePromises.push(messageMeta.save());
      }

      // Wait for all saves to complete
      await Promise.all(savePromises);
      
      // Query messages - Mongoose handles ObjectId conversion automatically
      const messages = await MessageMeta.find({ receiver: testUser2.id })
        .sort({ seq: 1 });

      expect(messages.length).toBe(5);
      expect(messages[0].seq).toBe(1);
      expect(messages[4].seq).toBe(5);
    });

    test('should paginate messages correctly', async () => {
      // Create 10 messages
      const baseTimestamp = Date.now();
      for (let i = 0; i < 10; i++) {
        const messageMeta = new MessageMeta({
          messageId: `msg-page-${i}`,
          sessionId: 'session-abc',
          sender: testUser1.id,
          receiver: testUser2.id,
          type: 'MSG',
          timestamp: baseTimestamp + i * 1000, // Ensure unique timestamps
          seq: i + 1
        });
        await messageMeta.save();
      }

      const page1 = await MessageMeta.find({ receiver: testUser2.id })
        .sort({ seq: 1 })
        .limit(5)
        .skip(0);

      const page2 = await MessageMeta.find({ receiver: testUser2.id })
        .sort({ seq: 1 })
        .limit(5)
        .skip(5);

      expect(page1.length).toBe(5);
      expect(page2.length).toBe(5);
      expect(page1[0].seq).toBe(1);
      expect(page2[0].seq).toBe(6);
    });

    test('should filter by delivered status', async () => {
      const delivered = new MessageMeta({
        messageId: 'msg-delivered',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1,
        delivered: true
      });
      await delivered.save();

      const pending = new MessageMeta({
        messageId: 'msg-pending',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 2,
        delivered: false
      });
      await pending.save();

      const pendingMessages = await MessageMeta.find({ receiver: testUser2.id, delivered: false });
      expect(pendingMessages.length).toBe(1);
      expect(pendingMessages[0].messageId).toBe('msg-pending');
    });
  });

  describe('Plaintext Prevention', () => {
    test('should ensure NO plaintext fields exist in schema', async () => {
      const messageMeta = new MessageMeta({
        messageId: 'msg-123',
        sessionId: 'session-abc',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });
      await messageMeta.save();

      const stored = await MessageMeta.findOne({ messageId: 'msg-123' });
      const storedObj = stored.toObject();

      // Verify no plaintext-related fields
      const forbiddenFields = ['plaintext', 'message', 'content', 'text', 'body', 'data'];
      forbiddenFields.forEach(field => {
        expect(storedObj[field]).toBeUndefined();
      });
    });
  });
});

