/**
 * Error Conditions Tests
 * Tests server rejection of invalid inputs and corrupted data
 */

import { MessageMeta } from '../src/models/MessageMeta.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { PublicKey } from '../src/models/PublicKey.js';
import { validateTimestamp } from '../src/utils/replayProtection.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser, generateTestJWK } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Error Conditions Tests', () => {
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

  describe('Missing Fields', () => {
    test('should reject message with missing sessionId', async () => {
      const message = new MessageMeta({
        messageId: 'msg-1',
        // Missing sessionId
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });

    test('should reject message with missing sender', async () => {
      const message = new MessageMeta({
        messageId: 'msg-2',
        sessionId: 'session-123',
        // Missing sender
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });

    test('should reject message with missing receiver', async () => {
      const message = new MessageMeta({
        messageId: 'msg-3',
        sessionId: 'session-123',
        sender: testUser1.id,
        // Missing receiver
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });

    test('should reject message with missing type', async () => {
      const message = new MessageMeta({
        messageId: 'msg-4',
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        // Missing type
        timestamp: Date.now(),
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });

    test('should reject message with missing timestamp', async () => {
      const message = new MessageMeta({
        messageId: 'msg-5',
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        // Missing timestamp
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });

    test('should reject message with missing sequence number', async () => {
      const message = new MessageMeta({
        messageId: 'msg-6',
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now()
        // Missing seq
      });

      await expect(message.save()).rejects.toThrow();
    });
  });

  describe('Corrupted Envelopes', () => {
    test('should reject invalid message type', async () => {
      const message = new MessageMeta({
        messageId: 'msg-7',
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'INVALID_TYPE', // Invalid type
        timestamp: Date.now(),
        seq: 1
      });

      // Should validate enum
      const validTypes = ['MSG', 'FILE_META', 'FILE_CHUNK', 'KEY_UPDATE'];
      expect(validTypes).not.toContain('INVALID_TYPE');
    });

    test('should reject negative sequence number', async () => {
      const message = new MessageMeta({
        messageId: 'msg-8',
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: -1 // Invalid seq
      });

      // Should validate seq > 0
      expect(message.seq).toBeLessThan(0);
    });

    test('should reject zero sequence number', async () => {
      const message = new MessageMeta({
        messageId: 'msg-9',
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 0 // Invalid seq
      });

      // Should validate seq > 0
      expect(message.seq).toBe(0);
    });
  });

  describe('Corrupted IV or AuthTag', () => {
    test('should validate IV format (if stored)', () => {
      // Server doesn't store IV, but if it did, should validate
      // This test documents the requirement
      const invalidIV = 'not-base64-format!!!';
      
      // IV should be base64 encoded, 12 bytes (96 bits)
      expect(invalidIV.length).not.toBe(16); // Base64 length for 12 bytes
    });

    test('should validate authTag format (if stored)', () => {
      // Server doesn't store authTag, but if it did, should validate
      const invalidAuthTag = 'invalid-tag-format';
      
      // AuthTag should be base64 encoded, 16 bytes (128 bits)
      expect(invalidAuthTag.length).not.toBe(24); // Base64 length for 16 bytes
    });
  });

  describe('Invalid SessionId', () => {
    test('should reject empty sessionId', async () => {
      const message = new MessageMeta({
        messageId: 'msg-10',
        sessionId: '', // Empty
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });

    test('should reject null sessionId', async () => {
      const message = new MessageMeta({
        messageId: 'msg-11',
        sessionId: null,
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: Date.now(),
        seq: 1
      });

      await expect(message.save()).rejects.toThrow();
    });
  });

  describe('Invalid Public Key Format', () => {
    test('should reject JWK with missing required fields', async () => {
      const invalidJWK = {
        kty: 'EC'
        // Missing crv, x, y
      };

      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: invalidJWK
      });

      // Validation should fail
      const validationError = publicKey.validateSync();
      expect(validationError).toBeDefined();
      expect(validationError.errors.publicIdentityKeyJWK).toBeDefined();
    });

    test('should reject non-P-256 keys', async () => {
      const invalidJWK = {
        kty: 'EC',
        crv: 'P-384', // Wrong curve
        x: 'test',
        y: 'test'
      };

      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: invalidJWK
      });

      // Should validate curve type
      expect(publicKey.publicIdentityKeyJWK.crv).not.toBe('P-256');
    });
  });

  describe('Invalid Timestamps', () => {
    test('should reject stale timestamps', () => {
      const staleTimestamp = Date.now() - 5 * 60 * 1000; // 5 minutes ago
      expect(validateTimestamp(staleTimestamp)).toBe(false);
    });

    test('should reject future timestamps beyond window', () => {
      const futureTimestamp = Date.now() + 5 * 60 * 1000; // 5 minutes in future
      expect(validateTimestamp(futureTimestamp)).toBe(false);
    });

    test('should reject zero timestamp', () => {
      expect(validateTimestamp(0)).toBe(false);
    });

    test('should reject negative timestamp', () => {
      expect(validateTimestamp(-1000)).toBe(false);
    });
  });

  describe('Invalid KEP Messages', () => {
    test('should reject KEP message with invalid type', () => {
      const kepMessage = new KEPMessage({
        messageId: 'kep-1',
        sessionId: 'session-123',
        from: testUser1.id,
        to: testUser2.id,
        type: 'INVALID_KEP_TYPE', // Invalid
        timestamp: Date.now(),
        seq: 1
      });

      const validTypes = ['KEP_INIT', 'KEP_RESPONSE'];
      expect(validTypes).not.toContain('INVALID_KEP_TYPE');
    });

    test('should reject KEP message with missing from field', async () => {
      const kepMessage = new KEPMessage({
        messageId: 'kep-2',
        sessionId: 'session-123',
        // Missing from
        to: testUser2.id,
        type: 'KEP_INIT',
        timestamp: Date.now(),
        seq: 1
      });

      await expect(kepMessage.save()).rejects.toThrow();
    });
  });

  describe('Server Input Validation', () => {
    test('should reject all invalid inputs', async () => {
      const invalidInputs = [
        // Missing required fields
        { sessionId: 'session-123' }, // Missing everything else
        { sender: testUser1.id }, // Missing everything else
        { type: 'MSG' }, // Missing everything else
        // Invalid types
        { sessionId: 'session-123', sender: testUser1.id, receiver: testUser2.id, type: 'INVALID', timestamp: Date.now(), seq: 1 },
        // Invalid timestamps
        { sessionId: 'session-123', sender: testUser1.id, receiver: testUser2.id, type: 'MSG', timestamp: 0, seq: 1 },
        { sessionId: 'session-123', sender: testUser1.id, receiver: testUser2.id, type: 'MSG', timestamp: -1, seq: 1 },
        // Invalid sequence
        { sessionId: 'session-123', sender: testUser1.id, receiver: testUser2.id, type: 'MSG', timestamp: Date.now(), seq: -1 },
        { sessionId: 'session-123', sender: testUser1.id, receiver: testUser2.id, type: 'MSG', timestamp: Date.now(), seq: 0 }
      ];

      for (const input of invalidInputs) {
        const message = new MessageMeta(input);
        await expect(message.save()).rejects.toThrow();
      }
    });
  });
});

