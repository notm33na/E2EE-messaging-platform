/**
 * Message Encryption Metadata Tests
 * Verifies that only metadata (no plaintext or key material) is stored for messages.
 */

import { MessageMeta } from '../src/models/MessageMeta.js';
import { validateTimestamp } from '../src/utils/replayProtection.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Message Encryption Metadata Tests', () => {
  let sender;
  let receiver;

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
    sender = await userService.createUser(userData1.email, userData1.password);
    receiver = await userService.createUser(userData2.email, userData2.password);
  });

  test('stores only metadata fields for encrypted messages', async () => {
    const meta = new MessageMeta({
      messageId: 'msg-meta-1',
      sessionId: 'session-enc-1',
      sender: sender.id,
      receiver: receiver.id,
      type: 'MSG',
      timestamp: Date.now(),
      seq: 1,
      meta: { purpose: 'chat' }
    });
    await meta.save();

    const stored = await MessageMeta.findOne({ messageId: 'msg-meta-1' });
    const obj = stored.toObject();

    // Only schema-defined metadata fields should exist
    expect(obj.plaintext).toBeUndefined();
    expect(obj.message).toBeUndefined();
    expect(obj.content).toBeUndefined();
    expect(obj.ciphertext).toBeUndefined();
    expect(obj.iv).toBeUndefined();
    expect(obj.authTag).toBeUndefined();
  });

  test('rejects messages missing required metadata (e.g., timestamp)', async () => {
    const invalid = new MessageMeta({
      messageId: 'msg-meta-2',
      sessionId: 'session-enc-1',
      sender: sender.id,
      receiver: receiver.id,
      type: 'MSG',
      // missing timestamp
      seq: 1
    });

    await expect(invalid.save()).rejects.toThrow();
  });

  test('enforces timestamp freshness window', () => {
    const fresh = Date.now();
    const stale = Date.now() - 3 * 60 * 1000;
    const future = Date.now() + 3 * 60 * 1000;

    expect(validateTimestamp(fresh)).toBe(true);
    expect(validateTimestamp(stale)).toBe(false);
    expect(validateTimestamp(future)).toBe(false);
  });
});


