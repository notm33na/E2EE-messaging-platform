/**
 * File Encryption Metadata Tests
 * Ensures file uploads are represented only as encrypted/chunk metadata.
 */

import { MessageMeta } from '../src/models/MessageMeta.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('File Encryption Metadata Tests', () => {
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

  test('stores file metadata without file content', async () => {
    const fileMeta = new MessageMeta({
      messageId: 'file-up-1',
      sessionId: 'file-session-1',
      sender: sender.id,
      receiver: receiver.id,
      type: 'FILE_META',
      timestamp: Date.now(),
      seq: 0,
      meta: {
        filename: 'secret.pdf',
        size: 2048,
        mimetype: 'application/pdf',
        totalChunks: 4
      }
    });
    await fileMeta.save();

    const stored = await MessageMeta.findOne({ messageId: 'file-up-1' });
    const obj = stored.toObject();

    expect(obj.meta.filename).toBe('secret.pdf');
    expect(obj.content).toBeUndefined();
    expect(obj.fileData).toBeUndefined();
    expect(obj.plaintext).toBeUndefined();
  });

  test('stores encrypted file chunks as metadata only', async () => {
    const chunk = new MessageMeta({
      messageId: 'file-chunk-1',
      sessionId: 'file-session-1',
      sender: sender.id,
      receiver: receiver.id,
      type: 'FILE_CHUNK',
      timestamp: Date.now(),
      seq: 1,
      meta: {
        chunkIndex: 0,
        totalChunks: 4
      }
    });
    await chunk.save();

    const stored = await MessageMeta.findOne({ messageId: 'file-chunk-1' });

    expect(stored.type).toBe('FILE_CHUNK');
    expect(stored.meta.chunkIndex).toBe(0);
    expect(stored.ciphertext).toBeUndefined();
    expect(stored.iv).toBeUndefined();
    expect(stored.authTag).toBeUndefined();
  });
});


