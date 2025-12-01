/**
 * Schema Validation Tests
 * Ensures MongoDB collections only store approved fields and no secret key material.
 */

import { User } from '../src/models/User.js';
import { PublicKey } from '../src/models/PublicKey.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { MessageMeta } from '../src/models/MessageMeta.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestJWK, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Schema Validation Tests', () => {
  let user;

  beforeAll(async () => {
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
    const userData = generateTestUser();
    user = await userService.createUser(userData.email, userData.password);
  });

  test('User collection only stores approved fields and no plaintext password', async () => {
    const dbUser = await User.findOne({ email: user.email }).select('+passwordHash +refreshTokens');
    const obj = dbUser.toObject();

    const allowedFields = ['_id', 'email', 'passwordHash', 'lastLoginAt', 'refreshTokens', 'isActive', 'createdAt', 'updatedAt', '__v'];
    Object.keys(obj).forEach(field => {
      expect(allowedFields).toContain(field);
    });

    expect(obj.password).toBeUndefined();
    expect(obj.plaintextPassword).toBeUndefined();
  });

  test('PublicKey collection never stores private keys', async () => {
    const jwk = generateTestJWK();
    await new PublicKey({
      userId: user.id,
      publicIdentityKeyJWK: jwk
    }).save();

    const stored = await PublicKey.findOne({ userId: user.id });
    const jwkStored = stored.publicIdentityKeyJWK;

    expect(jwkStored.d).toBeUndefined();
    expect(jwkStored.kty).toBe('EC');
    expect(jwkStored.crv).toBe('P-256');
  });

  test('KEPMessage schema only stores metadata fields', async () => {
    await new KEPMessage({
      messageId: 'schema-kep-1',
      sessionId: 'schema-session',
      from: user.id,
      to: user.id,
      type: 'KEP_INIT',
      timestamp: Date.now(),
      seq: 1
    }).save();

    const stored = await KEPMessage.findOne({ messageId: 'schema-kep-1' });
    const obj = stored.toObject();

    expect(obj.privateKey).toBeUndefined();
    expect(obj.ephemeralPrivateKey).toBeUndefined();
    expect(obj.ciphertext).toBeUndefined();
    expect(obj.iv).toBeUndefined();
    expect(obj.authTag).toBeUndefined();
  });

  test('MessageMeta schema only stores approved metadata fields', async () => {
    await new MessageMeta({
      messageId: 'schema-msg-1',
      sessionId: 'schema-session',
      sender: user.id,
      receiver: user.id,
      type: 'MSG',
      timestamp: Date.now(),
      seq: 1
    }).save();

    const stored = await MessageMeta.findOne({ messageId: 'schema-msg-1' });
    const obj = stored.toObject();

    const allowed = ['_id', 'messageId', 'sessionId', 'sender', 'receiver', 'type', 'timestamp', 'seq', 'delivered', 'deliveredAt', 'meta', 'metadataHash', 'createdAt', 'updatedAt', '__v'];
    Object.keys(obj).forEach(field => {
      expect(allowed).toContain(field);
    });

    expect(obj.plaintext).toBeUndefined();
    expect(obj.message).toBeUndefined();
    expect(obj.content).toBeUndefined();
    expect(obj.ciphertext).toBeUndefined();
    expect(obj.iv).toBeUndefined();
    expect(obj.authTag).toBeUndefined();
  });
});


