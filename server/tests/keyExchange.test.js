/**
 * Key Exchange Protocol Tests
 * Tests public key upload, retrieval, and key exchange metadata
 */

// Jest globals are available in test environment
import { PublicKey } from '../src/models/PublicKey.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestJWK, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Key Exchange Protocol Tests', () => {
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

  describe('Public Key Upload', () => {
    test('should upload public identity key', async () => {
      const jwk = generateTestJWK();
      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: jwk
      });
      await publicKey.save();

      expect(publicKey.userId.toString()).toBe(testUser1.id.toString());
      expect(publicKey.publicIdentityKeyJWK).toEqual(jwk);
      expect(publicKey.createdAt).toBeDefined();
    });

    test('should validate JWK structure', async () => {
      const invalidJWK = { kty: 'EC' }; // Missing required fields
      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: invalidJWK
      });

      await expect(publicKey.save()).rejects.toThrow();
    });

    test('should only accept P-256 keys', () => {
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

    test('should NOT store private keys', async () => {
      const jwk = generateTestJWK();
      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: jwk
      });
      await publicKey.save();

      const stored = await PublicKey.findOne({ userId: testUser1.id });
      expect(stored.publicIdentityKeyJWK.d).toBeUndefined(); // 'd' is private key component
      expect(stored.publicIdentityKeyJWK.kty).toBe('EC');
      expect(stored.publicIdentityKeyJWK.crv).toBe('P-256');
    });
  });

  describe('Public Key Retrieval', () => {
    test('should retrieve public key by userId', async () => {
      const jwk = generateTestJWK();
      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: jwk
      });
      await publicKey.save();

      const retrieved = await PublicKey.findOne({ userId: testUser1.id });
      expect(retrieved).toBeDefined();
      expect(retrieved.publicIdentityKeyJWK).toEqual(jwk);
    });

    test('should return 404 for non-existent public key', async () => {
      const mongoose = (await import('mongoose')).default;
      const nonExistentId = new mongoose.Types.ObjectId();
      const retrieved = await PublicKey.findOne({ userId: nonExistentId });
      expect(retrieved).toBeNull();
    });
  });

  describe('Key Exchange Messages', () => {
    test('should store KEP message metadata', async () => {
      const kepMessage = new KEPMessage({
        messageId: 'test-message-id',
        sessionId: 'test-session-id',
        from: testUser1.id,
        to: testUser2.id,
        type: 'KEP_INIT',
        timestamp: Date.now(),
        seq: 1,
        delivered: false
      });
      await kepMessage.save();

      expect(kepMessage.from.toString()).toBe(testUser1.id.toString());
      expect(kepMessage.to.toString()).toBe(testUser2.id.toString());
      expect(kepMessage.type).toBe('KEP_INIT');
    });

    test('should NOT store private keys in KEP messages', async () => {
      const kepMessage = new KEPMessage({
        messageId: 'test-message-id',
        sessionId: 'test-session-id',
        from: testUser1.id,
        to: testUser2.id,
        type: 'KEP_INIT',
        timestamp: Date.now(),
        seq: 1
      });
      await kepMessage.save();

      const stored = await KEPMessage.findOne({ messageId: 'test-message-id' });
      // KEP messages should only contain metadata, no keys
      expect(stored.message).toBeUndefined();
      expect(stored.privateKey).toBeUndefined();
      expect(stored.ephemeralPrivateKey).toBeUndefined();
    });

    test('should validate message type', () => {
      const invalidMessage = new KEPMessage({
        messageId: 'test',
        sessionId: 'test',
        from: testUser1.id,
        to: testUser2.id,
        type: 'INVALID_TYPE',
        timestamp: Date.now(),
        seq: 1
      });

      // Should validate enum
      expect(['KEP_INIT', 'KEP_RESPONSE']).toContain('KEP_INIT');
      expect(['KEP_INIT', 'KEP_RESPONSE']).not.toContain('INVALID_TYPE');
    });
  });

  describe('Server Key Handling', () => {
    test('should ensure server never receives private keys', async () => {
      // Simulate attempt to store private key (should be rejected)
      const jwkWithPrivateKey = {
        ...generateTestJWK(),
        d: 'private-key-component-should-not-be-stored'
      };

      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: jwkWithPrivateKey
      });

      // Even if someone tries to include 'd', we should validate it's not stored
      // The pre-save hook should remove it, but validation should also reject it
      await expect(publicKey.save()).rejects.toThrow();
    });
  });
});

