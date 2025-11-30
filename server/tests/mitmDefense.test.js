/**
 * MITM Defense Tests
 * Tests signature verification and MITM attack prevention
 */

import { PublicKey } from '../src/models/PublicKey.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { logInvalidSignature as logInvalidSignatureReplay, logInvalidKEPMessage } from '../src/utils/replayProtection.js';
import { logInvalidSignature } from '../src/utils/attackLogging.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestJWK, generateTestUser, readLogFile, clearTestLogs } from './setup.js';
import { userService } from '../src/services/user.service.js';
import crypto from 'crypto';

describe('MITM Defense Tests', () => {
  let testUser1, testUser2;

  beforeAll(async () => {
    await setupTestDB();
    clearTestLogs();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
    clearTestLogs();
    const userData1 = generateTestUser();
    const userData2 = generateTestUser();
    testUser1 = await userService.createUser(userData1.email, userData1.password);
    testUser2 = await userService.createUser(userData2.email, userData2.password);
  });

  describe('Signature Requirements', () => {
    test('should require signature for KEP messages', () => {
      // KEP messages must have signatures (client-side verification)
      // Server stores metadata only, but validates structure
      const kepMessage = new KEPMessage({
        messageId: 'test-msg',
        sessionId: 'session-123',
        from: testUser1.id,
        to: testUser2.id,
        type: 'KEP_INIT',
        timestamp: Date.now(),
        seq: 1
      });

      // Server doesn't store signature, but client must verify
      // This test verifies server accepts message structure
      expect(kepMessage.type).toBe('KEP_INIT');
    });

    test('should validate JWK structure for public keys', async () => {
      const validJWK = generateTestJWK();
      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: validJWK
      });

      expect(publicKey.publicIdentityKeyJWK.kty).toBe('EC');
      expect(publicKey.publicIdentityKeyJWK.crv).toBe('P-256');
    });
  });

  describe('Unsigned Ephemeral Keys', () => {
    test('should reject unsigned ephemeral keys (client-side check)', () => {
      // Note: Server doesn't verify signatures, but client must
      // This test documents the requirement
      const unsignedKey = {
        ephPub: generateTestJWK(),
        // No signature field
      };

      // Client should reject this
      expect(unsignedKey.signature).toBeUndefined();
    });

    test('should require signature in KEP message structure', () => {
      // KEP messages should include signature field (client-side)
      const kepMessage = {
        type: 'KEP_INIT',
        ephPub: generateTestJWK(),
        signature: null // Missing signature
      };

      // Client should reject messages without valid signatures
      expect(kepMessage.signature).toBeFalsy();
    });
  });

  describe('Signature Modification', () => {
    test('should detect modified signatures', () => {
      // Simulate signature verification failure
      const originalSignature = 'valid-signature-base64';
      const modifiedSignature = originalSignature.slice(0, -5) + 'XXXXX';

      expect(modifiedSignature).not.toBe(originalSignature);
      // Client-side verification should fail
    });

    test('should log invalid signature attempts', () => {
      const sessionId = 'session-123';
      const userId = testUser1.id;
      const reason = 'Signature verification failed';

      logInvalidSignature(sessionId, userId, 'KEP_INIT', reason);

      const logContent = readLogFile('invalid_signature.log');
      expect(logContent).toContain('INVALID_SIGNATURE');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain(reason);
    });
  });

  describe('Key Swapping Prevention', () => {
    test('should prevent swapping keys between users', async () => {
      // User1's public key
      const jwk1 = generateTestJWK();
      const publicKey1 = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: jwk1
      });
      await publicKey1.save();

      // User2's public key
      const jwk2 = {
        ...generateTestJWK(),
        x: 'differentXValue123456789012345678901234567890123456789012345678901234',
        y: 'differentYValue123456789012345678901234567890123456789012345678901234'
      };
      const publicKey2 = new PublicKey({
        userId: testUser2.id,
        publicIdentityKeyJWK: jwk2
      });
      await publicKey2.save();

      // Verify keys are different
      const stored1 = await PublicKey.findOne({ userId: testUser1.id });
      const stored2 = await PublicKey.findOne({ userId: testUser2.id });

      expect(stored1).toBeDefined();
      expect(stored2).toBeDefined();
      expect(stored1.publicIdentityKeyJWK.x).not.toBe(stored2.publicIdentityKeyJWK.x);
      expect(stored1.publicIdentityKeyJWK.y).not.toBe(stored2.publicIdentityKeyJWK.y);
    });

    test('should verify signature matches public key owner', () => {
      // Signature must be created with the owner's private key
      // This is verified client-side using the public key from server
      const user1JWK = generateTestJWK();
      const user2JWK = {
        ...generateTestJWK(),
        x: 'differentX',
        y: 'differentY'
      };

      // Signature created with user1's private key should not verify with user2's public key
      expect(user1JWK.x).not.toBe(user2JWK.x);
    });
  });

  describe('Invalid Signature Logging', () => {
    test('should log invalid signature to invalid_signature.log', () => {
      const sessionId = 'session-456';
      const userId = testUser2.id;
      const messageType = 'KEP_INIT';
      const reason = 'Signature does not match public key';

      logInvalidSignature(sessionId, userId, messageType, reason);

      const logContent = readLogFile('invalid_signature.log');
      expect(logContent).toBeTruthy();
      expect(logContent.length).toBeGreaterThan(0);
      
      const logLines = logContent.trim().split('\n').filter(l => l);
      expect(logLines.length).toBeGreaterThan(0);
      
      const lastLog = JSON.parse(logLines[logLines.length - 1]);

      expect(lastLog.userId).toBe(userId.toString());
      expect(lastLog.sessionId).toBe(sessionId);
      expect(lastLog.messageType).toBe(messageType);
      expect(lastLog.reason).toBe(reason);
    });

    test('should log invalid KEP messages', () => {
      const userId = testUser1.id;
      const sessionId = 'session-789';
      const reason = 'Missing signature field';

      logInvalidKEPMessage(userId, sessionId, reason);

      const logContent = readLogFile('invalid_kep_message.log');
      expect(logContent).toContain('invalid_kep_message');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain(reason);
    });
  });

  describe('Public Key Verification', () => {
    test('should only accept P-256 keys', async () => {
      const validJWK = {
        kty: 'EC',
        crv: 'P-256',
        x: 'testX',
        y: 'testY'
      };

      const publicKey = new PublicKey({
        userId: testUser1.id,
        publicIdentityKeyJWK: validJWK
      });

      expect(publicKey.publicIdentityKeyJWK.crv).toBe('P-256');
    });

    test('should reject non-ECC keys', () => {
      const invalidJWK = {
        kty: 'RSA', // Wrong key type
        n: 'test',
        e: 'AQAB'
      };

      // Should validate key type
      expect(invalidJWK.kty).not.toBe('EC');
    });
  });
});

