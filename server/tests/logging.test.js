/**
 * Logging Tests
 * Tests all logging mechanisms and ensures no plaintext in logs
 */

import { logReplayAttempt, logInvalidSignature, logKeyExchangeAttempt, logAuthenticationAttempt, logFailedDecryption, logMetadataAccess } from '../src/utils/attackLogging.js';
import { logMessageMetadataAccess, logMessageForwarding, logFileChunkForwarding, logReplayDetected } from '../src/utils/messageLogging.js';
import { logInvalidKEPMessage } from '../src/utils/replayProtection.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser, readLogFile, clearTestLogs } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Logging Tests', () => {
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

  describe('Authentication Logs', () => {
    test('should log successful authentication', () => {
      logAuthenticationAttempt(testUser1.id, true, 'Login successful');

      const logContent = readLogFile('authentication_attempts.log');
      expect(logContent).toContain('AUTH_ATTEMPT');
      expect(logContent).toContain(testUser1.id);
      expect(logContent).toContain('ACCEPTED');
    });

    test('should log failed authentication', () => {
      logAuthenticationAttempt(testUser2.id, false, 'Invalid password');

      const logContent = readLogFile('authentication_attempts.log');
      expect(logContent).toContain('AUTH_ATTEMPT');
      expect(logContent).toContain(testUser2.id);
      expect(logContent).toContain('REJECTED');
      expect(logContent).toContain('Invalid password');
    });

    test('should NOT log passwords in authentication logs', () => {
      logAuthenticationAttempt(testUser1.id, false, 'Invalid credentials');

      const logContent = readLogFile('authentication_attempts.log');
      // Should not contain password-related terms
      expect(logContent).not.toMatch(/password/i);
      expect(logContent).not.toMatch(/plaintext/i);
    });
  });

  describe('Key Exchange Logs', () => {
    test('should log key exchange attempts', () => {
      const sessionId = 'session-123';
      logKeyExchangeAttempt(sessionId, testUser1.id, testUser2.id, 'KEP_INIT', true);

      const logContent = readLogFile('key_exchange_attempts.log');
      expect(logContent).toContain('KEY_EXCHANGE');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain(testUser1.id);
      expect(logContent).toContain(testUser2.id);
    });

    test('should log failed key exchange', () => {
      const sessionId = 'session-456';
      logKeyExchangeAttempt(sessionId, testUser1.id, testUser2.id, 'KEP_RESPONSE', false);

      const logContent = readLogFile('key_exchange_attempts.log');
      expect(logContent).toContain('REJECTED');
    });

    test('should NOT log private keys in key exchange logs', () => {
      logKeyExchangeAttempt('session-789', testUser1.id, testUser2.id, 'KEP_INIT', true);

      const logContent = readLogFile('key_exchange_attempts.log');
      expect(logContent).not.toMatch(/private/i);
      expect(logContent).not.toMatch(/d=/i); // Private key component
    });
  });

  describe('Replay Logs', () => {
    test('should log replay attempts', () => {
      const sessionId = 'session-123';
      const seq = 1;
      const timestamp = Date.now();
      logReplayAttempt(sessionId, testUser1.id, seq, timestamp, 'Duplicate message ID');

      const logContent = readLogFile('replay_attempts.log');
      expect(logContent).toContain('REPLAY_ATTEMPT');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('Duplicate message ID');
    });

    test('should log replay detection', () => {
      const sessionId = 'session-456';
      const seq = 2;
      logReplayDetected(testUser2.id, sessionId, seq, 'Timestamp out of validity window');

      const logContent = readLogFile('replay_detected.log');
      expect(logContent).toContain('replay_detected');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('Timestamp out of validity window');
    });
  });

  describe('Invalid Signature Logs', () => {
    test('should log invalid signatures', () => {
      const sessionId = 'session-123';
      logInvalidSignature(sessionId, testUser1.id, 'KEP_INIT', 'Signature verification failed');

      const logContent = readLogFile('invalid_signature.log');
      expect(logContent).toContain('INVALID_SIGNATURE');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('Signature verification failed');
    });

    test('should log invalid KEP messages', () => {
      const sessionId = 'session-456';
      logInvalidKEPMessage(testUser2.id, sessionId, 'Missing signature field');

      const logContent = readLogFile('invalid_kep_message.log');
      expect(logContent).toContain('INVALID_KEP_MESSAGE');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('Missing signature field');
    });
  });

  describe('Failed Decryption Logs', () => {
    test('should log failed decryptions', () => {
      const sessionId = 'session-123';
      const seq = 5;
      logFailedDecryption(sessionId, testUser1.id, seq, 'Invalid auth tag');

      const logContent = readLogFile('failed_decryption.log');
      expect(logContent).toContain('DECRYPTION_FAILED');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('Invalid auth tag');
    });

    test('should NOT log plaintext in decryption logs', () => {
      logFailedDecryption('session-789', testUser2.id, 1, 'Decryption error');

      const logContent = readLogFile('failed_decryption.log');
      expect(logContent).not.toMatch(/plaintext/i);
      expect(logContent).not.toMatch(/message content/i);
    });
  });

  describe('Metadata Access Logs', () => {
    test('should log message metadata access', () => {
      const sessionId = 'session-123';
      logMessageMetadataAccess(testUser1.id, sessionId, 'store', { messageId: 'msg-1' });

      const logContent = readLogFile('message_metadata_access.log');
      expect(logContent).toContain('message_metadata_access');
      expect(logContent).toContain(testUser1.id);
      expect(logContent).toContain(sessionId);
    });

    test('should log metadata access with action type', () => {
      logMetadataAccess('session-456', testUser2.id, 'READ');

      const logContent = readLogFile('message_metadata_access.log');
      expect(logContent).toContain('METADATA_ACCESS');
      expect(logContent).toContain('READ');
    });
  });

  describe('Message Forwarding Logs', () => {
    test('should log message forwarding', () => {
      const sessionId = 'session-123';
      logMessageForwarding(testUser1.id, testUser2.id, sessionId, 'MSG');

      const logContent = readLogFile('msg_forwarding.log');
      expect(logContent).toContain('msg_forwarding');
      expect(logContent).toContain(testUser1.id);
      expect(logContent).toContain(testUser2.id);
      expect(logContent).toContain('MSG');
    });

    test('should log file chunk forwarding', () => {
      const sessionId = 'session-456';
      logFileChunkForwarding(testUser1.id, testUser2.id, sessionId, 3);

      const logContent = readLogFile('file_chunk_forwarding.log');
      expect(logContent).toContain('file_chunk_forwarding');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('3');
    });
  });

  describe('Plaintext Prevention in Logs', () => {
    test('should ensure NO plaintext in any logs', () => {
      // Generate various log entries
      logAuthenticationAttempt(testUser1.id, true, 'Login');
      logKeyExchangeAttempt('session-1', testUser1.id, testUser2.id, 'KEP_INIT', true);
      logReplayAttempt('session-2', testUser1.id, 1, Date.now(), 'Replay');
      logInvalidSignature('session-3', testUser1.id, 'KEP_INIT', 'Invalid');
      logFailedDecryption('session-4', testUser1.id, 1, 'Failed');
      logMessageMetadataAccess(testUser1.id, 'session-5', 'store', {});

      // Check all log files
      const logFiles = [
        'authentication_attempts.log',
        'key_exchange_attempts.log',
        'replay_attempts.log',
        'invalid_signature.log',
        'failed_decryption.log',
        'message_metadata_access.log'
      ];

      logFiles.forEach(filename => {
        const content = readLogFile(filename);
        // Should not contain plaintext indicators
        expect(content).not.toMatch(/plaintext/i);
        expect(content).not.toMatch(/message content/i);
        expect(content).not.toMatch(/decrypted/i);
      });
    });

    test('should ensure NO private keys in logs', () => {
      logKeyExchangeAttempt('session-1', testUser1.id, testUser2.id, 'KEP_INIT', true);
      logInvalidSignature('session-2', testUser1.id, 'KEP_INIT', 'Invalid signature');

      const keyExchangeLog = readLogFile('key_exchange_attempts.log');
      const signatureLog = readLogFile('invalid_signature.log');

      expect(keyExchangeLog).not.toMatch(/private.*key/i);
      expect(signatureLog).not.toMatch(/private.*key/i);
      expect(keyExchangeLog).not.toMatch(/d=/i); // Private key component
    });
  });
});

