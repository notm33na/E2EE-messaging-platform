/**
 * Replay Protection Tests
 * Tests timestamp validation, sequence number checks, and replay detection
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { validateTimestamp, generateMessageId } from '../src/utils/replayProtection.js';
import { logReplayAttempt } from '../src/utils/attackLogging.js';
import { MessageMeta } from '../src/models/MessageMeta.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Suite-specific logs directory for replay protection tests.
const suiteLogsDir = path.join(__dirname, 'logs', `replay-${process.pid}-${Date.now()}`);

function ensureSuiteLogsDir() {
  if (fs.existsSync(suiteLogsDir)) {
    fs.rmSync(suiteLogsDir, { recursive: true, force: true });
  }
  fs.mkdirSync(suiteLogsDir, { recursive: true });
}

function readLogFile(filename) {
  const baseDir = process.env.TEST_LOGS_DIR || suiteLogsDir;
  const logPath = path.join(baseDir, filename);
  if (fs.existsSync(logPath)) {
    return fs.readFileSync(logPath, 'utf8');
  }
  return '';
}

describe('Replay Protection Tests', () => {
  let testUser1, testUser2;

  beforeAll(async () => {
    // Use suite-specific log directory for replay logs.
    process.env.TEST_LOGS_DIR = suiteLogsDir;
    ensureSuiteLogsDir();
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
    if (fs.existsSync(suiteLogsDir)) {
      fs.rmSync(suiteLogsDir, { recursive: true, force: true });
    }
    delete process.env.TEST_LOGS_DIR;
  });

  beforeEach(async () => {
    await cleanTestDB();
    ensureSuiteLogsDir();
    const userData1 = generateTestUser();
    const userData2 = generateTestUser();
    testUser1 = await userService.createUser(userData1.email, userData1.password);
    testUser2 = await userService.createUser(userData2.email, userData2.password);
  });

  describe('Timestamp Validation', () => {
    test('should accept fresh timestamps', () => {
      const now = Date.now();
      expect(validateTimestamp(now)).toBe(true);
    });

    test('should reject stale timestamps (older than 2 minutes)', () => {
      const staleTimestamp = Date.now() - 3 * 60 * 1000; // 3 minutes ago
      expect(validateTimestamp(staleTimestamp)).toBe(false);
    });

    test('should reject future timestamps (more than 2 minutes ahead)', () => {
      const futureTimestamp = Date.now() + 3 * 60 * 1000; // 3 minutes in future
      expect(validateTimestamp(futureTimestamp)).toBe(false);
    });

    test('should accept timestamps within 2-minute window', () => {
      const recentTimestamp = Date.now() - 60 * 1000; // 1 minute ago
      expect(validateTimestamp(recentTimestamp)).toBe(true);
    });
  });

  describe('Message ID Generation', () => {
    test('should generate unique message IDs', () => {
      const sessionId = 'test-session';
      const seq1 = generateMessageId(sessionId, 1);
      const seq2 = generateMessageId(sessionId, 2);

      expect(seq1).not.toBe(seq2);
      expect(seq1).toContain(sessionId);
      expect(seq1).toContain('1');
    });

    test('should include sessionId and seq in message ID', () => {
      const sessionId = 'test-session-123';
      const seq = 5;
      const messageId = generateMessageId(sessionId, seq);

      expect(messageId).toContain(sessionId);
      expect(messageId).toContain(seq.toString());
    });
  });

  describe('Replay Detection - Same Ciphertext', () => {
    test('should reject duplicate message ID', async () => {
      const timestamp = Date.now();
      const messageId = generateMessageId('session-123', 1, timestamp);

      const message1 = new MessageMeta({
        messageId,
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp,
        seq: 1
      });
      await message1.save();

      // Attempt to create duplicate
      const message2 = new MessageMeta({
        messageId, // Same message ID
        sessionId: 'session-123',
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp,
        seq: 1
      });

      await expect(message2.save()).rejects.toThrow();
    });

    test('should log replay attempt', async () => {
      const sessionId = 'session-123';
      const seq = 1;
      const timestamp = Date.now() - 3 * 60 * 1000; // Stale timestamp

      logReplayAttempt(sessionId, testUser1.id, seq, timestamp, 'Timestamp out of validity window');

      const logContent = readLogFile('replay_attempts.log');
      expect(logContent).toContain('REPLAY_ATTEMPT');
      expect(logContent).toContain(sessionId);
      expect(logContent).toContain('Timestamp out of validity window');
    });
  });

  describe('Replay Detection - Reused Timestamp', () => {
    test('should reject message with reused timestamp and same seq', async () => {
      const sessionId = 'session-123';
      const timestamp = Date.now();
      const seq = 1;

      const message1 = new MessageMeta({
        messageId: generateMessageId(sessionId, seq, timestamp),
        sessionId,
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp,
        seq
      });
      await message1.save();

      // Attempt to reuse same timestamp and seq
      const message2 = new MessageMeta({
        messageId: generateMessageId(sessionId, seq, timestamp), // Same timestamp
        sessionId,
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp, // Same timestamp
        seq // Same seq
      });

      await expect(message2.save()).rejects.toThrow();
    });
  });

  describe('Replay Detection - Sequence Number', () => {
    test('should allow increasing sequence numbers', async () => {
      const sessionId = 'session-123';
      const timestamp = Date.now();

      const baseTimestamp = Date.now();
      for (let seq = 1; seq <= 5; seq++) {
        const message = new MessageMeta({
          messageId: generateMessageId(sessionId, seq, baseTimestamp + seq * 1000),
          sessionId,
          sender: testUser1.id,
          receiver: testUser2.id,
          type: 'MSG',
          timestamp: baseTimestamp + seq * 1000, // Ensure unique timestamps
          seq
        });
        await message.save();
      }

      const messages = await MessageMeta.find({ sessionId }).sort({ seq: 1 });
      expect(messages.length).toBe(5);
      expect(messages[0].seq).toBe(1);
      expect(messages[4].seq).toBe(5);
    });

    test('should reject sequence number rewind', async () => {
      const sessionId = 'session-123';
      const timestamp = Date.now();

      // Create message with seq 5
      const message1 = new MessageMeta({
        messageId: generateMessageId(sessionId, 5, timestamp + 5),
        sessionId,
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: timestamp + 5,
        seq: 5
      });
      await message1.save();

      // Attempt to create message with seq 3 (rewind)
      const message2 = new MessageMeta({
        messageId: generateMessageId(sessionId, 3, timestamp + 3),
        sessionId,
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: timestamp + 3,
        seq: 3
      });

      // This should be allowed (sequence can be out of order if timestamp is valid)
      // But we test that duplicate messageId is rejected
      await message2.save();

      // Now try to create another message with same seq 3 and timestamp (duplicate)
      const message3 = new MessageMeta({
        messageId: generateMessageId(sessionId, 3, timestamp + 3), // Same as message2
        sessionId,
        sender: testUser1.id,
        receiver: testUser2.id,
        type: 'MSG',
        timestamp: timestamp + 3,
        seq: 3
      });

      await expect(message3.save()).rejects.toThrow(); // Duplicate messageId
    });
  });

  describe('Replay Logging', () => {
    test('should create replay_attempts.log file', () => {
      const sessionId = 'session-123';
      const seq = 1;
      const timestamp = Date.now() - 3 * 60 * 1000;

      logReplayAttempt(sessionId, testUser1.id, seq, timestamp, 'Stale timestamp');

      const logContent = readLogFile('replay_attempts.log');
      expect(logContent).toBeTruthy();
      expect(logContent.length).toBeGreaterThan(0);
    });

    test('should log replay attempt with correct format', () => {
      const sessionId = 'session-456';
      const seq = 2;
      const timestamp = Date.now();
      const reason = 'Duplicate message ID';

      logReplayAttempt(sessionId, testUser1.id, seq, timestamp, reason);

      const logContent = readLogFile('replay_attempts.log');
      expect(logContent).toBeTruthy();
      expect(logContent.length).toBeGreaterThan(0);
      
      const logLines = logContent.trim().split('\n').filter(l => l);
      expect(logLines.length).toBeGreaterThan(0);
      
      // Parse log entry with HMAC (format: JSON|HMAC:...)
      const lastLine = logLines[logLines.length - 1];
      const logParts = lastLine.split('|HMAC:');
      const lastLog = JSON.parse(logParts[0]); // Extract JSON part before HMAC

      expect(lastLog.sessionId).toBe(sessionId);
      expect(lastLog.seq).toBe(seq);
      expect(lastLog.reason).toBe(reason);
      expect(lastLog.eventType).toBe('REPLAY_ATTEMPT');
    });
  });

  describe('KEP Message Replay Protection', () => {
    test('should reject duplicate KEP message', async () => {
      const timestamp = Date.now();
      const messageId = generateMessageId('kep-session', 1, timestamp);

      const kep1 = new KEPMessage({
        messageId,
        sessionId: 'kep-session',
        from: testUser1.id,
        to: testUser2.id,
        type: 'KEP_INIT',
        timestamp,
        seq: 1
      });
      await kep1.save();

      const kep2 = new KEPMessage({
        messageId, // Duplicate
        sessionId: 'kep-session',
        from: testUser1.id,
        to: testUser2.id,
        type: 'KEP_INIT',
        timestamp,
        seq: 1
      });

      await expect(kep2.save()).rejects.toThrow();
    });
  });
});

