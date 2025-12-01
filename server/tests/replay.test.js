/**
 * Replay Attack Protection Summary Tests
 * Covers timestamp window, message ID uniqueness, and logging integration.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { MessageMeta } from '../src/models/MessageMeta.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { validateTimestamp, generateMessageId, logReplayAttempt } from '../src/utils/replayProtection.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const suiteLogsDir = path.join(__dirname, 'logs', `replay-summary-${process.pid}-${Date.now()}`);

function ensureSuiteLogsDir() {
  if (fs.existsSync(suiteLogsDir)) {
    fs.rmSync(suiteLogsDir, { recursive: true, force: true });
  }
  fs.mkdirSync(suiteLogsDir, { recursive: true });
}

function readLogFile(filename) {
  const logPath = path.join(process.env.TEST_LOGS_DIR || suiteLogsDir, filename);
  if (fs.existsSync(logPath)) {
    return fs.readFileSync(logPath, 'utf8');
  }
  return '';
}

describe('Replay Attack Protection Summary Tests', () => {
  let sender;
  let receiver;

  beforeAll(async () => {
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
    sender = await userService.createUser(userData1.email, userData1.password);
    receiver = await userService.createUser(userData2.email, userData2.password);
  });

  test('timestamp window enforcement via validateTimestamp', () => {
    const now = Date.now();
    const okPast = now - 60 * 1000;
    const tooOld = now - 5 * 60 * 1000;
    const tooFuture = now + 5 * 60 * 1000;

    expect(validateTimestamp(now)).toBe(true);
    expect(validateTimestamp(okPast)).toBe(true);
    expect(validateTimestamp(tooOld)).toBe(false);
    expect(validateTimestamp(tooFuture)).toBe(false);
  });

  test('nonce/messageId uniqueness for MessageMeta', async () => {
    const sessionId = 'session-replay-1';
    const timestamp = Date.now();
    const seq = 1;
    const messageId = generateMessageId(sessionId, seq, timestamp);

    const msg1 = new MessageMeta({
      messageId,
      sessionId,
      sender: sender.id,
      receiver: receiver.id,
      type: 'MSG',
      timestamp,
      seq
    });
    await msg1.save();

    const msg2 = new MessageMeta({
      messageId,
      sessionId,
      sender: sender.id,
      receiver: receiver.id,
      type: 'MSG',
      timestamp,
      seq
    });

    await expect(msg2.save()).rejects.toThrow();
  });

  test('nonce/messageId uniqueness for KEPMessage', async () => {
    const sessionId = 'session-replay-kep';
    const timestamp = Date.now();
    const seq = 1;
    const messageId = generateMessageId(sessionId, seq, timestamp);

    const kep1 = new KEPMessage({
      messageId,
      sessionId,
      from: sender.id,
      to: receiver.id,
      type: 'KEP_INIT',
      timestamp,
      seq
    });
    await kep1.save();

    const kep2 = new KEPMessage({
      messageId,
      sessionId,
      from: sender.id,
      to: receiver.id,
      type: 'KEP_INIT',
      timestamp,
      seq
    });

    await expect(kep2.save()).rejects.toThrow();
  });

  test('logs replay attempts to replay_attempts.log', () => {
    const sessionId = 'session-log';
    const seq = 1;
    const timestamp = Date.now() - 5 * 60 * 1000;

    logReplayAttempt(sessionId, seq, timestamp, 'Timestamp out of validity window');

    const content = readLogFile('replay_attempts.log');
    expect(content).toContain('REPLAY_ATTEMPT');
    expect(content).toContain(sessionId);
  });
});


