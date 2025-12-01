/**
 * MITM Simulation Tests
 * Wraps existing MITM defense logging and key validation behaviour.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { PublicKey } from '../src/models/PublicKey.js';
import { logInvalidSignature, logInvalidKEPMessage } from '../src/utils/attackLogging.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestJWK, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const suiteLogsDir = path.join(__dirname, 'logs', `mitm-sim-${process.pid}-${Date.now()}`);

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

describe('MITM Simulation Tests', () => {
  let userA;
  let userB;

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
    userA = await userService.createUser(userData1.email, userData1.password);
    userB = await userService.createUser(userData2.email, userData2.password);
  });

  test('rejects non-ECC or non-P-256 keys as potential MITM vectors', async () => {
    const invalidJWK = {
      kty: 'RSA',
      n: 'test',
      e: 'AQAB'
    };

    const publicKey = new PublicKey({
      userId: userA.id,
      publicIdentityKeyJWK: invalidJWK
    });

    const validationError = publicKey.validateSync();
    expect(validationError).toBeDefined();
  });

  test('logs invalid signatures as MITM indicators', () => {
    const sessionId = 'mitm-session-1';
    const reason = 'Signature verification failed';

    logInvalidSignature(sessionId, userA.id.toString(), 'KEP_INIT', reason);

    const content = readLogFile('invalid_signature.log');
    expect(content).toContain('INVALID_SIGNATURE');
    expect(content).toContain(sessionId);
    expect(content).toContain(reason);
  });

  test('logs invalid KEP messages for MITM simulations', () => {
    const sessionId = 'mitm-session-2';
    const reason = 'Missing signature field';

    logInvalidKEPMessage(sessionId, userB.id.toString(), reason);

    const content = readLogFile('invalid_kep_message.log');
    expect(content).toContain('invalid_kep_message');
    expect(content).toContain(sessionId);
    expect(content).toContain(reason);
  });
});


