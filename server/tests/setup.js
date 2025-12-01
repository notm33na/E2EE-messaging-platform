/**
 * Test Setup and Utilities
 * Provides test database connection and helper functions
 */

import { setupTestDB, cleanTestDB, closeTestDB, getTestDBName } from './utils/createTestDB.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Re-export DB helpers from the isolated test DB utility so all suites
// use per-suite databases instead of a shared global connection.
export { setupTestDB, cleanTestDB, closeTestDB, getTestDBName };

/**
 * Clear test log files
 */
export function clearTestLogs() {
  const logsDir = path.join(__dirname, '../../logs');
  const logFiles = [
    'replay_attempts.log',
    'invalid_signature.log',
    'invalid_kep_message.log',
    'message_metadata_access.log',
    'msg_forwarding.log',
    'file_chunk_forwarding.log',
    'replay_detected.log',
    'key_exchange_attempts.log',
    'authentication_attempts.log',
    'failed_decryption.log'
  ];

  logFiles.forEach(file => {
    const logPath = path.join(logsDir, file);
    if (fs.existsSync(logPath)) {
      fs.writeFileSync(logPath, '', 'utf8');
    }
  });
}

/**
 * Read log file content
 */
export function readLogFile(filename) {
  const logsDir = path.join(__dirname, '../../logs');
  // Ensure logs directory exists
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }
  const logPath = path.join(logsDir, filename);
  if (fs.existsSync(logPath)) {
    return fs.readFileSync(logPath, 'utf8');
  }
  return '';
}

/**
 * Generate test JWK (public key)
 */
export function generateTestJWK() {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: 'testXValue123456789012345678901234567890123456789012345678901234',
    y: 'testYValue123456789012345678901234567890123456789012345678901234'
  };
}

/**
 * Generate test user data
 */
export function generateTestUser() {
  // Use Date.now() + Math.random() to ensure uniqueness even in parallel tests
  const uniqueId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  return {
    email: `test${uniqueId}@example.com`,
    password: 'TestPassword123!'
  };
}

/**
 * Sleep utility for async tests
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

