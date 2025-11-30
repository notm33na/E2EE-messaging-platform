import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const LOGS_DIR = path.join(__dirname, '../../logs');

// Ensure logs directory exists
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}

/**
 * Logs replay attempt
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @param {number} timestamp - Message timestamp
 * @param {string} reason - Reason for rejection
 */
export function logReplayAttempt(sessionId, seq, timestamp, reason) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    sessionId,
    seq,
    messageTimestamp: timestamp,
    reason,
    type: 'replay_attempt'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'replay_attempts.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  console.warn(`⚠️  Replay attempt detected: ${reason}`, logEntry);
}

/**
 * Logs invalid signature
 * @param {string} userId - User ID
 * @param {string} sessionId - Session identifier
 * @param {string} reason - Reason for rejection
 */
export function logInvalidSignature(userId, sessionId, reason) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    userId,
    sessionId,
    reason,
    type: 'invalid_signature'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'invalid_signature.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  console.warn(`⚠️  Invalid signature detected: ${reason}`, logEntry);
}

/**
 * Logs invalid KEP message
 * @param {string} userId - User ID
 * @param {string} sessionId - Session identifier
 * @param {string} reason - Reason for rejection
 */
export function logInvalidKEPMessage(userId, sessionId, reason) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    userId,
    sessionId,
    reason,
    type: 'invalid_kep_message'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'invalid_kep_message.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  console.warn(`⚠️  Invalid KEP message: ${reason}`, logEntry);
}

/**
 * Validates timestamp freshness
 * @param {number} messageTimestamp - Message timestamp
 * @param {number} maxAge - Maximum age in milliseconds (default: 2 minutes)
 * @returns {boolean} True if timestamp is valid
 */
export function validateTimestamp(messageTimestamp, maxAge = 120000) {
  const now = Date.now();
  const age = now - messageTimestamp;
  return age <= maxAge && age >= -maxAge;
}

/**
 * Generates unique message ID
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @returns {string} Message ID
 */
export function generateMessageId(sessionId, seq) {
  return `${sessionId}:${seq}:${Date.now()}`;
}

