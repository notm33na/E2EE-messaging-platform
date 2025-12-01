import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logReplayAttempt as coreLogReplayAttempt, logInvalidSignature as coreLogInvalidSignature, logInvalidKEPMessage as coreLogInvalidKEPMessage } from './attackLogging.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Keep a LOGS_DIR constant aligned with the shared test logs directory,
// even though primary logging is delegated to attackLogging utilities.
// Path resolution: src/utils -> ../ (src) -> ../ (server) -> logs
const LOGS_DIR =
  process.env.TEST_LOGS_DIR || path.join(__dirname, '../../logs');

if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}

/**
 * Logs replay attempt (legacy wrapper)
 *
 * NOTE: Core logging is delegated to attackLogging.logReplayAttempt
 * to ensure a single, consistent log format across the codebase.
 *
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @param {number} timestamp - Message timestamp
 * @param {string} reason - Reason for rejection
 */
export function logReplayAttempt(sessionId, seq, timestamp, reason) {
  // Delegate to core logger, which also records the userId/action.
  // We pass null for userId to preserve the original interface.
  coreLogReplayAttempt(sessionId, null, seq, timestamp, reason);
}

/**
 * Logs invalid signature (legacy wrapper)
 *
 * @param {string} userId - User ID
 * @param {string} sessionId - Session identifier
 * @param {string} reason - Reason for rejection
 */
export function logInvalidSignature(userId, sessionId, reason) {
  coreLogInvalidSignature(sessionId, userId, 'KEP', reason);
}

/**
 * Logs invalid KEP message (legacy wrapper)
 *
 * @param {string} userId - User ID
 * @param {string} sessionId - Session identifier
 * @param {string} reason - Reason for rejection
 */
export function logInvalidKEPMessage(userId, sessionId, reason) {
  coreLogInvalidKEPMessage(sessionId, userId, reason);
}

// Server clock sync tracking (for timestamp validation)
let serverClockOffset = 0; // Offset in milliseconds
const MAX_CLOCK_SKEW = 60000; // 1 minute maximum allowed clock skew

/**
 * Updates server clock offset (call periodically with NTP or trusted time source)
 * @param {number} offset - Clock offset in milliseconds
 */
export function updateClockOffset(offset) {
  serverClockOffset = offset;
}

/**
 * Validates timestamp freshness with improved clock skew detection
 * @param {number} messageTimestamp - Message timestamp
 * @param {number} maxAge - Maximum age in milliseconds (default: 2 minutes)
 * @returns {boolean} True if timestamp is valid
 */
export function validateTimestamp(messageTimestamp, maxAge = 120000) {
  const now = Date.now() + serverClockOffset; // Adjust for clock skew
  const age = now - messageTimestamp;
  
  // Stricter validation: reject if too far in future (more than maxAge + clock skew tolerance)
  if (age < -(maxAge + MAX_CLOCK_SKEW)) {
    return false; // Message from too far in future
  }
  
  // Reject if too far in future (beyond maxAge window)
  if (age < -maxAge) {
    return false; // Message from future beyond acceptable window
  }
  
  // Reject if too old
  if (age > maxAge) {
    return false;
  }
  
  return true;
}

/**
 * Generates unique message ID
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @param {number} timestamp - Message timestamp (optional, defaults to current time)
 * @returns {string} Message ID
 */
export function generateMessageId(sessionId, seq, timestamp = null) {
  const ts = timestamp || Date.now();
  return `${sessionId}:${seq}:${ts}`;
}

