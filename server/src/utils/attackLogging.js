/**
 * Attack Detection Logging
 * 
 * Comprehensive logging for attack simulations and detection.
 * 
 * SECURITY CONSIDERATIONS:
 * - Logs never contain plaintext or private keys
 * - Only metadata and attack indicators are logged
 * - Logs are for audit and educational purposes
 * 
 * DATA PRIVACY CONSTRAINTS:
 * - User IDs logged for audit trail
 * - Session IDs logged
 * - Attack type and outcome logged
 * - No sensitive data
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { writeProtectedLog } from './logIntegrity.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Base logs directory getter.
// In tests, this is driven by TEST_LOGS_DIR to ensure suite-specific isolation.
function getBaseLogsDir() {
  const dir = process.env.TEST_LOGS_DIR || path.join(__dirname, '../../logs');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

/**
 * Logs an event to a file
 * @param {string} filename - Log filename
 * @param {Object} event - Event data
 */
function resolveLogPath(filename) {
  const prefix = process.env.LOG_PREFIX || '';
  const effectiveName = prefix ? `${prefix}_${filename}` : filename;
  const baseDir = getBaseLogsDir();
  return path.join(baseDir, effectiveName);
}

function writeLog(filename, event) {
  // Use protected logging with HMAC integrity
  writeProtectedLog(filename, event);
}

/**
 * Logs a replay attack attempt
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID
 * @param {number} seq - Sequence number
 * @param {number} timestamp - Message timestamp
 * @param {string} reason - Rejection reason
 */
export function logReplayAttempt(sessionId, userId, seq, timestamp, reason) {
  writeLog('replay_attempts.log', {
    eventType: 'REPLAY_ATTEMPT',
    sessionId,
    userId,
    seq,
    timestamp,
    reason,
    action: 'REJECTED'
  });
}

/**
 * Logs an invalid signature detection
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID
 * @param {string} messageType - Type of message (KEP_INIT, KEP_RESPONSE, KEY_UPDATE)
 * @param {string} reason - Failure reason
 */
export function logInvalidSignature(sessionId, userId, messageType, reason) {
  writeLog('invalid_signature.log', {
    eventType: 'INVALID_SIGNATURE',
    sessionId,
    userId,
    messageType,
    reason,
    action: 'REJECTED'
  });
}

/**
 * Logs a key exchange attempt
 * @param {string} sessionId - Session identifier
 * @param {string} fromUserId - Initiator user ID
 * @param {string} toUserId - Recipient user ID
 * @param {string} messageType - KEP_INIT or KEP_RESPONSE
 * @param {boolean} success - Whether exchange succeeded
 */
export function logKeyExchangeAttempt(sessionId, fromUserId, toUserId, messageType, success) {
  writeLog('key_exchange_attempts.log', {
    eventType: 'KEY_EXCHANGE',
    sessionId,
    fromUserId,
    toUserId,
    messageType,
    success,
    action: success ? 'ACCEPTED' : 'REJECTED'
  });
}

/**
 * Logs authentication attempt
 * @param {string} userId - User ID
 * @param {boolean} success - Whether authentication succeeded
 * @param {string} reason - Success/failure reason
 */
export function logAuthenticationAttempt(userId, success, reason) {
  writeLog('authentication_attempts.log', {
    eventType: 'AUTH_ATTEMPT',
    userId,
    success,
    reason,
    action: success ? 'ACCEPTED' : 'REJECTED'
  });
}

/**
 * Logs failed message decryption
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID
 * @param {number} seq - Sequence number
 * @param {string} reason - Failure reason
 */
export function logFailedDecryption(sessionId, userId, seq, reason) {
  writeLog('failed_decryption.log', {
    eventType: 'DECRYPTION_FAILED',
    sessionId,
    userId,
    seq,
    reason,
    action: 'REJECTED'
  });
}

/**
 * Logs an invalid KEP message (structure / signature issues)
 * This is used by MITM and logging tests to verify that
 * invalid KEP messages are persisted to a dedicated log.
 *
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID associated with the KEP message
 * @param {string} reason - Reason for rejection
 */
export function logInvalidKEPMessage(sessionId, userId, reason) {
  writeLog('invalid_kep_message.log', {
    eventType: 'INVALID_KEP_MESSAGE',
    // Lowercase type field so tests that search for "invalid_kep_message"
    // as a substring can still find this entry while keeping eventType
    // in a normalized, uppercase form.
    type: 'invalid_kep_message',
    sessionId,
    userId,
    reason,
    action: 'REJECTED'
  });
}

/**
 * Logs metadata access
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID accessing metadata
 * @param {string} action - Action type (READ, WRITE, DELETE)
 */
export function logMetadataAccess(sessionId, userId, action) {
  writeLog('message_metadata_access.log', {
    eventType: 'METADATA_ACCESS',
    sessionId,
    userId,
    action,
    timestamp: Date.now()
  });
}

/**
 * Generic event logger
 * @param {string} eventType - Event type
 * @param {string} sessionId - Session identifier (optional)
 * @param {string} userId - User ID (optional)
 * @param {string} description - Event description
 * @param {Object} metadata - Additional metadata
 */
export function logEvent(eventType, sessionId, userId, description, metadata = {}) {
  const logEntry = {
    eventType,
    sessionId: sessionId || null,
    userId: userId || null,
    description,
    ...metadata,
    timestamp: new Date().toISOString()
  };

  // Route to appropriate log file based on event type
  if (eventType.includes('REPLAY')) {
    writeLog('replay_attempts.log', logEntry);
  } else if (eventType.includes('SIGNATURE')) {
    writeLog('invalid_signature.log', logEntry);
  } else if (eventType.includes('KEY_EXCHANGE')) {
    writeLog('key_exchange_attempts.log', logEntry);
  } else if (eventType.includes('AUTH')) {
    writeLog('authentication_attempts.log', logEntry);
  } else if (eventType.includes('DECRYPTION')) {
    writeLog('failed_decryption.log', logEntry);
  } else if (eventType.includes('METADATA')) {
    writeLog('message_metadata_access.log', logEntry);
  } else {
    // Default to general log
    writeLog('general_events.log', logEntry);
  }
}

