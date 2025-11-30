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
 * Logs message metadata access
 * @param {string} userId - User ID
 * @param {string} sessionId - Session identifier
 * @param {string} action - Action performed (store, fetch, etc.)
 * @param {Object} metadata - Additional metadata
 */
export function logMessageMetadataAccess(userId, sessionId, action, metadata = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    userId,
    sessionId,
    action,
    ...metadata,
    type: 'message_metadata_access'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'message_metadata_access.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
}

/**
 * Logs message forwarding
 * @param {string} senderId - Sender user ID
 * @param {string} receiverId - Receiver user ID
 * @param {string} sessionId - Session identifier
 * @param {string} messageType - Message type (MSG, FILE_META, FILE_CHUNK)
 */
export function logMessageForwarding(senderId, receiverId, sessionId, messageType) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    senderId,
    receiverId,
    sessionId,
    messageType,
    type: 'msg_forwarding'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'msg_forwarding.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
}

/**
 * Logs file chunk forwarding
 * @param {string} senderId - Sender user ID
 * @param {string} receiverId - Receiver user ID
 * @param {string} sessionId - Session identifier
 * @param {number} chunkIndex - Chunk index
 */
export function logFileChunkForwarding(senderId, receiverId, sessionId, chunkIndex) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    senderId,
    receiverId,
    sessionId,
    chunkIndex,
    type: 'file_chunk_forwarding'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'file_chunk_forwarding.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
}

/**
 * Logs replay detection
 * @param {string} userId - User ID
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @param {string} reason - Reason for rejection
 */
export function logReplayDetected(userId, sessionId, seq, reason) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    userId,
    sessionId,
    seq,
    reason,
    type: 'replay_detected'
  };

  const logLine = JSON.stringify(logEntry) + '\n';
  const logPath = path.join(LOGS_DIR, 'replay_detected.log');

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  console.warn(`⚠️  Replay detected: ${reason}`, logEntry);
}

