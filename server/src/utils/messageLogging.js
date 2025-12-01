import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Base logs directory getter. Tests can override this with TEST_LOGS_DIR to get
// suite-specific log isolation.
function getLogsDir() {
  const dir =
    process.env.TEST_LOGS_DIR || path.join(__dirname, '../../logs');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function resolveLogPath(filename) {
  const prefix = process.env.LOG_PREFIX || '';
  const effectiveName = prefix ? `${prefix}_${filename}` : filename;
  const baseDir = getLogsDir();
  return path.join(baseDir, effectiveName);
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
  const logPath = resolveLogPath('message_metadata_access.log');

  // Ensure directory exists
  const baseDir = getLogsDir();
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  // Force sync to ensure write is committed (if file exists)
  try {
    if (fs.existsSync(logPath)) {
      const fd = fs.openSync(logPath, 'r+');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
    }
  } catch (err) {
    // Ignore sync errors, write should still be committed
  }
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
  const logPath = resolveLogPath('msg_forwarding.log');

  // Ensure directory exists
  const baseDir = getLogsDir();
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  // Force sync to ensure write is committed (if file exists)
  try {
    if (fs.existsSync(logPath)) {
      const fd = fs.openSync(logPath, 'r+');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
    }
  } catch (err) {
    // Ignore sync errors, write should still be committed
  }
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
  const logPath = resolveLogPath('file_chunk_forwarding.log');

  // Ensure directory exists
  const baseDir = getLogsDir();
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  // Force sync to ensure write is committed (if file exists)
  try {
    if (fs.existsSync(logPath)) {
      const fd = fs.openSync(logPath, 'r+');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
    }
  } catch (err) {
    // Ignore sync errors, write should still be committed
  }
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
  const logPath = resolveLogPath('replay_detected.log');

  // Ensure directory exists
  const baseDir = getLogsDir();
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  fs.appendFileSync(logPath, logLine, { flag: 'a' });
  // Force sync to ensure write is committed (if file exists)
  try {
    if (fs.existsSync(logPath)) {
      const fd = fs.openSync(logPath, 'r+');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
    }
  } catch (err) {
    // Ignore sync errors, write should still be committed
  }
  console.warn(`⚠️  Replay detected: ${reason}`, logEntry);
}

