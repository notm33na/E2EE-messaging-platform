/**
 * Message Flow
 * 
 * Handles sending and receiving encrypted messages using session keys
 * from Phase 3. Includes replay protection and integrity checking.
 */

import { getSendKey, getRecvKey, updateSessionSeq, loadSession, triggerReplayDetection, triggerInvalidSignature } from './sessionManager.js';
import { encryptAESGCM, decryptAESGCM, decryptAESGCMToString } from './aesGcm.js';
import { buildTextMessageEnvelope } from './messageEnvelope.js';
import { validateEnvelopeStructure } from './messageEnvelope.js';
import { base64ToArrayBuffer } from './signatures.js';
import { sequenceManager, generateTimestamp } from './messages.js';
import { clearPlaintextAfterEncryption, clearPlaintextAfterDecryption } from '../utils/memorySecurity.js';

/**
 * Validates timestamp freshness
 * @param {number} messageTimestamp - Message timestamp
 * @param {number} maxAge - Maximum age in milliseconds (default: 2 minutes)
 * @returns {boolean} True if timestamp is valid
 */
function validateTimestamp(messageTimestamp, maxAge = 120000) {
  const now = Date.now();
  const age = now - messageTimestamp;
  return age <= maxAge && age >= -maxAge;
}

/**
 * Sends an encrypted text message
 * @param {string} sessionId - Session identifier
 * @param {string} plaintext - Message text to encrypt and send
 * @param {Function} socketEmit - Socket.IO emit function
 * @returns {Promise<Object>} Sent envelope
 */
export async function sendEncryptedMessage(sessionId, plaintext, socketEmit, userId = null) {
  try {
    // 1. Load session (with userId for encrypted key access)
    const session = await loadSession(sessionId, userId);
    
    if (!session) {
      throw new Error('Session not found');
    }
    
    // Use userId from session if not provided
    if (!userId) {
      userId = session.userId;
    }
    
    // 2. Get send key
    const sendKey = await getSendKey(sessionId, userId);

    // 3. Encrypt plaintext with sendKey
    const { ciphertext, iv, authTag } = await encryptAESGCM(sendKey, plaintext);

    // 3.5. Clear plaintext from memory after encryption
    if (plaintext instanceof ArrayBuffer) {
      clearPlaintextAfterEncryption(plaintext);
    } else if (typeof plaintext === 'string') {
      // String is immutable, but we can clear any buffer representation
      clearPlaintextAfterEncryption(plaintext);
    }

    // 4. Build envelope
    const envelope = buildTextMessageEnvelope(
      sessionId,
      session.userId,
      session.peerId,
      ciphertext,
      iv,
      authTag
    );

    // 5. Send via WebSocket
    socketEmit('msg:send', envelope);

    console.log(`✓ Encrypted message sent (seq: ${envelope.seq})`);

    return envelope;
  } catch (error) {
    throw new Error(`Failed to send encrypted message: ${error.message}`);
  }
}

/**
 * Handles incoming encrypted message
 * @param {Object} envelope - Message envelope
 * @param {string} userId - User ID (for encrypted key access)
 * @returns {Promise<{valid: boolean, plaintext?: string, error?: string}>}
 */
export async function handleIncomingMessage(envelope, userId = null) {
  try {
    // 1. Validate envelope structure
    const structureCheck = validateEnvelopeStructure(envelope);
    if (!structureCheck.valid) {
      console.error('Invalid envelope structure:', structureCheck.error);
      return { valid: false, error: structureCheck.error };
    }

    // 2. Validate timestamp freshness
    const maxAge = 120000; // 2 minutes
    if (!validateTimestamp(envelope.timestamp, maxAge)) {
      const error = 'Timestamp out of validity window';
      console.warn(`⚠️  Replay attempt: ${error}`);
      logReplayAttempt(envelope.sessionId, envelope.seq, envelope.timestamp, error);
      triggerReplayDetection(envelope.sessionId, { ...envelope, reason: error });
      return { valid: false, error };
    }

    // 3. Validate sequence number (strictly increasing)
    const isValidSeq = sequenceManager.validateSequence(envelope.sessionId, envelope.seq);
    if (!isValidSeq) {
      const error = 'Sequence number must be strictly increasing';
      console.warn(`⚠️  Replay attempt: ${error}`);
      logReplayAttempt(envelope.sessionId, envelope.seq, envelope.timestamp, error);
      triggerReplayDetection(envelope.sessionId, { ...envelope, reason: error });
      return { valid: false, error };
    }

    // 4. Load session and receive key (with userId for encrypted key access)
    const session = await loadSession(envelope.sessionId, userId);
    if (!session) {
      return { valid: false, error: 'Session not found' };
    }

    // Use userId from session if not provided
    if (!userId) {
      userId = session.userId;
    }

    const recvKey = await getRecvKey(envelope.sessionId, userId);

    // 5. Convert base64 fields to ArrayBuffer
    const ciphertext = base64ToArrayBuffer(envelope.ciphertext);
    const iv = base64ToArrayBuffer(envelope.iv);
    const authTag = base64ToArrayBuffer(envelope.authTag);

    // 6. Decrypt using recvKey
    let plaintext;
    try {
      if (envelope.type === 'MSG') {
        plaintext = await decryptAESGCMToString(recvKey, iv, ciphertext, authTag);
      } else {
        // For file chunks, return ArrayBuffer
        plaintext = await decryptAESGCM(recvKey, iv, ciphertext, authTag);
      }

      // 7. Update session sequence (with userId for encrypted storage)
      await updateSessionSeq(envelope.sessionId, envelope.seq, userId);

      console.log(`✓ Message decrypted successfully (seq: ${envelope.seq})`);

      // Note: Plaintext is returned to caller - they should clear it after use
      // Memory clearing is best-effort in JavaScript (strings are immutable)
      // For ArrayBuffer plaintext, we clear it after a short delay
      if (plaintext instanceof ArrayBuffer) {
        // Schedule memory clearing after a short delay
        setTimeout(() => {
          clearPlaintextAfterDecryption(plaintext);
        }, 100);
      }
      
      return {
        valid: true,
        plaintext,
        envelope
      };
    } catch (error) {
    console.error('Failed to handle incoming message:', error);
    logInvalidEnvelope(envelope.sessionId, envelope.seq, error.message);
    
    // Trigger invalid signature detection if decryption fails (could be tampered)
    if (error.message.includes('decrypt') || error.message.includes('auth tag')) {
      triggerInvalidSignature(envelope.sessionId, { ...envelope, reason: error.message });
    }
    
    return { valid: false, error: error.message };
  }
}

/**
 * Logs replay attempt (client-side)
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @param {number} timestamp - Message timestamp
 * @param {string} reason - Reason for rejection
 */
function logReplayAttempt(sessionId, seq, timestamp, reason) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    sessionId,
    seq,
    messageTimestamp: timestamp,
    reason,
    type: 'replay_attempt',
    source: 'client'
  };
  console.warn('Replay attempt detected:', logEntry);
  // In production, could send to server for centralized logging
}

/**
 * Logs invalid envelope (client-side)
 * @param {string} sessionId - Session identifier
 * @param {number} seq - Sequence number
 * @param {string} reason - Reason for rejection
 */
function logInvalidEnvelope(sessionId, seq, reason) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    sessionId,
    seq,
    reason,
    type: 'invalid_envelope',
    source: 'client'
  };
  console.error('Invalid envelope:', logEntry);
}

