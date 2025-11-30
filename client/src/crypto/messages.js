/**
 * Key Exchange Protocol (KEP) Message Handling
 * 
 * Builds and validates KEP messages for the authenticated
 * ECDH key exchange protocol.
 * 
 * Message Types:
 * - KEP_INIT: Initial key exchange message from initiator
 * - KEP_RESPONSE: Response message from responder
 */

import { exportPublicKey } from './ecdh.js';
import { signEphemeralKey, arrayBufferToBase64, base64ToArrayBuffer } from './signatures.js';

/**
 * Generates a nonce (number used once)
 * @param {number} length - Length in bytes (default: 16)
 * @returns {Uint8Array} Nonce
 */
export function generateNonce(length = 16) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generates timestamp with nonce for replay protection
 * @returns {Object} {timestamp: number, nonce: Uint8Array}
 */
export function generateTimestamp() {
  return {
    timestamp: Date.now(),
    nonce: generateNonce()
  };
}

/**
 * Sequence number manager per session
 */
class SequenceManager {
  constructor() {
    this.sequences = new Map(); // sessionId -> lastSeq
  }

  /**
   * Gets next sequence number for session
   * @param {string} sessionId - Session identifier
   * @returns {number} Next sequence number
   */
  getNextSequence(sessionId) {
    const current = this.sequences.get(sessionId) || 0;
    const next = current + 1;
    this.sequences.set(sessionId, next);
    return next;
  }

  /**
   * Validates sequence number (must be strictly increasing)
   * @param {string} sessionId - Session identifier
   * @param {number} seq - Sequence number to validate
   * @returns {boolean} True if valid
   */
  validateSequence(sessionId, seq) {
    const lastSeq = this.sequences.get(sessionId) || 0;
    if (seq <= lastSeq) {
      return false; // Sequence must be strictly increasing
    }
    this.sequences.set(sessionId, seq);
    return true;
  }

  /**
   * Resets sequence for session
   * @param {string} sessionId - Session identifier
   */
  resetSequence(sessionId) {
    this.sequences.delete(sessionId);
  }
}

export const sequenceManager = new SequenceManager();

/**
 * Builds KEP_INIT message
 * @param {string} fromUserId - Initiator user ID
 * @param {string} toUserId - Recipient user ID
 * @param {CryptoKey} ephPublicKey - Ephemeral public key
 * @param {CryptoKey} identityPrivateKey - Identity private key for signing
 * @param {string} sessionId - Session identifier
 * @returns {Promise<Object>} KEP_INIT message object
 */
export async function buildKEPInit(fromUserId, toUserId, ephPublicKey, identityPrivateKey, sessionId) {
  try {
    // Export ephemeral public key to JWK
    const ephPubJWK = await exportPublicKey(ephPublicKey);

    // Sign ephemeral public key
    const signature = await signEphemeralKey(identityPrivateKey, ephPubJWK);

    // Generate timestamp and nonce
    const { timestamp, nonce } = generateTimestamp();

    // Get sequence number
    const seq = sequenceManager.getNextSequence(sessionId);

    return {
      type: 'KEP_INIT',
      from: fromUserId,
      to: toUserId,
      sessionId: sessionId,
      ephPub: ephPubJWK,
      signature: arrayBufferToBase64(signature),
      timestamp: timestamp,
      nonce: arrayBufferToBase64(nonce),
      seq: seq
    };
  } catch (error) {
    throw new Error(`Failed to build KEP_INIT message: ${error.message}`);
  }
}

/**
 * Validates KEP_INIT message
 * @param {Object} message - KEP_INIT message
 * @param {CryptoKey} identityPublicKey - Sender's identity public key
 * @param {number} maxAge - Maximum age in milliseconds (default: 2 minutes)
 * @returns {Promise<{valid: boolean, error?: string}>}
 */
export async function validateKEPInit(message, identityPublicKey, maxAge = 120000) {
  try {
    // Check message structure
    if (!message.type || message.type !== 'KEP_INIT') {
      return { valid: false, error: 'Invalid message type' };
    }

    if (!message.from || !message.to || !message.ephPub || !message.signature) {
      return { valid: false, error: 'Missing required fields' };
    }

    // Verify timestamp freshness
    const now = Date.now();
    const age = now - message.timestamp;
    if (age > maxAge || age < -maxAge) {
      return { valid: false, error: 'Timestamp out of validity window' };
    }

    // Verify signature
    const { verifyEphemeralKeySignature, base64ToArrayBuffer } = await import('./signatures.js');
    const signature = base64ToArrayBuffer(message.signature);
    const isValid = await verifyEphemeralKeySignature(identityPublicKey, signature, message.ephPub);

    if (!isValid) {
      return { valid: false, error: 'Invalid signature' };
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

/**
 * Builds KEP_RESPONSE message
 * @param {string} fromUserId - Responder user ID
 * @param {string} toUserId - Initiator user ID
 * @param {CryptoKey} ephPublicKey - Responder's ephemeral public key
 * @param {CryptoKey} identityPrivateKey - Identity private key for signing
 * @param {ArrayBuffer} rootKey - Derived root key for confirmation
 * @param {string} sessionId - Session identifier
 * @returns {Promise<Object>} KEP_RESPONSE message object
 */
export async function buildKEPResponse(fromUserId, toUserId, ephPublicKey, identityPrivateKey, rootKey, sessionId) {
  try {
    // Export ephemeral public key
    const ephPubJWK = await exportPublicKey(ephPublicKey);

    // Sign ephemeral public key
    const signature = await signEphemeralKey(identityPrivateKey, ephPubJWK);

    // Generate key confirmation HMAC
    const encoder = new TextEncoder();
    const confirmData = encoder.encode(`CONFIRM:${toUserId}`);
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      rootKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const keyConfirmation = await crypto.subtle.sign('HMAC', hmacKey, confirmData);

    // Generate timestamp
    const { timestamp, nonce } = generateTimestamp();

    // Get sequence number
    const seq = sequenceManager.getNextSequence(sessionId);

    return {
      type: 'KEP_RESPONSE',
      from: fromUserId,
      to: toUserId,
      sessionId: sessionId,
      ephPub: ephPubJWK,
      signature: arrayBufferToBase64(signature),
      keyConfirmation: arrayBufferToBase64(keyConfirmation),
      timestamp: timestamp,
      nonce: arrayBufferToBase64(nonce),
      seq: seq
    };
  } catch (error) {
    throw new Error(`Failed to build KEP_RESPONSE message: ${error.message}`);
  }
}

/**
 * Validates KEP_RESPONSE message
 * @param {Object} message - KEP_RESPONSE message
 * @param {CryptoKey} identityPublicKey - Responder's identity public key
 * @param {ArrayBuffer} rootKey - Our derived root key for confirmation check
 * @param {string} userId - Our user ID for confirmation
 * @param {number} maxAge - Maximum age in milliseconds (default: 2 minutes)
 * @returns {Promise<{valid: boolean, error?: string}>}
 */
export async function validateKEPResponse(message, identityPublicKey, rootKey, userId, maxAge = 120000) {
  try {
    // Check message structure
    if (!message.type || message.type !== 'KEP_RESPONSE') {
      return { valid: false, error: 'Invalid message type' };
    }

    if (!message.from || !message.ephPub || !message.signature || !message.keyConfirmation) {
      return { valid: false, error: 'Missing required fields' };
    }

    // Verify timestamp freshness
    const now = Date.now();
    const age = now - message.timestamp;
    if (age > maxAge || age < -maxAge) {
      return { valid: false, error: 'Timestamp out of validity window' };
    }

    // Verify signature
    const { verifyEphemeralKeySignature, base64ToArrayBuffer } = await import('./signatures.js');
    const signature = base64ToArrayBuffer(message.signature);
    const isValid = await verifyEphemeralKeySignature(identityPublicKey, signature, message.ephPub);

    if (!isValid) {
      return { valid: false, error: 'Invalid signature' };
    }

    // Verify key confirmation
    const encoder = new TextEncoder();
    const confirmData = encoder.encode(`CONFIRM:${userId}`);
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      rootKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const keyConfirmation = base64ToArrayBuffer(message.keyConfirmation);
    const confirmValid = await crypto.subtle.verify('HMAC', hmacKey, keyConfirmation, confirmData);

    if (!confirmValid) {
      return { valid: false, error: 'Key confirmation failed' };
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

