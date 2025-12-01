/**
 * Message Envelope Structure
 * 
 * Defines the standard E2EE message envelope format for encrypted messages.
 * All messages are encrypted with AES-256-GCM and wrapped in this envelope.
 */

import { generateNonce, generateTimestamp } from './messages.js';
import { sequenceManager } from './messages.js';
import { arrayBufferToBase64, signData } from './signatures.js';

/**
 * Builds a text message envelope with optional identity signature for non-repudiation
 * @param {string} sessionId - Session identifier
 * @param {string} sender - Sender user ID
 * @param {string} receiver - Receiver user ID
 * @param {ArrayBuffer} ciphertext - Encrypted message content
 * @param {Uint8Array} iv - Initialization vector (96 bits)
 * @param {ArrayBuffer} authTag - Authentication tag
 * @param {CryptoKey} identityPrivateKey - Optional identity private key for signing
 * @returns {Promise<Object>} Message envelope with optional signature
 */
export async function buildTextMessageEnvelope(sessionId, sender, receiver, ciphertext, iv, authTag, identityPrivateKey = null) {
  const { timestamp, nonce } = generateTimestamp();
  const seq = sequenceManager.getNextSequence(sessionId);

  const envelope = {
    type: 'MSG',
    sessionId,
    sender,
    receiver,
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
    timestamp,
    seq,
    nonce: arrayBufferToBase64(nonce)
  };

  // Add identity signature for non-repudiation if identity key provided
  if (identityPrivateKey) {
    const signaturePayload = JSON.stringify({
      sessionId,
      sender,
      receiver,
      timestamp,
      seq,
      ciphertextHash: arrayBufferToBase64(ciphertext.slice(0, Math.min(32, ciphertext.byteLength))) // Hash of first 32 bytes
    });
    const encoder = new TextEncoder();
    const payloadBuffer = encoder.encode(signaturePayload);
    const signature = await signData(identityPrivateKey, payloadBuffer);
    envelope.identitySignature = arrayBufferToBase64(signature);
  }

  return envelope;
}

/**
 * Builds a file metadata envelope
 * @param {string} sessionId - Session identifier
 * @param {string} sender - Sender user ID
 * @param {string} receiver - Receiver user ID
 * @param {ArrayBuffer} ciphertext - Encrypted metadata
 * @param {Uint8Array} iv - Initialization vector
 * @param {ArrayBuffer} authTag - Authentication tag
 * @param {Object} meta - File metadata (filename, size, totalChunks, mimetype)
 * @returns {Object} File metadata envelope
 */
export function buildFileMetaEnvelope(sessionId, sender, receiver, ciphertext, iv, authTag, meta) {
  const { timestamp, nonce } = generateTimestamp();
  const seq = sequenceManager.getNextSequence(sessionId);

  return {
    type: 'FILE_META',
    sessionId,
    sender,
    receiver,
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
    timestamp,
    seq,
    nonce: arrayBufferToBase64(nonce),
    meta: {
      filename: meta.filename,
      size: meta.size,
      totalChunks: meta.totalChunks,
      mimetype: meta.mimetype
    }
  };
}

/**
 * Builds a file chunk envelope
 * @param {string} sessionId - Session identifier
 * @param {string} sender - Sender user ID
 * @param {string} receiver - Receiver user ID
 * @param {ArrayBuffer} ciphertext - Encrypted chunk data
 * @param {Uint8Array} iv - Initialization vector
 * @param {ArrayBuffer} authTag - Authentication tag
 * @param {Object} meta - Chunk metadata (chunkIndex, totalChunks)
 * @returns {Object} File chunk envelope
 */
export function buildFileChunkEnvelope(sessionId, sender, receiver, ciphertext, iv, authTag, meta) {
  const { timestamp, nonce } = generateTimestamp();
  const seq = sequenceManager.getNextSequence(sessionId);

  return {
    type: 'FILE_CHUNK',
    sessionId,
    sender,
    receiver,
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
    timestamp,
    seq,
    nonce: arrayBufferToBase64(nonce),
    meta: {
      chunkIndex: meta.chunkIndex,
      totalChunks: meta.totalChunks
    }
  };
}

/**
 * Validates envelope structure
 * @param {Object} envelope - Message envelope to validate
 * @returns {{valid: boolean, error?: string}}
 */
export function validateEnvelopeStructure(envelope) {
  // Check required fields
  const requiredFields = ['type', 'sessionId', 'sender', 'receiver', 'ciphertext', 'iv', 'authTag', 'timestamp', 'seq'];
  
  for (const field of requiredFields) {
    if (!(field in envelope)) {
      return { valid: false, error: `Missing required field: ${field}` };
    }
  }

  // Validate type
  if (!['MSG', 'FILE_META', 'FILE_CHUNK'].includes(envelope.type)) {
    return { valid: false, error: 'Invalid message type' };
  }

  // Validate timestamp (must be number)
  if (typeof envelope.timestamp !== 'number') {
    return { valid: false, error: 'Timestamp must be a number' };
  }

  // Validate sequence number (must be number)
  if (typeof envelope.seq !== 'number') {
    return { valid: false, error: 'Sequence number must be a number' };
  }

  // Validate base64 fields
  const base64Fields = ['ciphertext', 'iv', 'authTag', 'nonce'];
  for (const field of base64Fields) {
    if (envelope[field] && typeof envelope[field] !== 'string') {
      return { valid: false, error: `${field} must be a base64 string` };
    }
  }

  // Validate file metadata if present
  if (envelope.type === 'FILE_META' || envelope.type === 'FILE_CHUNK') {
    if (!envelope.meta) {
      return { valid: false, error: 'File message must include meta field' };
    }
  }

  if (envelope.type === 'FILE_META') {
    if (!envelope.meta.filename || !envelope.meta.size || !envelope.meta.totalChunks) {
      return { valid: false, error: 'FILE_META must include filename, size, and totalChunks' };
    }
  }

  if (envelope.type === 'FILE_CHUNK') {
    if (typeof envelope.meta.chunkIndex !== 'number' || typeof envelope.meta.totalChunks !== 'number') {
      return { valid: false, error: 'FILE_CHUNK must include chunkIndex and totalChunks' };
    }
  }

  return { valid: true };
}

