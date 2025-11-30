/**
 * Key Rotation Protocol
 * 
 * Implements forward secrecy through periodic key rotation.
 * 
 * FORWARD SECRECY:
 * - Old session keys cannot decrypt new messages after rotation
 * - Ephemeral keys are discarded after use
 * - Each rotation uses fresh ephemeral key pairs
 * 
 * SECURITY CONSIDERATIONS:
 * - Key updates must be signed with identity keys
 * - Replay protection via timestamp and sequence numbers
 * - Both parties must acknowledge key rotation
 * - Old keys are securely discarded from memory
 * 
 * DATA PRIVACY CONSTRAINTS:
 * - Only public ephemeral keys are transmitted
 * - Private keys never leave client
 * - Session keys never transmitted
 */

import { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKeys, exportPublicKey } from './ecdh.js';
import { signData, verifySignature, arrayBufferToBase64, base64ToArrayBuffer } from './signatures.js';
import { loadPrivateKey } from './identityKeys.js';
import { rotateEphemeralKeys } from './sessionManager.js';
import { generateTimestamp } from './messages.js';

/**
 * Builds a KEY_UPDATE message for key rotation
 * @param {string} sessionId - Session identifier
 * @param {string} fromUserId - Sender user ID
 * @param {string} toUserId - Recipient user ID
 * @param {CryptoKey} newEphPublicKey - New ephemeral public key
 * @param {CryptoKey} identityPrivateKey - Identity private key for signing
 * @param {number} rotationSeq - Rotation sequence number
 * @returns {Promise<Object>} KEY_UPDATE message
 */
export async function buildKeyUpdate(sessionId, fromUserId, toUserId, newEphPublicKey, identityPrivateKey, rotationSeq) {
  try {
    // Export ephemeral public key
    const ephPubJWK = await exportPublicKey(newEphPublicKey);
    
    // Create payload to sign
    const payload = {
      sessionId,
      from: fromUserId,
      to: toUserId,
      ephPub: ephPubJWK,
      rotationSeq,
      timestamp: Date.now()
    };
    
    const payloadString = JSON.stringify(payload);
    const payloadBuffer = new TextEncoder().encode(payloadString);
    
    // Sign payload with identity key
    const signature = await signData(identityPrivateKey, payloadBuffer);
    
    // Generate timestamp and nonce
    const { timestamp, nonce } = generateTimestamp();
    
    return {
      type: 'KEY_UPDATE',
      sessionId,
      from: fromUserId,
      to: toUserId,
      ephPub: ephPubJWK,
      signature: arrayBufferToBase64(signature),
      rotationSeq,
      timestamp,
      nonce: arrayBufferToBase64(nonce)
    };
  } catch (error) {
    throw new Error(`Failed to build key update: ${error.message}`);
  }
}

/**
 * Validates and processes a KEY_UPDATE message
 * @param {Object} keyUpdateMessage - KEY_UPDATE message
 * @param {CryptoKey} senderIdentityPubKey - Sender's identity public key
 * @param {string} sessionId - Session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @param {CryptoKey} ourNewEphPrivateKey - Our new ephemeral private key
 * @returns {Promise<{rootKey: ArrayBuffer, sendKey: ArrayBuffer, recvKey: ArrayBuffer}>} New session keys
 */
export async function processKeyUpdate(keyUpdateMessage, senderIdentityPubKey, sessionId, userId, peerId, ourNewEphPrivateKey) {
  try {
    // Validate message structure
    if (keyUpdateMessage.type !== 'KEY_UPDATE') {
      throw new Error('Invalid message type');
    }
    
    if (keyUpdateMessage.sessionId !== sessionId) {
      throw new Error('Session ID mismatch');
    }
    
    // Verify timestamp freshness (±2 minutes)
    const now = Date.now();
    const messageTime = keyUpdateMessage.timestamp;
    if (Math.abs(now - messageTime) > 2 * 60 * 1000) {
      throw new Error('Key update message is stale');
    }
    
    // Reconstruct payload for signature verification
    const payload = {
      sessionId: keyUpdateMessage.sessionId,
      from: keyUpdateMessage.from,
      to: keyUpdateMessage.to,
      ephPub: keyUpdateMessage.ephPub,
      rotationSeq: keyUpdateMessage.rotationSeq,
      timestamp: keyUpdateMessage.timestamp
    };
    
    const payloadString = JSON.stringify(payload);
    const payloadBuffer = new TextEncoder().encode(payloadString);
    const signature = base64ToArrayBuffer(keyUpdateMessage.signature);
    
    // Verify signature
    const isValid = await verifySignature(senderIdentityPubKey, signature, payloadBuffer);
    if (!isValid) {
      throw new Error('Invalid signature on key update');
    }
    
    // Import peer's new ephemeral public key
    const ecdhModule = await import('./ecdh.js');
    const peerEphPublicKey = await ecdhModule.importPublicKey(keyUpdateMessage.ephPub);
    
    // Compute new shared secret
    const newSharedSecret = await computeSharedSecret(ourNewEphPrivateKey, peerEphPublicKey);
    
    // Derive new session keys
    const newKeys = await deriveSessionKeys(newSharedSecret, sessionId, userId, peerId);
    
    // Update session with new keys
    await rotateEphemeralKeys(sessionId, userId, peerId, peerEphPublicKey, ourNewEphPrivateKey);
    
    return newKeys;
  } catch (error) {
    throw new Error(`Failed to process key update: ${error.message}`);
  }
}

/**
 * Initiates key rotation for a session
 * @param {string} sessionId - Session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @param {string} password - User password for identity key access
 * @returns {Promise<Object>} Key update message to send
 */
export async function initiateKeyRotation(sessionId, userId, peerId, password) {
  try {
    // Load identity private key
    const identityPrivateKey = await loadPrivateKey(userId, password);
    
    // Generate new ephemeral key pair
    const { privateKey: newEphPrivateKey, publicKey: newEphPublicKey } = await generateEphemeralKeyPair();
    
    // Get current rotation count (or start at 1)
    const sessionManager = await import('./sessionManager.js');
    const session = await sessionManager.loadSession(sessionId);
    const rotationSeq = (session?.keyRotationCount || 0) + 1;
    
    // Build key update message
    const keyUpdate = await buildKeyUpdate(
      sessionId,
      userId,
      peerId,
      newEphPublicKey,
      identityPrivateKey,
      rotationSeq
    );
    
    // Note: newEphPrivateKey is kept in memory by caller
    // It will be used when peer responds with their ephemeral public key
    
    return {
      keyUpdateMessage: keyUpdate,
      newEphPrivateKey // Keep in memory for when peer responds
    };
  } catch (error) {
    throw new Error(`Failed to initiate key rotation: ${error.message}`);
  }
}

/**
 * Responds to a key update from peer
 * @param {Object} keyUpdateMessage - KEY_UPDATE message from peer
 * @param {CryptoKey} peerIdentityPubKey - Peer's identity public key
 * @param {string} sessionId - Session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @param {string} password - User password for identity key access
 * @returns {Promise<Object>} Response key update message
 */
export async function respondToKeyRotation(keyUpdateMessage, peerIdentityPubKey, sessionId, userId, peerId, password) {
  try {
    // Generate our new ephemeral key pair
    const { privateKey: ourNewEphPrivateKey, publicKey: ourNewEphPublicKey } = await generateEphemeralKeyPair();
    
    // Process peer's key update (this updates our session keys)
    await processKeyUpdate(
      keyUpdateMessage,
      peerIdentityPubKey,
      sessionId,
      userId,
      peerId,
      ourNewEphPrivateKey
    );
    
    // Load identity private key
    const identityPrivateKey = await loadPrivateKey(userId, password);
    
    // Get rotation sequence
    const sessionManager = await import('./sessionManager.js');
    const session = await sessionManager.loadSession(sessionId);
    const rotationSeq = session.keyRotationCount || 1;
    
    // Build response key update
    const responseKeyUpdate = await buildKeyUpdate(
      sessionId,
      userId,
      peerId,
      ourNewEphPublicKey,
      identityPrivateKey,
      rotationSeq
    );
    
    return {
      keyUpdateMessage: responseKeyUpdate,
      newEphPrivateKey: ourNewEphPrivateKey // Keep in memory
    };
  } catch (error) {
    throw new Error(`Failed to respond to key rotation: ${error.message}`);
  }
}

