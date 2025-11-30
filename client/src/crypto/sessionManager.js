/**
 * Session Manager
 * 
 * Manages E2EE sessions including:
 * - Session creation and storage
 * - Key retrieval (send/recv keys)
 * - Sequence number management
 * - Session persistence in IndexedDB
 * - Replay detection and logging (Phase 7)
 * - Invalid signature detection and logging (Phase 7)
 */

/**
 * Logging hooks for attack detection (Phase 7)
 */
let onReplayDetectedCallback = null;
let onInvalidSignatureCallback = null;

/**
 * Sets callback for replay detection
 * @param {Function} callback - Callback function (sessionId, message)
 */
export function setReplayDetectionCallback(callback) {
  onReplayDetectedCallback = callback;
}

/**
 * Sets callback for invalid signature detection
 * @param {Function} callback - Callback function (sessionId, message)
 */
export function setInvalidSignatureCallback(callback) {
  onInvalidSignatureCallback = callback;
}

/**
 * Triggers replay detection callback
 * @param {string} sessionId - Session identifier
 * @param {Object} message - Message that triggered replay detection
 */
export function triggerReplayDetection(sessionId, message) {
  if (onReplayDetectedCallback) {
    onReplayDetectedCallback(sessionId, message);
  }
}

/**
 * Triggers invalid signature callback
 * @param {string} sessionId - Session identifier
 * @param {Object} message - Message with invalid signature
 */
export function triggerInvalidSignature(sessionId, message) {
  if (onInvalidSignatureCallback) {
    onInvalidSignatureCallback(sessionId, message);
  }
}

const DB_NAME = 'InfosecCryptoDB';
const DB_VERSION = 1;
const SESSIONS_STORE = 'sessions';

/**
 * Opens IndexedDB database
 * @returns {Promise<IDBDatabase>}
 */
async function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(SESSIONS_STORE)) {
        db.createObjectStore(SESSIONS_STORE, { keyPath: 'sessionId' });
      }
    };
  });
}

/**
 * Converts ArrayBuffer to base64 string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts base64 string to ArrayBuffer
 * @param {string} base64 - Base64 string
 * @returns {ArrayBuffer} ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Creates a new session
 * @param {string} sessionId - Unique session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @param {ArrayBuffer} rootKey - Root key
 * @param {ArrayBuffer} sendKey - Key for sending messages
 * @param {ArrayBuffer} recvKey - Key for receiving messages
 * @returns {Promise<void>}
 */
export async function createSession(sessionId, userId, peerId, rootKey, sendKey, recvKey) {
  try {
    const session = {
      sessionId,
      userId,
      peerId,
      rootKey: arrayBufferToBase64(rootKey),
      sendKey: arrayBufferToBase64(sendKey),
      recvKey: arrayBufferToBase64(recvKey),
      lastSeq: 0,
      lastTimestamp: Date.now(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const db = await openDB();
    const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
    const store = transaction.objectStore(SESSIONS_STORE);

    await new Promise((resolve, reject) => {
      const request = store.put(session);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });

    console.log(`✓ Session created: ${sessionId}`);
  } catch (error) {
    throw new Error(`Failed to create session: ${error.message}`);
  }
}

/**
 * Loads session from storage
 * @param {string} sessionId - Session identifier
 * @returns {Promise<Object|null>} Session object or null
 */
export async function loadSession(sessionId) {
  try {
    const db = await openDB();
    const transaction = db.transaction([SESSIONS_STORE], 'readonly');
    const store = transaction.objectStore(SESSIONS_STORE);

    const session = await new Promise((resolve, reject) => {
      const request = store.get(sessionId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    if (!session) {
      return null;
    }

    // Convert base64 keys back to ArrayBuffer
    return {
      ...session,
      rootKey: base64ToArrayBuffer(session.rootKey),
      sendKey: base64ToArrayBuffer(session.sendKey),
      recvKey: base64ToArrayBuffer(session.recvKey)
    };
  } catch (error) {
    throw new Error(`Failed to load session: ${error.message}`);
  }
}

/**
 * Updates session sequence number
 * @param {string} sessionId - Session identifier
 * @param {number} seq - New sequence number
 * @returns {Promise<void>}
 */
export async function updateSessionSeq(sessionId, seq) {
  try {
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    session.lastSeq = seq;
    session.lastTimestamp = Date.now();
    session.updatedAt = new Date().toISOString();

    // Convert keys back to base64 for storage
    const sessionToStore = {
      ...session,
      rootKey: arrayBufferToBase64(session.rootKey),
      sendKey: arrayBufferToBase64(session.sendKey),
      recvKey: arrayBufferToBase64(session.recvKey)
    };

    const db = await openDB();
    const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
    const store = transaction.objectStore(SESSIONS_STORE);

    await new Promise((resolve, reject) => {
      const request = store.put(sessionToStore);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    throw new Error(`Failed to update session sequence: ${error.message}`);
  }
}

/**
 * Gets send key for session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<ArrayBuffer>} Send key
 */
export async function getSendKey(sessionId) {
  try {
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }
    return session.sendKey;
  } catch (error) {
    throw new Error(`Failed to get send key: ${error.message}`);
  }
}

/**
 * Gets receive key for session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<ArrayBuffer>} Receive key
 */
export async function getRecvKey(sessionId) {
  try {
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }
    return session.recvKey;
  } catch (error) {
    throw new Error(`Failed to get recv key: ${error.message}`);
  }
}

/**
 * Gets root key for session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<ArrayBuffer>} Root key
 */
export async function getRootKey(sessionId) {
  try {
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }
    return session.rootKey;
  } catch (error) {
    throw new Error(`Failed to get root key: ${error.message}`);
  }
}

/**
 * Stores session (updates existing or creates new)
 * @param {Object} session - Session object
 * @returns {Promise<void>}
 */
export async function storeSession(session) {
  try {
    // Convert ArrayBuffer keys to base64 for storage
    const sessionToStore = {
      ...session,
      rootKey: arrayBufferToBase64(session.rootKey),
      sendKey: arrayBufferToBase64(session.sendKey),
      recvKey: arrayBufferToBase64(session.recvKey),
      updatedAt: new Date().toISOString()
    };

    const db = await openDB();
    const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
    const store = transaction.objectStore(SESSIONS_STORE);

    await new Promise((resolve, reject) => {
      const request = store.put(sessionToStore);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    throw new Error(`Failed to store session: ${error.message}`);
  }
}

/**
 * Deletes session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<void>}
 */
export async function deleteSession(sessionId) {
  try {
    const db = await openDB();
    const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
    const store = transaction.objectStore(SESSIONS_STORE);

    await new Promise((resolve, reject) => {
      const request = store.delete(sessionId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });

    console.log(`✓ Session deleted: ${sessionId}`);
  } catch (error) {
    throw new Error(`Failed to delete session: ${error.message}`);
  }
}

/**
 * Gets all sessions for a user
 * @param {string} userId - User ID
 * @returns {Promise<Array>} Array of sessions
 */
export async function getUserSessions(userId) {
  try {
    const db = await openDB();
    const transaction = db.transaction([SESSIONS_STORE], 'readonly');
    const store = transaction.objectStore(SESSIONS_STORE);

    const sessions = await new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    // Filter by userId and convert keys
    return sessions
      .filter(s => s.userId === userId || s.peerId === userId)
      .map(s => ({
        ...s,
        rootKey: base64ToArrayBuffer(s.rootKey),
        sendKey: base64ToArrayBuffer(s.sendKey),
        recvKey: base64ToArrayBuffer(s.recvKey)
      }));
  } catch (error) {
    throw new Error(`Failed to get user sessions: ${error.message}`);
  }
}

/**
 * Rotates ephemeral keys for forward secrecy (Phase 6)
 * 
 * Generates new ephemeral key pair, derives new session keys,
 * and updates the session. Old ephemeral keys are discarded.
 * 
 * FORWARD SECRECY: Old session keys cannot decrypt new messages
 * after rotation, even if old ephemeral keys are compromised.
 * 
 * @param {string} sessionId - Session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @param {CryptoKey} newEphPublicKey - New ephemeral public key from peer
 * @param {CryptoKey} newEphPrivateKey - Our new ephemeral private key
 * @returns {Promise<{rootKey: ArrayBuffer, sendKey: ArrayBuffer, recvKey: ArrayBuffer}>} New session keys
 */
export async function rotateEphemeralKeys(sessionId, userId, peerId, newEphPublicKey, newEphPrivateKey) {
  try {
    // Import ECDH functions
    const ecdhModule = await import('./ecdh.js');
    const { computeSharedSecret, deriveSessionKeys } = ecdhModule;
    
    // Compute new shared secret from new ephemeral keys
    const newSharedSecret = await computeSharedSecret(newEphPrivateKey, newEphPublicKey);
    
    // Derive new session keys using same HKDF procedure
    const newKeys = await deriveSessionKeys(newSharedSecret, sessionId, userId, peerId);
    
    // Update session with new keys
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }
    
    // Update session with new keys
    session.rootKey = newKeys.rootKey;
    session.sendKey = newKeys.sendKey;
    session.recvKey = newKeys.recvKey;
    session.updatedAt = new Date().toISOString();
    session.keyRotationCount = (session.keyRotationCount || 0) + 1;
    session.lastKeyRotation = new Date().toISOString();
    
    // Store updated session
    await storeSession(session);
    
    console.log(`✓ Keys rotated for session: ${sessionId} (rotation #${session.keyRotationCount})`);
    
    return newKeys;
  } catch (error) {
    throw new Error(`Failed to rotate keys: ${error.message}`);
  }
}

/**
 * Rotates keys for a session (legacy function name, calls rotateEphemeralKeys)
 * @param {string} sessionId - Session identifier
 * @returns {Promise<void>}
 */
export async function rotateKeys(sessionId) {
  // This is a placeholder - actual rotation requires new ephemeral keys
  // Use rotateEphemeralKeys() with new key pair instead
  console.warn('rotateKeys() is deprecated. Use rotateEphemeralKeys() with new ephemeral keys.');
  throw new Error('Use rotateEphemeralKeys() with new ephemeral key pair');
}

