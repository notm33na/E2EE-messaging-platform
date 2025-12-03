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
const DB_VERSION = 7; // Must match the highest version used by any module
const SESSIONS_STORE = 'sessions';
const SESSION_ENCRYPTION_STORE = 'sessionEncryptionKeys'; // Store encryption metadata

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
      const transaction = event.target.transaction;
      
      // Create stores if they don't exist (idempotent)
      if (!db.objectStoreNames.contains(SESSIONS_STORE)) {
        db.createObjectStore(SESSIONS_STORE, { keyPath: 'sessionId' });
      }
      if (!db.objectStoreNames.contains(SESSION_ENCRYPTION_STORE)) {
        db.createObjectStore(SESSION_ENCRYPTION_STORE, { keyPath: 'userId' });
      }
      
      // Ensure all other required stores exist
      if (!db.objectStoreNames.contains('identityKeys')) {
        db.createObjectStore('identityKeys', { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains('messages')) {
        const msgStore = db.createObjectStore('messages', { keyPath: 'id' });
        msgStore.createIndex('sessionId', 'sessionId', { unique: false });
        msgStore.createIndex('timestamp', 'timestamp', { unique: false });
        msgStore.createIndex('seq', 'seq', { unique: false });
      }
      if (!db.objectStoreNames.contains('messageQueue')) {
        const queueStore = db.createObjectStore('messageQueue', { keyPath: 'id', autoIncrement: true });
        queueStore.createIndex('sessionId', 'sessionId', { unique: false });
        queueStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
      if (!db.objectStoreNames.contains('clientLogs')) {
        const logStore = db.createObjectStore('clientLogs', { 
          keyPath: 'id', 
          autoIncrement: true 
        });
        logStore.createIndex('timestamp', 'timestamp', { unique: false });
        logStore.createIndex('userId', 'userId', { unique: false });
        logStore.createIndex('sessionId', 'sessionId', { unique: false });
        logStore.createIndex('event', 'event', { unique: false });
        logStore.createIndex('synced', 'synced', { unique: false });
      }
    };
  });
}

/**
 * In-memory cache for session encryption keys (derived from password)
 * Cleared on logout or timeout
 */
const sessionEncryptionKeyCache = new Map(); // userId -> { key: CryptoKey, expiresAt: number }

/**
 * Derives session encryption key from password
 * Uses same PBKDF2 parameters as identity key encryption for consistency.
 * Tests may lower the iteration count via CRYPTO_PBKDF2_ITERATIONS env var
 * for performance while keeping the production default strong.
 * @param {string} password - User password
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>}
 */
async function deriveSessionEncryptionKey(password, salt) {
  const iterations =
    (typeof process !== 'undefined' &&
      process.env &&
      parseInt(process.env.CRYPTO_PBKDF2_ITERATIONS || '', 10)) ||
    100000;
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Gets or derives session encryption key for user
 * Caches in memory for active sessions
 * @param {string} userId - User ID
 * @param {string} password - User password
 * @returns {Promise<CryptoKey>}
 */
async function getSessionEncryptionKey(userId, password) {
  // Check cache first
  const cached = sessionEncryptionKeyCache.get(userId);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.key;
  }

  // Load or generate salt
  const db = await openDB();
  let encryptionData;
  
  try {
    encryptionData = await new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_ENCRYPTION_STORE], 'readwrite');
      const store = transaction.objectStore(SESSION_ENCRYPTION_STORE);
      
      // Set up transaction handlers first to avoid race conditions
      let resolved = false;
      let requestResult = null;
      
      const completeHandler = () => {
        if (!resolved) {
          resolved = true;
          resolve(requestResult);
        }
      };
      const errorHandler = () => {
        if (!resolved) {
          resolved = true;
          reject(transaction.error || new Error('Transaction error'));
        }
      };
      
      transaction.oncomplete = completeHandler;
      transaction.onerror = errorHandler;
      
      const request = store.get(userId);
      request.onsuccess = () => {
        requestResult = request.result;
        // If transaction is already complete, resolve immediately
        if (transaction.readyState === 'done') {
          if (!resolved) {
            resolved = true;
            resolve(requestResult);
          }
        }
        // Otherwise, wait for transaction.oncomplete
      };
      request.onerror = () => {
        if (!resolved) {
          resolved = true;
          reject(request.error);
        }
      };
    });

    if (!encryptionData) {
      // Generate new salt and store
      const salt = crypto.getRandomValues(new Uint8Array(16));
      encryptionData = {
        userId: userId,
        salt: Array.from(salt),
        createdAt: new Date().toISOString()
      };
      
      await new Promise((resolve, reject) => {
        const transaction = db.transaction([SESSION_ENCRYPTION_STORE], 'readwrite');
        const store = transaction.objectStore(SESSION_ENCRYPTION_STORE);
        
        // Set up transaction handlers first to avoid race conditions
        let resolved = false;
        const completeHandler = () => {
          if (!resolved) {
            resolved = true;
            resolve();
          }
        };
        const errorHandler = () => {
          if (!resolved) {
            resolved = true;
            reject(transaction.error || new Error('Transaction error'));
          }
        };
        
        transaction.oncomplete = completeHandler;
        transaction.onerror = errorHandler;
        
        const request = store.put(encryptionData);
        request.onsuccess = () => {
          // If transaction is already complete, resolve immediately
          if (transaction.readyState === 'done') {
            if (!resolved) {
              resolved = true;
              resolve();
            }
          }
          // Otherwise, wait for transaction.oncomplete
        };
        request.onerror = () => {
          if (!resolved) {
            resolved = true;
            reject(request.error);
          }
        };
      });
    }
  } finally {
    // Explicitly close database connection (important for fake-indexeddb)
    // Add a small delay to ensure transaction cleanup completes
    // This helps fake-indexeddb properly clean up before the next operation
    await new Promise(resolve => setTimeout(resolve, 50));
    try {
      if (db && typeof db.close === 'function') {
        db.close();
      }
    } catch (error) {
      // Ignore errors when closing - database might already be closed
    }
  }

  // Derive key
  const saltArray = new Uint8Array(encryptionData.salt);
  const key = await deriveSessionEncryptionKey(password, saltArray);

  // Cache for 1 hour
  sessionEncryptionKeyCache.set(userId, {
    key: key,
    expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
  });

  return key;
}

/**
 * Encrypts session keys for storage
 * @param {ArrayBuffer} keyData - Key data to encrypt (rootKey, sendKey, or recvKey)
 * @param {CryptoKey} encryptionKey - Encryption key
 * @returns {Promise<{encrypted: ArrayBuffer, iv: Uint8Array, authTag: ArrayBuffer}>}
 */
async function encryptSessionKey(keyData, encryptionKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits for GCM
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    encryptionKey,
    keyData
  );

  // Extract ciphertext and auth tag
  const tagLength = 16; // 128 bits = 16 bytes
  const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);
  const authTag = encrypted.slice(encrypted.byteLength - tagLength);

  return { encrypted: ciphertext, iv, authTag };
}

/**
 * Decrypts session keys from storage
 * @param {ArrayBuffer} encrypted - Encrypted key data
 * @param {Uint8Array} iv - Initialization vector
 * @param {ArrayBuffer} authTag - Authentication tag
 * @param {CryptoKey} encryptionKey - Decryption key
 * @returns {Promise<ArrayBuffer>}
 */
async function decryptSessionKey(encrypted, iv, authTag, encryptionKey) {
  // Combine ciphertext and auth tag
  const combined = new Uint8Array(encrypted.byteLength + authTag.byteLength);
  combined.set(new Uint8Array(encrypted), 0);
  combined.set(new Uint8Array(authTag), encrypted.byteLength);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    encryptionKey,
    combined
  );

  return decrypted;
}

/**
 * Clears session encryption key cache for user
 * @param {string} userId - User ID
 */
export function clearSessionEncryptionCache(userId) {
  sessionEncryptionKeyCache.delete(userId);
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
 * Creates a new session with encrypted key storage
 * @param {string} sessionId - Unique session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @param {ArrayBuffer} rootKey - Root key
 * @param {ArrayBuffer} sendKey - Key for sending messages
 * @param {ArrayBuffer} recvKey - Key for receiving messages
 * @param {string} password - User password for encryption (optional, uses cached key if available)
 * @returns {Promise<void>}
 */
export async function createSession(sessionId, userId, peerId, rootKey, sendKey, recvKey, password = null) {
  try {
    // Get encryption key (from cache or derive from password)
    let encryptionKey = null;
    if (password) {
      encryptionKey = await getSessionEncryptionKey(userId, password);
    } else {
      // Try to use cached key
      const cached = sessionEncryptionKeyCache.get(userId);
      if (cached && cached.expiresAt > Date.now()) {
        encryptionKey = cached.key;
      } else {
        throw new Error('Password required for session encryption or cached key expired');
      }
    }

    // Encrypt session keys
    const rootKeyEnc = await encryptSessionKey(rootKey, encryptionKey);
    const sendKeyEnc = await encryptSessionKey(sendKey, encryptionKey);
    const recvKeyEnc = await encryptSessionKey(recvKey, encryptionKey);

    const session = {
      sessionId,
      userId,
      peerId,
      rootKey: {
        encrypted: Array.from(new Uint8Array(rootKeyEnc.encrypted)),
        iv: Array.from(rootKeyEnc.iv),
        authTag: Array.from(new Uint8Array(rootKeyEnc.authTag))
      },
      sendKey: {
        encrypted: Array.from(new Uint8Array(sendKeyEnc.encrypted)),
        iv: Array.from(sendKeyEnc.iv),
        authTag: Array.from(new Uint8Array(sendKeyEnc.authTag))
      },
      recvKey: {
        encrypted: Array.from(new Uint8Array(recvKeyEnc.encrypted)),
        iv: Array.from(recvKeyEnc.iv),
        authTag: Array.from(new Uint8Array(recvKeyEnc.authTag))
      },
      encrypted: true, // Flag to indicate encrypted storage
      lastSeq: 0,
      lastTimestamp: Date.now(),
      // Track recently used nonce hashes (client-side replay protection).
      // Stored as an array of hex-encoded SHA-256(nonce) values.
      usedNonceHashes: [],
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

    console.log(`✓ Session created with encrypted keys: ${sessionId}`);
  } catch (error) {
    throw new Error(`Failed to create session: ${error.message}`);
  }
}

/**
 * Validates session access - ensures user has permission to access session
 * @param {Object} session - Session object
 * @param {string} requestingUserId - User ID requesting access
 * @returns {boolean} True if access is allowed
 */
export function validateSessionAccess(session, requestingUserId) {
  if (!session || !requestingUserId) {
    return false;
  }
  
  // User can only access sessions where they are the userId or peerId
  const sessionUserId = session.userId?.toString() || session.userId;
  const sessionPeerId = session.peerId?.toString() || session.peerId;
  const reqUserId = requestingUserId.toString() || requestingUserId;
  
  return sessionUserId === reqUserId || sessionPeerId === reqUserId;
}

/**
 * Loads session from storage and decrypts keys
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID (for encryption key lookup and access control)
 * @param {string} password - User password for decryption (optional, uses cached key if available)
 * @returns {Promise<Object|null>} Session object with decrypted keys or null
 */
export async function loadSession(sessionId, userId = null, password = null) {
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

    // Handle legacy unencrypted sessions (backward compatibility)
    if (!session.encrypted) {
      return {
        ...session,
        rootKey: base64ToArrayBuffer(session.rootKey),
        sendKey: base64ToArrayBuffer(session.sendKey),
        recvKey: base64ToArrayBuffer(session.recvKey)
      };
    }

    // Decrypt encrypted session keys
    if (!userId) {
      userId = session.userId;
    }

    // Get encryption key
    let encryptionKey = null;
    if (password) {
      encryptionKey = await getSessionEncryptionKey(userId, password);
    } else {
      const cached = sessionEncryptionKeyCache.get(userId);
      if (cached && cached.expiresAt > Date.now()) {
        encryptionKey = cached.key;
      } else {
        throw new Error('Password required for session decryption or cached key expired');
      }
    }

    // Validate session access before decrypting keys
    if (userId && !validateSessionAccess(session, userId)) {
      throw new Error('Access denied: User does not have permission to access this session');
    }

    // Decrypt keys
    const rootKeyBuf = new Uint8Array(session.rootKey.encrypted).buffer;
    const rootKeyIV = new Uint8Array(session.rootKey.iv);
    const rootKeyTag = new Uint8Array(session.rootKey.authTag).buffer;
    const rootKey = await decryptSessionKey(rootKeyBuf, rootKeyIV, rootKeyTag, encryptionKey);

    const sendKeyBuf = new Uint8Array(session.sendKey.encrypted).buffer;
    const sendKeyIV = new Uint8Array(session.sendKey.iv);
    const sendKeyTag = new Uint8Array(session.sendKey.authTag).buffer;
    const sendKey = await decryptSessionKey(sendKeyBuf, sendKeyIV, sendKeyTag, encryptionKey);

    const recvKeyBuf = new Uint8Array(session.recvKey.encrypted).buffer;
    const recvKeyIV = new Uint8Array(session.recvKey.iv);
    const recvKeyTag = new Uint8Array(session.recvKey.authTag).buffer;
    const recvKey = await decryptSessionKey(recvKeyBuf, recvKeyIV, recvKeyTag, encryptionKey);

    return {
      ...session,
      rootKey,
      sendKey,
      recvKey
    };
  } catch (error) {
    throw new Error(`Failed to load session: ${error.message}`);
  }
}

/**
 * Initializes session encryption key cache for user
 * Call this after login to cache the encryption key
 * @param {string} userId - User ID
 * @param {string} password - User password
 * @returns {Promise<void>}
 */
export async function initializeSessionEncryption(userId, password) {
  await getSessionEncryptionKey(userId, password);
}

/**
 * Updates session sequence number
 * @param {string} sessionId - Session identifier
 * @param {number} seq - New sequence number
 * @param {string} userId - User ID (for encryption key lookup)
 * @returns {Promise<void>}
 */
export async function updateSessionSeq(sessionId, seq, userId = null) {
  try {
    const session = await loadSession(sessionId, userId);
    if (!session) {
      throw new Error('Session not found');
    }

    session.lastSeq = seq;
    session.lastTimestamp = Date.now();
    session.updatedAt = new Date().toISOString();

    // Re-encrypt and store
    await storeSession(session, userId);
  } catch (error) {
    throw new Error(`Failed to update session sequence: ${error.message}`);
  }
}

/**
 * Gets send key for session
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID (for encryption key lookup)
 * @returns {Promise<ArrayBuffer>} Send key
 */
export async function getSendKey(sessionId, userId = null) {
  try {
    const session = await loadSession(sessionId, userId);
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
 * @param {string} userId - User ID (for encryption key lookup)
 * @returns {Promise<ArrayBuffer>} Receive key
 */
export async function getRecvKey(sessionId, userId = null) {
  try {
    const session = await loadSession(sessionId, userId);
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
 * @param {string} userId - User ID (for encryption key lookup)
 * @returns {Promise<ArrayBuffer>} Root key
 */
export async function getRootKey(sessionId, userId = null) {
  try {
    const session = await loadSession(sessionId, userId);
    if (!session) {
      throw new Error('Session not found');
    }
    return session.rootKey;
  } catch (error) {
    throw new Error(`Failed to get root key: ${error.message}`);
  }
}

/**
 * Stores session (updates existing or creates new) with encrypted keys
 * @param {Object} session - Session object with decrypted keys
 * @param {string} userId - User ID (for encryption key lookup)
 * @returns {Promise<void>}
 */
export async function storeSession(session, userId = null) {
  try {
    if (!userId) {
      userId = session.userId;
    }

    // Get encryption key from cache
    const cached = sessionEncryptionKeyCache.get(userId);
    if (!cached || cached.expiresAt <= Date.now()) {
      throw new Error('Session encryption key not available. Call initializeSessionEncryption() first.');
    }
    const encryptionKey = cached.key;

    // Encrypt keys
    const rootKeyEnc = await encryptSessionKey(session.rootKey, encryptionKey);
    const sendKeyEnc = await encryptSessionKey(session.sendKey, encryptionKey);
    const recvKeyEnc = await encryptSessionKey(session.recvKey, encryptionKey);

    const sessionToStore = {
      ...session,
      rootKey: {
        encrypted: Array.from(new Uint8Array(rootKeyEnc.encrypted)),
        iv: Array.from(rootKeyEnc.iv),
        authTag: Array.from(new Uint8Array(rootKeyEnc.authTag))
      },
      sendKey: {
        encrypted: Array.from(new Uint8Array(sendKeyEnc.encrypted)),
        iv: Array.from(sendKeyEnc.iv),
        authTag: Array.from(new Uint8Array(sendKeyEnc.authTag))
      },
      recvKey: {
        encrypted: Array.from(new Uint8Array(recvKeyEnc.encrypted)),
        iv: Array.from(recvKeyEnc.iv),
        authTag: Array.from(new Uint8Array(recvKeyEnc.authTag))
      },
      encrypted: true,
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
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(SESSIONS_STORE)) {
      console.warn('sessions store does not exist, returning empty array');
      return [];
    }
    
    const transaction = db.transaction([SESSIONS_STORE], 'readonly');
    const store = transaction.objectStore(SESSIONS_STORE);

    const sessions = await new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    // Filter by userId and decrypt keys
    const decryptedSessions = [];
    for (const s of sessions) {
      if (s.userId === userId || s.peerId === userId) {
        try {
          const decrypted = await loadSession(s.sessionId, userId);
          if (decrypted) {
            decryptedSessions.push(decrypted);
          }
        } catch (error) {
          console.warn(`Failed to decrypt session ${s.sessionId}:`, error);
          // Skip sessions that can't be decrypted
        }
      }
    }
    return decryptedSessions;
  } catch (error) {
    console.error('Failed to get user sessions:', error);
    // Return empty array instead of throwing to prevent breaking the UI
    return [];
  }
}

/**
 * Checks whether a nonce hash has already been used for a given session.
 * Nonces are tracked as SHA-256(nonceBytes) hex strings in the session record.
 * @param {string} sessionId - Session identifier
 * @param {string} nonceHash - Hex-encoded SHA-256 hash of the nonce
 * @returns {Promise<boolean>} True if nonce hash has been seen before
 */
export async function isNonceUsed(sessionId, nonceHash) {
  const db = await openDB();
  const transaction = db.transaction([SESSIONS_STORE], 'readonly');
  const store = transaction.objectStore(SESSIONS_STORE);

  const session = await new Promise((resolve, reject) => {
    const request = store.get(sessionId);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  if (!session || !Array.isArray(session.usedNonceHashes)) {
    return false;
  }

  return session.usedNonceHashes.includes(nonceHash);
}

/**
 * Stores a nonce hash for a session, keeping only the most recent 200 entries.
 * This prevents unbounded growth while still detecting recent replays.
 * @param {string} sessionId - Session identifier
 * @param {string} nonceHash - Hex-encoded SHA-256 hash of the nonce
 * @returns {Promise<void>}
 */
export async function storeUsedNonce(sessionId, nonceHash) {
  const db = await openDB();
  const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
  const store = transaction.objectStore(SESSIONS_STORE);

  const session = await new Promise((resolve, reject) => {
    const request = store.get(sessionId);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  if (!session) {
    // If the session does not exist, nothing to track.
    return;
  }

  let used = Array.isArray(session.usedNonceHashes)
    ? session.usedNonceHashes.slice()
    : [];

  if (!used.includes(nonceHash)) {
    used.push(nonceHash);
    // Keep only the last 200 nonces to bound storage.
    if (used.length > 200) {
      used = used.slice(used.length - 200);
    }
    session.usedNonceHashes = used;

    await new Promise((resolve, reject) => {
      const request = store.put(session);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
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
    
    // Store updated session (with encryption)
    await storeSession(session, userId);
    
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

