/**
 * Identity Key Management
 * 
 * Handles generation, storage, and retrieval of user identity key pairs.
 * Identity keys are ECC P-256 key pairs used for signing ephemeral keys
 * in the Key Exchange Protocol (KEP).
 * 
 * Storage Strategy:
 * - Private keys stored in IndexedDB (preferred) or encrypted localStorage
 * - Encryption uses AES-GCM with key derived from user password via PBKDF2
 * - Public keys are uploaded to server and stored in plaintext
 */

const DB_NAME = 'InfosecCryptoDB';
const DB_VERSION = 7; // Must match the highest version used by any module
const STORE_NAME = 'identityKeys';

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
      // Create identityKeys store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
      }
      // Also ensure other common stores exist (for backward compatibility)
      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions', { keyPath: 'sessionId' });
      }
      if (!db.objectStoreNames.contains('sessionEncryptionKeys')) {
        db.createObjectStore('sessionEncryptionKeys', { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains('messages')) {
        const msgStore = db.createObjectStore('messages', { keyPath: 'id' });
        msgStore.createIndex('sessionId', 'sessionId', { unique: false });
        msgStore.createIndex('timestamp', 'timestamp', { unique: false });
        msgStore.createIndex('seq', 'seq', { unique: false });
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
      if (!db.objectStoreNames.contains('messageQueue')) {
        const queueStore = db.createObjectStore('messageQueue', { keyPath: 'id', autoIncrement: true });
        queueStore.createIndex('sessionId', 'sessionId', { unique: false });
        queueStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
  });
}

/**
 * Checks if Web Crypto API is available
 * @returns {boolean}
 */
function isCryptoAvailable() {
  // Simply check if crypto.subtle exists
  // The browser will enforce secure context requirements itself
  return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
}

/**
 * Generates a new ECC P-256 identity key pair
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function generateIdentityKeyPair() {
  try {
    // Check if Web Crypto API is available
    if (!isCryptoAvailable()) {
      const hasCrypto = typeof crypto !== 'undefined';
      const hasSubtle = hasCrypto && typeof crypto.subtle !== 'undefined';
      const isSecure = typeof window !== 'undefined' && window.isSecureContext;
      const isLocalhost = typeof window !== 'undefined' && (
        window.location.hostname === 'localhost' || 
        window.location.hostname === '127.0.0.1' ||
        window.location.hostname === '[::1]'
      );
      
      let errorMsg = 'Web Crypto API is not available. ';
      
      if (!hasCrypto) {
        errorMsg += 'Your browser does not support the Web Crypto API. ';
      } else if (!hasSubtle) {
        errorMsg += 'Your browser does not support crypto.subtle. ';
      }
      
      if (typeof window !== 'undefined' && !isSecure && !isLocalhost) {
        errorMsg += 'This page must be served over HTTPS (or localhost) to use encryption. ';
      }
      
      errorMsg += 'Please use a modern browser (Chrome, Firefox, Edge, Safari) and ensure you are accessing the site over HTTPS or localhost.';
      
      throw new Error(errorMsg);
    }

    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true, // extractable
      ['sign', 'verify']
    );

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  } catch (error) {
    // If error already has a helpful message, re-throw it
    if (error.message && error.message.includes('Web Crypto API')) {
      throw error;
    }
    throw new Error(`Failed to generate identity key pair: ${error.message || error.toString()}`);
  }
}

/**
 * Derives encryption key from password using PBKDF2
 * @param {string} password - User password
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>}
 */
async function deriveKeyFromPassword(password, salt) {
  // Check if Web Crypto API is available
  if (!isCryptoAvailable()) {
    throw new Error('Web Crypto API is not available. This page must be served over HTTPS (or localhost).');
  }

  // Allow tests to lower iteration count via environment for performance,
  // while keeping production-strength defaults.
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
 * Stores private key encrypted with password
 * @param {string} userId - User ID
 * @param {CryptoKey} privateKey - Private key to store
 * @param {string} password - User password for encryption
 * @returns {Promise<void>}
 */
export async function storePrivateKeyEncrypted(userId, privateKey, password) {
  // Check if Web Crypto API is available
  if (!isCryptoAvailable()) {
    throw new Error('Web Crypto API is not available. This page must be served over HTTPS (or localhost).');
  }

  try {
    // Export private key to JWK format
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);

    // Convert JWK to ArrayBuffer for encryption
    const encoder = new TextEncoder();
    const keyData = encoder.encode(JSON.stringify(jwk));

    // Generate salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits for GCM

    // Derive encryption key from password
    const encryptionKey = await deriveKeyFromPassword(password, salt);

    // Encrypt private key
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      encryptionKey,
      keyData
    );

    // Store in IndexedDB
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const encryptedKey = {
      userId: userId,
      encryptedData: Array.from(new Uint8Array(encryptedData)),
      salt: Array.from(salt),
      iv: Array.from(iv),
      createdAt: new Date().toISOString()
    };

    await new Promise((resolve, reject) => {
      const request = store.put(encryptedKey);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });

    console.log('✓ Identity private key stored securely');
  } catch (error) {
    throw new Error(`Failed to store private key: ${error.message}`);
  }
}

/**
 * Loads and decrypts private key
 * @param {string} userId - User ID
 * @param {string} password - User password for decryption
 * @returns {Promise<CryptoKey>}
 */
export async function loadPrivateKey(userId, password) {
  // Check if Web Crypto API is available
  if (!isCryptoAvailable()) {
    throw new Error('Web Crypto API is not available. This page must be served over HTTPS (or localhost).');
  }

  try {
    // Load from IndexedDB
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);

    const encryptedKey = await new Promise((resolve, reject) => {
      const request = store.get(userId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    if (!encryptedKey) {
      throw new Error('Private key not found for user');
    }

    // Convert stored arrays back to Uint8Array
    const encryptedData = new Uint8Array(encryptedKey.encryptedData);
    const salt = new Uint8Array(encryptedKey.salt);
    const iv = new Uint8Array(encryptedKey.iv);

    // Derive decryption key
    const decryptionKey = await deriveKeyFromPassword(password, salt);

    // Decrypt
    let decryptedData;
    try {
      decryptedData = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        decryptionKey,
        encryptedData
      );
    } catch (decryptError) {
      // Decryption failed - likely wrong password
      const errorMsg = decryptError.message || decryptError.name || 'Decryption failed';
      throw new Error(`Failed to decrypt private key. The password may be incorrect. (${errorMsg})`);
    }

    // Parse JWK and import key
    let jwk;
    try {
      const decoder = new TextDecoder();
      jwk = JSON.parse(decoder.decode(decryptedData));
    } catch (parseError) {
      throw new Error('Failed to parse decrypted key data. The key may be corrupted.');
    }

    let privateKey;
    try {
      privateKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        {
          name: 'ECDSA',
          namedCurve: 'P-256'
        },
        true,
        ['sign']
      );
    } catch (importError) {
      const errorMsg = importError.message || importError.name || 'Import failed';
      throw new Error(`Failed to import private key. The key data may be corrupted. (${errorMsg})`);
    }

    return privateKey;
  } catch (error) {
    // If error already has a user-friendly message, re-throw it
    if (error.message && error.message.includes('Failed to decrypt') || 
        error.message && error.message.includes('Failed to parse') ||
        error.message && error.message.includes('Failed to import')) {
      throw error;
    }
    
    // Provide more detailed error messages for other errors
    let errorMessage = error.message || error.name || error.toString() || 'Unknown error';
    
    if (errorMessage.includes('not found') || errorMessage.includes('No such object')) {
      errorMessage = 'Private key not found. Please generate an identity key pair in the Keys page.';
    } else if (errorMessage.includes('decrypt') || errorMessage.includes('password') || errorMessage.includes('bad decrypt')) {
      errorMessage = 'Failed to decrypt private key. The password may be incorrect.';
    } else if (errorMessage.includes('importKey') || errorMessage.includes('Invalid key')) {
      errorMessage = 'Private key data is corrupted. Please regenerate your identity key pair.';
    }
    
    const detailedError = new Error(`Failed to load private key: ${errorMessage}`);
    detailedError.originalError = error;
    throw detailedError;
  }
}

/**
 * Exports public key in JWK format
 * @param {CryptoKey} publicKey - Public key to export
 * @returns {Promise<Object>} JWK object
 */
export async function exportPublicKey(publicKey) {
  try {
    return await crypto.subtle.exportKey('jwk', publicKey);
  } catch (error) {
    throw new Error(`Failed to export public key: ${error.message}`);
  }
}

/**
 * Imports public key from JWK format
 * @param {Object} jwk - JWK object
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(jwk) {
  // Check if Web Crypto API is available
  if (!isCryptoAvailable()) {
    throw new Error('Web Crypto API is not available. This page must be served over HTTPS (or localhost).');
  }

  try {
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['verify']
    );
  } catch (error) {
    throw new Error(`Failed to import public key: ${error.message}`);
  }
}

/**
 * Checks if identity key pair exists for user
 * @param {string} userId - User ID
 * @returns {Promise<boolean>}
 */
export async function hasIdentityKey(userId) {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);

    const result = await new Promise((resolve, reject) => {
      const request = store.get(userId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    return !!result;
  } catch (error) {
    return false;
  }
}

/**
 * Deletes stored identity key (for testing/cleanup)
 * @param {string} userId - User ID
 * @returns {Promise<void>}
 */
export async function deleteIdentityKey(userId) {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    await new Promise((resolve, reject) => {
      const request = store.delete(userId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    throw new Error(`Failed to delete identity key: ${error.message}`);
  }
}

