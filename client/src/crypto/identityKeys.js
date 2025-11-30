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
const DB_VERSION = 1;
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
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
      }
    };
  });
}

/**
 * Generates a new ECC P-256 identity key pair
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function generateIdentityKeyPair() {
  try {
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
    throw new Error(`Failed to generate identity key pair: ${error.message}`);
  }
}

/**
 * Derives encryption key from password using PBKDF2
 * @param {string} password - User password
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>}
 */
async function deriveKeyFromPassword(password, salt) {
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
      iterations: 100000,
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
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      decryptionKey,
      encryptedData
    );

    // Parse JWK and import key
    const decoder = new TextDecoder();
    const jwk = JSON.parse(decoder.decode(decryptedData));

    const privateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign']
    );

    return privateKey;
  } catch (error) {
    throw new Error(`Failed to load private key: ${error.message}`);
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

