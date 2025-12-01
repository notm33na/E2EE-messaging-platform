/**
 * Test Data Generator Utility
 * 
 * Provides functions to generate test data for frontend tests.
 * Uses Web Crypto API exclusively.
 * 
 * IMPORTANT: This utility is ONLY for tests - NOT for production use.
 * Private keys are stored in-memory only and never exported.
 */

// In-memory storage for private keys (never exported)
// Maps public key JWK string representation to private key
const privateKeyStore = new Map();

// Sequence counter for message metadata
let sequenceCounter = 0;

/**
 * Creates a unique key from JWK for storage lookup
 * @param {Object} jwk - JWK object
 * @returns {string} Unique key string
 */
function getJwkKey(jwk) {
  return `${jwk.kty}_${jwk.crv}_${jwk.x}_${jwk.y}`;
}

/**
 * Converts ArrayBuffer to base64url string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Base64url string
 */
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Convert to base64, then to base64url
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Converts base64url string to ArrayBuffer
 * @param {string} base64url - Base64url string
 * @returns {ArrayBuffer} ArrayBuffer
 */
function base64urlToArrayBuffer(base64url) {
  // Convert base64url to base64
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Generates ECDSA P-256 identity keypair
 * Returns public JWK only (private key stored in-memory)
 * @returns {Promise<Object>} Public key in JWK format
 */
export async function generateIdentityKeys() {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true, // extractable
      ['sign', 'verify']
    );

    // Export public key to JWK
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    // Store private key in-memory (never export)
    // Use JWK properties as key for lookup
    const jwkKey = getJwkKey(publicKeyJwk);
    privateKeyStore.set(jwkKey, keyPair.privateKey);

    return publicKeyJwk;
  } catch (error) {
    throw new Error(`Failed to generate identity keys: ${error.message}`);
  }
}

/**
 * Gets private identity key from store (internal use only)
 * @param {Object} publicKeyJwk - Public key JWK
 * @returns {CryptoKey|null} Private key or null if not found
 */
function getPrivateIdentityKey(publicKeyJwk) {
  const jwkKey = getJwkKey(publicKeyJwk);
  return privateKeyStore.get(jwkKey) || null;
}

/**
 * Generates ephemeral P-256 ECDH keypair
 * @returns {Promise<{publicKeyJwk: Object, privateKeyObject: CryptoKey}>}
 */
export async function generateEphemeralECDHKeys() {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true, // extractable
      ['deriveKey', 'deriveBits']
    );

    // Export public key to JWK
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    return {
      publicKeyJwk,
      privateKeyObject: keyPair.privateKey
    };
  } catch (error) {
    throw new Error(`Failed to generate ephemeral ECDH keys: ${error.message}`);
  }
}

/**
 * Derives AES-GCM 256-bit session key using HKDF
 * @param {ArrayBuffer} sharedSecret - ECDH shared secret
 * @returns {Promise<ArrayBuffer>} Derived 256-bit session key
 */
export async function generateHKDFSessionKey(sharedSecret) {
  try {
    const encoder = new TextEncoder();

    // Generate random 16-byte salt
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Info: "test-session"
    const info = encoder.encode('test-session');

    // Import shared secret as HKDF key material
    const baseKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits']
    );

    // Derive 256-bit (32-byte) key
    const derivedKey = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: info
      },
      baseKey,
      256 // 256 bits = 32 bytes
    );

    return derivedKey;
  } catch (error) {
    throw new Error(`Failed to derive HKDF session key: ${error.message}`);
  }
}

/**
 * Generates a random 12-byte IV for AES-GCM
 * @returns {Uint8Array} 12-byte IV
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Encrypts plaintext using AES-GCM
 * @param {ArrayBuffer} sessionKey - 256-bit session key
 * @param {ArrayBuffer|string} plaintext - Data to encrypt
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: Uint8Array, authTag: ArrayBuffer}>}
 */
export async function generateCiphertext(sessionKey, plaintext) {
  try {
    // Convert string to ArrayBuffer if needed
    let plaintextBuffer;
    if (typeof plaintext === 'string') {
      const encoder = new TextEncoder();
      plaintextBuffer = encoder.encode(plaintext);
    } else {
      plaintextBuffer = plaintext;
    }

    // Generate IV
    const iv = generateIV();

    // Import session key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      sessionKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt']
    );

    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128 // 128-bit authentication tag
      },
      cryptoKey,
      plaintextBuffer
    );

    // Extract ciphertext and auth tag
    // In Web Crypto API, the auth tag is appended to the ciphertext
    const tagLength = 16; // 128 bits = 16 bytes
    const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);
    const authTag = encrypted.slice(encrypted.byteLength - tagLength);

    return {
      ciphertext,
      iv,
      authTag
    };
  } catch (error) {
    throw new Error(`Failed to generate ciphertext: ${error.message}`);
  }
}

/**
 * Generates message metadata
 * @param {string} sender - Sender user ID
 * @param {string} receiver - Receiver user ID
 * @returns {Object} Message metadata
 */
export function generateMessageMetadata(sender, receiver) {
  // Generate random 16-byte nonce as hex string
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = Array.from(nonceBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Increment sequence
  sequenceCounter += 1;

  return {
    timestamp: new Date().toISOString(),
    seq: sequenceCounter,
    nonce: nonce,
    type: 'MSG'
  };
}

/**
 * Generates ECDSA P-256 signature and verifies it before returning
 * @param {Object} privateIdentityKey - Public key JWK from generateIdentityKeys() (used to retrieve private key)
 * @param {ArrayBuffer|string} data - Data to sign
 * @returns {Promise<string>} Base64url-encoded signature
 */
export async function generateSignature(privateIdentityKey, data) {
  try {
    // Get private key from store using public key JWK
    const privateKey = getPrivateIdentityKey(privateIdentityKey);
    if (!privateKey) {
      throw new Error('Private key not found in store. Use generateIdentityKeys() first and pass the returned public key JWK.');
    }

    // Convert string to ArrayBuffer if needed
    let dataBuffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      dataBuffer = encoder.encode(data);
    } else {
      dataBuffer = data;
    }

    // Sign data
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      privateKey,
      dataBuffer
    );

    // Export public key for verification
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: privateIdentityKey.kty,
        crv: privateIdentityKey.crv,
        x: privateIdentityKey.x,
        y: privateIdentityKey.y,
        use: privateIdentityKey.use,
        key_ops: ['verify']
      },
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      false,
      ['verify']
    );

    // Verify signature before returning
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      publicKey,
      signature,
      dataBuffer
    );

    if (!isValid) {
      throw new Error('Generated signature failed verification');
    }

    // Convert to base64url
    return arrayBufferToBase64url(signature);
  } catch (error) {
    throw new Error(`Failed to generate signature: ${error.message}`);
  }
}

/**
 * Splits file into chunks and encrypts each chunk with AES-GCM
 * @param {Blob|File} fileBlob - File to encrypt
 * @param {ArrayBuffer} sessionKey - 256-bit session key
 * @returns {Promise<Array<Object>>} Array of encrypted chunk metadata objects
 */
export async function generateEncryptedFileChunks(fileBlob, sessionKey) {
  try {
    const CHUNK_SIZE = 64 * 1024; // 64 KB chunks
    const fileBuffer = await fileBlob.arrayBuffer();
    const chunks = [];
    const totalChunks = Math.ceil(fileBuffer.byteLength / CHUNK_SIZE);

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileBuffer.byteLength);
      const chunkBuffer = fileBuffer.slice(start, end);

      // Encrypt chunk
      const { ciphertext, iv, authTag } = await generateCiphertext(sessionKey, chunkBuffer);

      chunks.push({
        chunkIndex: i,
        totalChunks: totalChunks,
        ciphertext: ciphertext,
        iv: iv,
        authTag: authTag,
        size: chunkBuffer.byteLength
      });
    }

    return chunks;
  } catch (error) {
    throw new Error(`Failed to generate encrypted file chunks: ${error.message}`);
  }
}

/**
 * Resets the sequence counter (useful for test cleanup)
 */
export function resetSequenceCounter() {
  sequenceCounter = 0;
}

/**
 * Clears all stored private keys (useful for test cleanup)
 */
export function clearPrivateKeyStore() {
  privateKeyStore.clear();
}

