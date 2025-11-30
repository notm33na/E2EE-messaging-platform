/**
 * ECDH (Elliptic Curve Diffie-Hellman) Operations
 * 
 * Handles ephemeral key generation, shared secret computation,
 * and HKDF-based key derivation for session keys.
 * 
 * Uses Web Crypto API with P-256 curve.
 */

/**
 * Generates an ephemeral ECDH key pair for key exchange
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function generateEphemeralKeyPair() {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true, // extractable
      ['deriveKey', 'deriveBits']
    );

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
    };
  } catch (error) {
    throw new Error(`Failed to generate ephemeral key pair: ${error.message}`);
  }
}

/**
 * Computes shared secret using ECDH
 * @param {CryptoKey} privateKey - Our private key
 * @param {CryptoKey} publicKey - Their public key
 * @returns {Promise<ArrayBuffer>} Shared secret as ArrayBuffer
 */
export async function computeSharedSecret(privateKey, publicKey) {
  try {
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
        public: publicKey
      },
      privateKey,
      256 // 256 bits = 32 bytes
    );

    return sharedSecret;
  } catch (error) {
    throw new Error(`Failed to compute shared secret: ${error.message}`);
  }
}

/**
 * HKDF (HMAC-based Key Derivation Function) using Web Crypto API
 * @param {ArrayBuffer} inputKeyMaterial - Input key material (shared secret)
 * @param {ArrayBuffer} salt - Salt (optional, can be empty)
 * @param {ArrayBuffer} info - Context/application-specific info
 * @param {number} length - Output length in bits
 * @returns {Promise<ArrayBuffer>} Derived key material
 */
export async function hkdf(inputKeyMaterial, salt, info, length) {
  try {
    // Import input key material
    const baseKey = await crypto.subtle.importKey(
      'raw',
      inputKeyMaterial,
      'HKDF',
      false,
      ['deriveBits']
    );

    // Derive key using HKDF
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt || new ArrayBuffer(0),
        info: info
      },
      baseKey,
      length
    );

    return derivedBits;
  } catch (error) {
    throw new Error(`HKDF derivation failed: ${error.message}`);
  }
}

/**
 * Derives session keys from shared secret using HKDF
 * 
 * Key derivation chain:
 * 1. rootKey = HKDF(sharedSecret, salt="ROOT", info=sessionId, 256 bits)
 * 2. sendKey = HKDF(rootKey, salt="SEND", info=userId, 256 bits)
 * 3. recvKey = HKDF(rootKey, salt="RECV", info=peerId, 256 bits)
 * 
 * @param {ArrayBuffer} sharedSecret - ECDH shared secret
 * @param {string} sessionId - Unique session identifier
 * @param {string} userId - Our user ID
 * @param {string} peerId - Peer user ID
 * @returns {Promise<{rootKey: ArrayBuffer, sendKey: ArrayBuffer, recvKey: ArrayBuffer}>}
 */
export async function deriveSessionKeys(sharedSecret, sessionId, userId, peerId) {
  try {
    const encoder = new TextEncoder();

    // Derive root key
    const rootKeySalt = encoder.encode('ROOT');
    const rootKeyInfo = encoder.encode(sessionId);
    const rootKey = await hkdf(sharedSecret, rootKeySalt, rootKeyInfo, 256);

    // Derive send key (for messages we send)
    const sendKeySalt = encoder.encode('SEND');
    const sendKeyInfo = encoder.encode(userId);
    const sendKey = await hkdf(rootKey, sendKeySalt, sendKeyInfo, 256);

    // Derive receive key (for messages we receive)
    const recvKeySalt = encoder.encode('RECV');
    const recvKeyInfo = encoder.encode(peerId);
    const recvKey = await hkdf(rootKey, recvKeySalt, recvKeyInfo, 256);

    return {
      rootKey,
      sendKey,
      recvKey
    };
  } catch (error) {
    throw new Error(`Failed to derive session keys: ${error.message}`);
  }
}

/**
 * Exports public key to JWK format
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
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
  } catch (error) {
    throw new Error(`Failed to import public key: ${error.message}`);
  }
}

