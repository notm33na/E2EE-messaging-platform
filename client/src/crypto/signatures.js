/**
 * Digital Signature Operations
 * 
 * Handles signing and verification of data using ECC P-256 keys.
 * Used for:
 * - Signing ephemeral public keys in KEP
 * - Verifying signatures from peers
 */

/**
 * Signs data using private key
 * @param {CryptoKey} privateKey - Private key for signing
 * @param {ArrayBuffer|string} data - Data to sign
 * @returns {Promise<ArrayBuffer>} Signature as ArrayBuffer
 */
export async function signData(privateKey, data) {
  try {
    // Convert string to ArrayBuffer if needed
    let dataBuffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      dataBuffer = encoder.encode(data);
    } else {
      dataBuffer = data;
    }

    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      privateKey,
      dataBuffer
    );

    return signature;
  } catch (error) {
    throw new Error(`Failed to sign data: ${error.message}`);
  }
}

/**
 * Verifies signature using public key
 * @param {CryptoKey} publicKey - Public key for verification
 * @param {ArrayBuffer} signature - Signature to verify
 * @param {ArrayBuffer|string} data - Original data
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifySignature(publicKey, signature, data) {
  try {
    // Convert string to ArrayBuffer if needed
    let dataBuffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      dataBuffer = encoder.encode(data);
    } else {
      dataBuffer = data;
    }

    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      publicKey,
      signature,
      dataBuffer
    );

    return isValid;
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Signs ephemeral public key for KEP
 * @param {CryptoKey} identityPrivateKey - Identity private key
 * @param {Object} ephPubJWK - Ephemeral public key in JWK format
 * @returns {Promise<ArrayBuffer>} Signature
 */
export async function signEphemeralKey(identityPrivateKey, ephPubJWK) {
  try {
    // Serialize JWK to string for signing
    const jwkString = JSON.stringify(ephPubJWK);
    return await signData(identityPrivateKey, jwkString);
  } catch (error) {
    throw new Error(`Failed to sign ephemeral key: ${error.message}`);
  }
}

/**
 * Verifies signature on ephemeral public key
 * @param {CryptoKey} identityPublicKey - Identity public key
 * @param {ArrayBuffer} signature - Signature to verify
 * @param {Object} ephPubJWK - Ephemeral public key in JWK format
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifyEphemeralKeySignature(identityPublicKey, signature, ephPubJWK) {
  try {
    const jwkString = JSON.stringify(ephPubJWK);
    return await verifySignature(identityPublicKey, signature, jwkString);
  } catch (error) {
    console.error('Ephemeral key signature verification error:', error);
    return false;
  }
}

/**
 * Converts ArrayBuffer to base64 string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Base64 string
 */
export function arrayBufferToBase64(buffer) {
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
export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

