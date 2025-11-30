/**
 * AES-256-GCM Encryption/Decryption
 * 
 * Provides AES-GCM encryption and decryption using Web Crypto API.
 * Uses 256-bit keys and 96-bit IVs as required by GCM mode.
 */

import { base64ToArrayBuffer } from './signatures.js';

/**
 * Generates a random 96-bit (12-byte) IV for AES-GCM
 * @returns {Uint8Array} 96-bit IV
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Encrypts data using AES-256-GCM
 * @param {ArrayBuffer} key - 256-bit encryption key
 * @param {ArrayBuffer|string} plaintext - Data to encrypt
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: Uint8Array, authTag: ArrayBuffer}>}
 */
export async function encryptAESGCM(key, plaintext) {
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

    // Import key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
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
    throw new Error(`AES-GCM encryption failed: ${error.message}`);
  }
}

/**
 * Decrypts data using AES-256-GCM
 * @param {ArrayBuffer} key - 256-bit decryption key
 * @param {Uint8Array|ArrayBuffer} iv - Initialization vector (96 bits)
 * @param {ArrayBuffer} ciphertext - Encrypted data
 * @param {ArrayBuffer} authTag - Authentication tag (128 bits)
 * @returns {Promise<ArrayBuffer>} Decrypted plaintext
 */
export async function decryptAESGCM(key, iv, ciphertext, authTag) {
  try {
    // Ensure IV is Uint8Array
    const ivArray = iv instanceof Uint8Array ? iv : new Uint8Array(iv);

    // Import key
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['decrypt']
    );

    // Combine ciphertext and auth tag (Web Crypto expects them together)
    const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    combined.set(new Uint8Array(ciphertext), 0);
    combined.set(new Uint8Array(authTag), ciphertext.byteLength);

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivArray,
        tagLength: 128
      },
      cryptoKey,
      combined
    );

    return decrypted;
  } catch (error) {
    if (error.name === 'OperationError') {
      throw new Error('Decryption failed: Authentication tag verification failed');
    }
    throw new Error(`AES-GCM decryption failed: ${error.message}`);
  }
}

/**
 * Decrypts data and converts to string
 * @param {ArrayBuffer} key - 256-bit decryption key
 * @param {Uint8Array|ArrayBuffer} iv - Initialization vector
 * @param {ArrayBuffer} ciphertext - Encrypted data
 * @param {ArrayBuffer} authTag - Authentication tag
 * @returns {Promise<string>} Decrypted text
 */
export async function decryptAESGCMToString(key, iv, ciphertext, authTag) {
  const decrypted = await decryptAESGCM(key, iv, ciphertext, authTag);
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

