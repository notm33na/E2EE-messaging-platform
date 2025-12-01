/**
 * Memory Security Utilities
 * 
 * Provides functions to securely clear sensitive data from memory
 * to prevent plaintext exposure in browser memory dumps.
 */

/**
 * Securely clears an ArrayBuffer by overwriting with random data
 * @param {ArrayBuffer} buffer - Buffer to clear
 */
export function secureClearArrayBuffer(buffer) {
  if (!buffer || buffer.byteLength === 0) {
    return;
  }

  try {
    // Overwrite with random data (multiple passes for better security)
    const view = new Uint8Array(buffer);
    for (let pass = 0; pass < 3; pass++) {
      crypto.getRandomValues(view);
    }
    // Final pass: zero out
    view.fill(0);
  } catch (error) {
    // If clearing fails, at least try to zero out
    try {
      new Uint8Array(buffer).fill(0);
    } catch (e) {
      // Ignore - buffer may be read-only or already cleared
    }
  }
}

/**
 * Securely clears a string by creating and clearing a buffer
 * Note: JavaScript strings are immutable, so this creates a new buffer
 * @param {string} str - String to clear (reference)
 * @returns {ArrayBuffer} Buffer that was cleared (caller should discard reference)
 */
export function secureClearString(str) {
  if (!str) {
    return new ArrayBuffer(0);
  }

  const encoder = new TextEncoder();
  const buffer = encoder.encode(str).buffer;
  secureClearArrayBuffer(buffer);
  return buffer;
}

/**
 * Securely clears plaintext after encryption
 * @param {ArrayBuffer|string} plaintext - Plaintext to clear
 */
export function clearPlaintextAfterEncryption(plaintext) {
  if (plaintext instanceof ArrayBuffer) {
    secureClearArrayBuffer(plaintext);
  } else if (typeof plaintext === 'string') {
    secureClearString(plaintext);
  }
}

/**
 * Securely clears decrypted plaintext after use
 * @param {ArrayBuffer|string} plaintext - Decrypted plaintext to clear
 */
export function clearPlaintextAfterDecryption(plaintext) {
  if (plaintext instanceof ArrayBuffer) {
    secureClearArrayBuffer(plaintext);
  } else if (typeof plaintext === 'string') {
    secureClearString(plaintext);
  }
}

