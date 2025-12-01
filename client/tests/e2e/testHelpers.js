/**
 * E2EE Test Helpers
 * 
 * Provides utilities for E2EE tests including:
 * - Test user setup (Alice/Bob)
 * - IndexedDB cleanup
 * - Crypto key comparison utilities
 * - Test data generators
 */

/**
 * Clears all IndexedDB databases used by the app
 */
export async function clearIndexedDB() {
  const dbNames = ['InfosecCryptoDB'];
  
  for (const dbName of dbNames) {
    try {
      const deleteRequest = indexedDB.deleteDatabase(dbName);
      await Promise.race([
        new Promise((resolve, reject) => {
          deleteRequest.onsuccess = () => resolve();
          deleteRequest.onerror = () => reject(deleteRequest.error);
          deleteRequest.onblocked = () => {
            // Database is blocked, wait a bit and try again
            setTimeout(resolve, 100);
          };
        }),
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error('IndexedDB deletion timeout')), 2000);
        })
      ]).catch((error) => {
        // Ignore timeout errors - database might not exist or be in use
        if (!error.message.includes('timeout')) {
          throw error;
        }
      });
    } catch (error) {
      // Ignore errors if database doesn't exist or deletion fails
      // This is safe for test cleanup
    }
  }
  
  // Small delay to ensure cleanup completes
  await new Promise(resolve => setTimeout(resolve, 50));
}

/**
 * Compares two ArrayBuffers for equality
 * @param {ArrayBuffer} a - First buffer
 * @param {ArrayBuffer} b - Second buffer
 * @returns {boolean} True if buffers are equal
 */
export function arrayBuffersEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  const viewA = new Uint8Array(a);
  const viewB = new Uint8Array(b);
  for (let i = 0; i < viewA.length; i++) {
    if (viewA[i] !== viewB[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Converts ArrayBuffer to hex string for debugging
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Hex string
 */
export function arrayBufferToHex(buffer) {
  const view = new Uint8Array(buffer);
  return Array.from(view)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generates test user data
 * @param {string} name - User name (e.g., 'alice', 'bob')
 * @returns {Object} User data
 */
export function generateTestUser(name) {
  return {
    userId: `test-${name}-${Date.now()}`,
    password: `TestPassword123!${name}`,
    email: `test-${name}@example.com`
  };
}

/**
 * Waits for a specified number of milliseconds
 * @param {number} ms - Milliseconds to wait
 * @returns {Promise<void>}
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Creates a test file for file encryption tests
 * @param {string} filename - File name
 * @param {string} content - File content
 * @param {string} mimetype - MIME type
 * @returns {File} File object
 */
export function createTestFile(filename, content, mimetype = 'text/plain') {
  const blob = new Blob([content], { type: mimetype });
  return new File([blob], filename, { type: mimetype });
}

/**
 * Reads a File as ArrayBuffer
 * @param {File} file - File to read
 * @returns {Promise<ArrayBuffer>}
 */
export async function readFileAsArrayBuffer(file) {
  return await file.arrayBuffer();
}

/**
 * Compares two CryptoKeys by exporting and comparing JWK
 * Note: This only works for extractable keys
 * @param {CryptoKey} key1 - First key
 * @param {CryptoKey} key2 - Second key
 * @returns {Promise<boolean>} True if keys are equal
 */
export async function cryptoKeysEqual(key1, key2) {
  try {
    const jwk1 = await crypto.subtle.exportKey('jwk', key1);
    const jwk2 = await crypto.subtle.exportKey('jwk', key2);
    
    // Compare JWK properties
    return (
      jwk1.kty === jwk2.kty &&
      jwk1.crv === jwk2.crv &&
      jwk1.x === jwk2.x &&
      jwk1.y === jwk2.y &&
      (jwk1.d === undefined || jwk1.d === jwk2.d) // Private key component (if present)
    );
  } catch (error) {
    return false;
  }
}

/**
 * Validates that a value is NOT plaintext (for security checks)
 * @param {*} value - Value to check
 * @param {string} knownPlaintext - Known plaintext that should NOT appear
 * @returns {boolean} True if plaintext is NOT found
 */
export function ensureNoPlaintext(value, knownPlaintext) {
  if (typeof value === 'string') {
    return !value.includes(knownPlaintext);
  }
  if (value instanceof ArrayBuffer) {
    const view = new Uint8Array(value);
    const plaintextBytes = new TextEncoder().encode(knownPlaintext);
    // Check if plaintext bytes appear in the buffer
    for (let i = 0; i <= view.length - plaintextBytes.length; i++) {
      let match = true;
      for (let j = 0; j < plaintextBytes.length; j++) {
        if (view[i + j] !== plaintextBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        return false;
      }
    }
    return true;
  }
  // For objects, recursively check
  if (typeof value === 'object' && value !== null) {
    for (const key in value) {
      if (!ensureNoPlaintext(value[key], knownPlaintext)) {
        return false;
      }
    }
  }
  return true;
}

