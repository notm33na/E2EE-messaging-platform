/**
 * Memory Security Utilities
 * Provides functions to minimize plaintext exposure in browser memory
 */

/**
 * Clears an ArrayBuffer by overwriting with zeros
 * Note: This is best-effort; JavaScript doesn't guarantee memory clearing
 * @param {ArrayBuffer} buffer - Buffer to clear
 */
export function clearArrayBuffer(buffer) {
  if (buffer && buffer.byteLength > 0) {
    try {
      const view = new Uint8Array(buffer);
      // Overwrite with zeros
      view.fill(0);
      // Try to clear reference
      view.set([]);
    } catch (error) {
      // Silently fail - memory clearing is best-effort
      console.warn('Failed to clear ArrayBuffer:', error);
    }
  }
}

/**
 * Clears a string from memory (best-effort)
 * Note: Strings are immutable in JavaScript, but we can minimize references
 * @param {string} str - String to clear (reference)
 */
export function clearString(str) {
  // Strings are immutable, but we can minimize exposure
  // Return empty string to replace reference
  return '';
}

/**
 * Clears plaintext data after encryption/decryption operations
 * @param {ArrayBuffer|string} data - Data to clear
 */
export function clearPlaintextAfterOperation(data) {
  if (data instanceof ArrayBuffer) {
    clearArrayBuffer(data);
  } else if (typeof data === 'string') {
    // Strings are immutable, but minimize exposure time
    // Clear any buffer representations if they exist
    return clearString(data);
  }
}

/**
 * Wraps a function to automatically clear sensitive data after execution
 * @param {Function} fn - Function to wrap
 * @param {Array<string>} sensitiveParams - Parameter names that contain sensitive data
 * @returns {Function} Wrapped function
 */
export function withMemoryClearing(fn, sensitiveParams = []) {
  return async function(...args) {
    try {
      const result = await fn.apply(this, args);
      // Clear sensitive parameters after function execution
      sensitiveParams.forEach((paramName, index) => {
        if (args[index]) {
          clearPlaintextAfterOperation(args[index]);
        }
      });
      return result;
    } catch (error) {
      // Clear on error too
      sensitiveParams.forEach((paramName, index) => {
        if (args[index]) {
          clearPlaintextAfterOperation(args[index]);
        }
      });
      throw error;
    }
  };
}

/**
 * Minimizes memory exposure time by clearing data as soon as possible
 * @param {Function} operation - Operation to perform
 * @param {ArrayBuffer|string} sensitiveData - Sensitive data to clear after operation
 * @returns {Promise<any>} Operation result
 */
export async function minimizeMemoryExposure(operation, sensitiveData) {
  try {
    const result = await operation();
    // Clear sensitive data immediately after operation
    clearPlaintextAfterOperation(sensitiveData);
    return result;
  } catch (error) {
    // Clear on error
    clearPlaintextAfterOperation(sensitiveData);
    throw error;
  }
}

