/**
 * File Decryption
 * 
 * Handles decryption and reconstruction of encrypted files.
 */

import { decryptAESGCM } from './aesGcm.js';
import { base64ToArrayBuffer } from './signatures.js';
import { getRecvKey, loadSession } from './sessionManager.js';
import { clearPlaintextAfterDecryption } from './memorySecurity.js';

/**
 * Decrypts file metadata and chunks, reconstructs original file
 * @param {Object} metaEnvelope - FILE_META envelope
 * @param {Array<Object>} chunkEnvelopes - Array of FILE_CHUNK envelopes
 * @param {string} sessionId - Session identifier
 * @param {string} userId - User ID for key access
 * @param {Function} onProgress - Optional progress callback (chunkIndex, totalChunks, progress)
 * @returns {Promise<{blob: Blob, filename: string, mimetype: string}>}
 */
/**
 * Validates timestamp freshness
 * @param {number} messageTimestamp - Message timestamp
 * @param {number} maxAge - Maximum age in milliseconds (default: 2 minutes)
 * @returns {boolean} True if timestamp is valid
 */
function validateTimestamp(messageTimestamp, maxAge = 120000) {
  const now = Date.now();
  const age = now - messageTimestamp;
  return age <= maxAge && age >= -maxAge;
}

export async function decryptFile(metaEnvelope, chunkEnvelopes, sessionId, userId = null, onProgress = null) {
  try {
    // 1. Validate timestamps (maxAge = 2 minutes = 120000ms)
    const maxAge = 120000;
    
    // Check metadata envelope timestamp
    if (metaEnvelope.timestamp && !validateTimestamp(metaEnvelope.timestamp, maxAge)) {
      const now = Date.now();
      const age = Math.abs(now - metaEnvelope.timestamp);
      const error = new Error(`Timestamp out of validity window: message is ${Math.round(age / 1000)}s old (max ${maxAge / 1000}s)`);
      console.error(`Timestamp validation error: ${error.message}`);
      throw error;
    }
    
    // Check chunk envelope timestamps
    if (chunkEnvelopes && Array.isArray(chunkEnvelopes)) {
      for (const chunk of chunkEnvelopes) {
        if (chunk.timestamp && !validateTimestamp(chunk.timestamp, maxAge)) {
          const now = Date.now();
          const age = Math.abs(now - chunk.timestamp);
          const error = new Error(`Timestamp out of validity window: chunk ${chunk.meta?.chunkIndex ?? 'unknown'} is ${Math.round(age / 1000)}s old (max ${maxAge / 1000}s)`);
          console.error(`Timestamp validation error: ${error.message}`);
          throw error;
        }
      }
    }
    
    // 2. Get receive key (with userId for encrypted key access)
    // Load session first to get userId if not provided
    if (!userId) {
      const session = await loadSession(sessionId, null);
      if (session) {
        userId = session.userId;
      }
    }
    const recvKey = await getRecvKey(sessionId, userId);

    // 3. Decrypt metadata
    const metaCiphertext = base64ToArrayBuffer(metaEnvelope.ciphertext);
    const metaIV = base64ToArrayBuffer(metaEnvelope.iv);
    const metaAuthTag = base64ToArrayBuffer(metaEnvelope.authTag);

    const decryptedMeta = await decryptAESGCM(recvKey, metaIV, metaCiphertext, metaAuthTag);
    const decoder = new TextDecoder();
    const metadataJson = decoder.decode(decryptedMeta);
    const metadata = JSON.parse(metadataJson);

    const { filename, size, totalChunks, mimetype } = metadata;
    
    // Report initial progress
    if (onProgress) {
      onProgress(0, totalChunks, 0, 0, 0);
    }

    // 3. Sort chunks by index
    const sortedChunks = chunkEnvelopes
      .slice()
      .sort((a, b) => a.meta.chunkIndex - b.meta.chunkIndex);

    // 4. Verify we have all chunks
    if (sortedChunks.length !== totalChunks) {
      const error = new Error(`Missing chunks: expected ${totalChunks}, got ${sortedChunks.length}`);
      console.error(`Missing chunks error: ${error.message}`);
      throw error;
    }

    // 5. Decrypt all chunks
    const decryptedChunks = [];
    const startTime = Date.now();

    for (let i = 0; i < sortedChunks.length; i++) {
      const chunkEnvelope = sortedChunks[i];

      // Verify chunk index matches
      if (chunkEnvelope.meta.chunkIndex !== i) {
        const error = new Error(`Chunk index mismatch: expected ${i}, got ${chunkEnvelope.meta.chunkIndex}`);
        console.error(`Chunk index mismatch error: ${error.message}`);
        throw error;
      }

      // Decrypt chunk
      const chunkCiphertext = base64ToArrayBuffer(chunkEnvelope.ciphertext);
      const chunkIV = base64ToArrayBuffer(chunkEnvelope.iv);
      const chunkAuthTag = base64ToArrayBuffer(chunkEnvelope.authTag);

      const decryptedChunk = await decryptAESGCM(recvKey, chunkIV, chunkCiphertext, chunkAuthTag);
      decryptedChunks.push(decryptedChunk);

      // Report progress
      if (onProgress) {
        const progress = ((i + 1) / totalChunks) * 100;
        const elapsed = (Date.now() - startTime) / 1000; // seconds
        // Calculate processed bytes (sum of all decrypted chunks so far)
        const processedBytes = decryptedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0) + decryptedChunk.byteLength;
        const speed = elapsed > 0 ? processedBytes / elapsed : 0; // bytes per second
        const remainingBytes = Math.max(0, size - processedBytes);
        const timeRemaining = speed > 0 ? remainingBytes / speed : 0; // seconds

        onProgress(i + 1, totalChunks, progress, speed, timeRemaining);
      }
    }

    // 6. Combine chunks into single ArrayBuffer
    const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    const combinedBuffer = new Uint8Array(totalSize);
    let offset = 0;

    for (const chunk of decryptedChunks) {
      combinedBuffer.set(new Uint8Array(chunk), offset);
      offset += chunk.byteLength;
    }

    // 7. Create Blob
    const blob = new Blob([combinedBuffer], { type: mimetype });

    // 8. Clear decrypted chunks from memory after blob creation
    for (const chunk of decryptedChunks) {
      clearPlaintextAfterDecryption(chunk);
    }
    clearPlaintextAfterDecryption(combinedBuffer);
    clearPlaintextAfterDecryption(decryptedMeta);

    console.log(`✓ File decrypted: ${filename} (${totalChunks} chunks)`);

    return {
      blob,
      filename,
      mimetype,
      size
    };
  } catch (error) {
    // Log decryption errors for security monitoring
    console.error(`Failed to decrypt file: ${error.message}`, error);
    
    // Preserve original error information for tests and debugging
    // If error has originalError (from createUserFriendlyError), preserve it
    const originalError = error.originalError || error;
    const isOperationError = error.name === 'OperationError' || originalError.name === 'OperationError';
    
    let errorMessage = `Failed to decrypt file: ${error.message}`;
    
    // Include OperationError in message if present (for test compatibility)
    if (isOperationError) {
      errorMessage += ' Error: OperationError';
    }
    
    const wrappedError = new Error(errorMessage);
    
    // Preserve error name (e.g., OperationError) - prioritize OperationError
    if (isOperationError) {
      wrappedError.name = 'OperationError';
    } else if (error.name) {
      wrappedError.name = error.name;
    }
    
    // Preserve original error if available
    wrappedError.originalError = originalError;
    
    // Preserve technical message if available
    if (error.technicalMessage) {
      wrappedError.technicalMessage = error.technicalMessage;
    }
    
    // Preserve error type if available
    if (error.errorType) {
      wrappedError.errorType = error.errorType;
    }
    
    // Preserve stack trace
    if (error.stack) {
      wrappedError.stack = error.stack;
    }
    
    throw wrappedError;
  }
}

