/**
 * File Decryption
 * 
 * Handles decryption and reconstruction of encrypted files.
 */

import { decryptAESGCM } from './aesGcm.js';
import { base64ToArrayBuffer } from './signatures.js';
import { getRecvKey } from './sessionManager.js';

/**
 * Decrypts file metadata and chunks, reconstructs original file
 * @param {Object} metaEnvelope - FILE_META envelope
 * @param {Array<Object>} chunkEnvelopes - Array of FILE_CHUNK envelopes
 * @param {string} sessionId - Session identifier
 * @returns {Promise<{blob: Blob, filename: string, mimetype: string}>}
 */
export async function decryptFile(metaEnvelope, chunkEnvelopes, sessionId, userId = null) {
  try {
    // 1. Get receive key (with userId for encrypted key access)
    // Load session first to get userId if not provided
    const { loadSession } = await import('./sessionManager.js');
    if (!userId) {
      const session = await loadSession(sessionId, null);
      if (session) {
        userId = session.userId;
      }
    }
    const recvKey = await getRecvKey(sessionId, userId);

    // 2. Decrypt metadata
    const metaCiphertext = base64ToArrayBuffer(metaEnvelope.ciphertext);
    const metaIV = base64ToArrayBuffer(metaEnvelope.iv);
    const metaAuthTag = base64ToArrayBuffer(metaEnvelope.authTag);

    const decryptedMeta = await decryptAESGCM(recvKey, metaIV, metaCiphertext, metaAuthTag);
    const decoder = new TextDecoder();
    const metadataJson = decoder.decode(decryptedMeta);
    const metadata = JSON.parse(metadataJson);

    const { filename, size, totalChunks, mimetype } = metadata;

    // 3. Sort chunks by index
    const sortedChunks = chunkEnvelopes
      .slice()
      .sort((a, b) => a.meta.chunkIndex - b.meta.chunkIndex);

    // 4. Verify we have all chunks
    if (sortedChunks.length !== totalChunks) {
      throw new Error(`Missing chunks: expected ${totalChunks}, got ${sortedChunks.length}`);
    }

    // 5. Decrypt all chunks
    const decryptedChunks = [];

    for (let i = 0; i < sortedChunks.length; i++) {
      const chunkEnvelope = sortedChunks[i];

      // Verify chunk index matches
      if (chunkEnvelope.meta.chunkIndex !== i) {
        throw new Error(`Chunk index mismatch: expected ${i}, got ${chunkEnvelope.meta.chunkIndex}`);
      }

      // Decrypt chunk
      const chunkCiphertext = base64ToArrayBuffer(chunkEnvelope.ciphertext);
      const chunkIV = base64ToArrayBuffer(chunkEnvelope.iv);
      const chunkAuthTag = base64ToArrayBuffer(chunkEnvelope.authTag);

      const decryptedChunk = await decryptAESGCM(recvKey, chunkIV, chunkCiphertext, chunkAuthTag);
      decryptedChunks.push(decryptedChunk);
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
    const { clearPlaintextAfterDecryption } = await import('../utils/memorySecurity.js');
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
    throw new Error(`Failed to decrypt file: ${error.message}`);
  }
}

