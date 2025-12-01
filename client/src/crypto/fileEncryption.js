/**
 * File Encryption
 * 
 * Handles encryption of files in chunks for efficient transmission.
 * Files are split into 256 KB chunks, each encrypted independently.
 */

import { encryptAESGCM, generateIV } from './aesGcm.js';
import { buildFileMetaEnvelope, buildFileChunkEnvelope } from './messageEnvelope.js';
import { getSendKey } from './sessionManager.js';

const CHUNK_SIZE = 256 * 1024; // 256 KB
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB maximum file size

/**
 * Encrypts a file and returns metadata and chunk envelopes
 * @param {File} file - File to encrypt
 * @param {string} sessionId - Session identifier
 * @param {string} sender - Sender user ID
 * @param {string} receiver - Receiver user ID
 * @returns {Promise<{fileMetaEnvelope: Object, chunkEnvelopes: Array<Object>}>}
 */
export async function encryptFile(file, sessionId, sender, receiver, userId = null) {
  try {
    // 1. Read file as ArrayBuffer
    const fileBuffer = await file.arrayBuffer();
    const fileSize = fileBuffer.byteLength;

    // 2. Validate file size
    if (fileSize > MAX_FILE_SIZE) {
      throw new Error(`File size (${(fileSize / 1024 / 1024).toFixed(2)} MB) exceeds maximum allowed size (${MAX_FILE_SIZE / 1024 / 1024} MB)`);
    }

    // 3. Calculate number of chunks
    const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);

    // 4. Get send key (with userId for encrypted key access)
    // If userId not provided, will try to get from session
    const sendKey = await getSendKey(sessionId, userId || sender);

    // 4. Encrypt file metadata
    const metadata = {
      filename: file.name,
      size: fileSize,
      totalChunks: totalChunks,
      mimetype: file.type || 'application/octet-stream'
    };

    const metadataJson = JSON.stringify(metadata);
    const encoder = new TextEncoder();
    const metadataBuffer = encoder.encode(metadataJson);

    const { ciphertext: metaCiphertext, iv: metaIV, authTag: metaAuthTag } = 
      await encryptAESGCM(sendKey, metadataBuffer);

    const fileMetaEnvelope = buildFileMetaEnvelope(
      sessionId,
      sender,
      receiver,
      metaCiphertext,
      metaIV,
      metaAuthTag,
      metadata
    );

    // 5. Encrypt file chunks
    const chunkEnvelopes = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileSize);
      const chunk = fileBuffer.slice(start, end);

      // Encrypt chunk
      const { ciphertext, iv, authTag } = await encryptAESGCM(sendKey, chunk);

      // Build chunk envelope
      const chunkEnvelope = buildFileChunkEnvelope(
        sessionId,
        sender,
        receiver,
        ciphertext,
        iv,
        authTag,
        {
          chunkIndex: i,
          totalChunks: totalChunks
        }
      );

      chunkEnvelopes.push(chunkEnvelope);
    }

    console.log(`✓ File encrypted: ${file.name} (${totalChunks} chunks)`);

    return {
      fileMetaEnvelope,
      chunkEnvelopes
    };
  } catch (error) {
    throw new Error(`Failed to encrypt file: ${error.message}`);
  }
}

/**
 * Gets the chunk size used for file encryption
 * @returns {number} Chunk size in bytes
 */
export function getChunkSize() {
  return CHUNK_SIZE;
}

