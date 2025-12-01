/**
 * Metadata Minimization Utilities
 * 
 * Provides functions to minimize metadata exposure while maintaining
 * necessary functionality for message routing and delivery.
 */

/**
 * Sanitizes message metadata for external exposure
 * Removes sensitive fields and minimizes information leakage
 * @param {Object} metadata - Full message metadata
 * @param {string} requestingUserId - ID of user requesting the metadata
 * @returns {Object} Sanitized metadata
 */
export function sanitizeMessageMetadata(metadata, requestingUserId) {
  if (!metadata) {
    return null;
  }

  const sanitized = {
    messageId: metadata.messageId,
    sessionId: metadata.sessionId,
    type: metadata.type,
    timestamp: metadata.timestamp,
    seq: metadata.seq,
    delivered: metadata.delivered
  };

  // Only include sender/receiver if user is part of the conversation
  const senderId = metadata.sender?.toString() || metadata.sender;
  const receiverId = metadata.receiver?.toString() || metadata.receiver;
  const userId = requestingUserId?.toString() || requestingUserId;

  if (senderId === userId || receiverId === userId) {
    // User is part of conversation - include limited sender/receiver info
    sanitized.sender = senderId === userId ? 'you' : senderId;
    sanitized.receiver = receiverId === userId ? 'you' : receiverId;
  } else {
    // User is not part of conversation - exclude sender/receiver
    // This prevents metadata enumeration attacks
  }

  // Only include file metadata if user is part of conversation
  if (senderId === userId || receiverId === userId) {
    if (metadata.meta) {
      sanitized.meta = {
        filename: metadata.meta.filename ? '[FILENAME]' : undefined, // Obfuscate filename
        size: metadata.meta.size,
        totalChunks: metadata.meta.totalChunks,
        chunkIndex: metadata.meta.chunkIndex,
        mimetype: metadata.meta.mimetype ? '[MIMETYPE]' : undefined // Obfuscate mimetype
      };
    }
  }

  return sanitized;
}

/**
 * Minimizes message metadata for API responses
 * Only includes essential fields, excludes sensitive information
 * @param {Object} messageMeta - MessageMeta document
 * @returns {Object} Minimized metadata
 */
export function minimizeMessageMeta(messageMeta) {
  if (!messageMeta) return null;
  
  const minimized = {
    messageId: messageMeta.messageId,
    sessionId: messageMeta.sessionId,
    type: messageMeta.type,
    timestamp: messageMeta.timestamp,
    seq: messageMeta.seq,
    delivered: messageMeta.delivered,
    deliveredAt: messageMeta.deliveredAt
  };
  
  // Only include specific meta fields for FILE_META and FILE_CHUNK
  if (messageMeta.type === 'FILE_META' && messageMeta.meta) {
    minimized.meta = {
      filename: messageMeta.meta.filename,
      size: messageMeta.meta.size,
      totalChunks: messageMeta.meta.totalChunks,
      mimetype: messageMeta.meta.mimetype
    };
  } else if (messageMeta.type === 'FILE_CHUNK' && messageMeta.meta) {
    minimized.meta = {
      chunkIndex: messageMeta.meta.chunkIndex,
      totalChunks: messageMeta.meta.totalChunks
    };
  }
  
  return minimized;
}

/**
 * Checks if metadata query should be rate limited
 * Prevents metadata enumeration attacks
 * @param {string} userId - User ID making the query
 * @param {Map} queryCounts - Map tracking query counts per user
 * @param {number} maxQueries - Maximum queries per window (default: 100)
 * @returns {boolean} True if query should be allowed
 */
export function checkMetadataQueryRateLimit(userId, queryCounts, maxQueries = 100) {
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute window

  const userQueries = queryCounts.get(userId) || { count: 0, resetAt: now + windowMs };

  if (now > userQueries.resetAt) {
    userQueries.count = 0;
    userQueries.resetAt = now + windowMs;
  }

  if (userQueries.count >= maxQueries) {
    return false; // Rate limit exceeded
  }

  userQueries.count++;
  queryCounts.set(userId, userQueries);
  return true; // Query allowed
}

