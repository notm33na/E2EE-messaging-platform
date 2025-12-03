import { MessageMeta, verifyMetadataHash } from '../models/MessageMeta.js';
import { logMessageMetadataAccess, logMessageForwarding, logFileChunkForwarding } from '../utils/messageLogging.js';
import { validateTimestamp, generateMessageId, hashNonceBase64, isNonceHashUsed } from '../utils/replayProtection.js';
import { logReplayAttempt } from '../utils/replayProtection.js';
import { requireSenderAuthorization } from '../middlewares/authorization.middleware.js';

/**
 * Relay message (REST fallback)
 * POST /api/messages/relay
 */
export async function relayMessage(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    const envelope = req.body;

    // Validate required fields
    if (!envelope.type || !envelope.sessionId || !envelope.receiver || !envelope.timestamp || !envelope.seq) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields in envelope'
      });
    }

    // Validate timestamp
    if (!validateTimestamp(envelope.timestamp)) {
      logReplayAttempt(envelope.sessionId, envelope.seq, envelope.timestamp, 'Timestamp out of validity window');
      return res.status(400).json({
        success: false,
        error: 'Timestamp out of validity window'
      });
    }

    // Validate and hash nonce (must exist, correct length)
    let nonceHash;
    try {
      nonceHash = hashNonceBase64(envelope.nonce);
    } catch (err) {
      const reason = err.message || 'Invalid nonce';
      logReplayAttempt(envelope.sessionId, envelope.seq, envelope.timestamp, reason);
      return res.status(400).json({
        success: false,
        error: reason
      });
    }

    // Check if nonce hash has already been used in this session (replay protection)
    const nonceAlreadyUsed = await isNonceHashUsed(envelope.sessionId, nonceHash, MessageMeta);
    if (nonceAlreadyUsed) {
      const reason = 'REPLAY_REJECT: Duplicate nonce detected in session';
      logReplayAttempt(envelope.sessionId, envelope.seq, envelope.timestamp, reason);
      return res.status(400).json({
        success: false,
        error: 'Message rejected: duplicate nonce detected (replay attempt)'
      });
    }

    // Generate message ID using the message's timestamp
    const messageId = generateMessageId(envelope.sessionId, envelope.seq, envelope.timestamp);

    // Store metadata
    const messageMeta = new MessageMeta({
      messageId,
      sessionId: envelope.sessionId,
      sender: req.user.id,
      receiver: envelope.receiver,
      type: envelope.type,
      timestamp: envelope.timestamp,
      seq: envelope.seq,
      nonceHash,
      meta: envelope.meta || {},
      delivered: false
    });

    await messageMeta.save();

    // Log metadata access
    logMessageMetadataAccess(req.user.id, envelope.sessionId, 'store', {
      messageId,
      type: envelope.type
    });

    // Forward to recipient via WebSocket if online
    const io = req.app.get('io');
    if (io) {
      const sockets = await io.fetchSockets();
      const recipientSocket = sockets.find(s => s.data.user?.id === envelope.receiver);

      if (recipientSocket) {
        if (envelope.type === 'FILE_CHUNK') {
          recipientSocket.emit('msg:receive', envelope);
          logFileChunkForwarding(req.user.id, envelope.receiver, envelope.sessionId, envelope.meta?.chunkIndex);
        } else {
          recipientSocket.emit('msg:receive', envelope);
          logMessageForwarding(req.user.id, envelope.receiver, envelope.sessionId, envelope.type);
        }

        messageMeta.delivered = true;
        messageMeta.deliveredAt = new Date();
        await messageMeta.save();
      }
    }

    res.json({
      success: true,
      message: 'Message relayed',
      data: {
        messageId,
        sessionId: envelope.sessionId,
        delivered: messageMeta.delivered
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate message (replay attempt) - can be duplicate messageId or duplicate nonceHash
      const reason = 'REPLAY_REJECT: Duplicate nonce detected';
      logReplayAttempt(req.body.sessionId, req.body.seq, req.body.timestamp, reason);
      return res.status(400).json({
        success: false,
        error: reason
      });
    }
    next(error);
  }
}

/**
 * Get pending messages
 * GET /api/messages/pending/:userId
 */
export async function getPendingMessages(req, res, next) {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'User ID is required'
      });
    }

    // Only allow users to fetch their own pending messages
    // Compare as strings to handle ObjectId vs string mismatches
    if (req.user && String(req.user.id) !== String(userId)) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'Cannot access messages for another user'
      });
    }

    const pendingMessages = await MessageMeta.find({
      receiver: userId,
      delivered: false
    })
      .sort({ createdAt: 1 })
      .limit(100);

    // Verify integrity hash for each message
    for (const message of pendingMessages) {
      if (!verifyMetadataHash(message)) {
        // Metadata tampering detected - log security event
        const { logEvent } = await import('../utils/attackLogging.js');
        logEvent('METADATA_TAMPER_DETECTED', userId, 'Metadata integrity check failed', {
          messageId: message.messageId,
          sessionId: message.sessionId
        });
        // Remove tampered message from results
        const index = pendingMessages.indexOf(message);
        if (index > -1) {
          pendingMessages.splice(index, 1);
        }
      }
    }

    // Log metadata access
    logMessageMetadataAccess(userId, 'all', 'fetch_pending', {
      count: pendingMessages.length
    });

    // Apply metadata minimization
    const { minimizeMessageMeta } = await import('../utils/metadataMinimization.js');
    
    res.json({
      success: true,
      data: {
        messages: pendingMessages.map(msg => minimizeMessageMeta(msg))
      }
    });
  } catch (error) {
    next(error);
  }
}

