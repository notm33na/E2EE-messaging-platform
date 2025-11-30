import { MessageMeta } from '../models/MessageMeta.js';
import { logMessageMetadataAccess, logMessageForwarding, logFileChunkForwarding } from '../utils/messageLogging.js';
import { validateTimestamp, generateMessageId } from '../utils/replayProtection.js';
import { logReplayAttempt } from '../utils/replayProtection.js';

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

    // Generate message ID
    const messageId = generateMessageId(envelope.sessionId, envelope.seq);

    // Store metadata
    const messageMeta = new MessageMeta({
      messageId,
      sessionId: envelope.sessionId,
      sender: req.user.id,
      receiver: envelope.receiver,
      type: envelope.type,
      timestamp: envelope.timestamp,
      seq: envelope.seq,
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
      // Duplicate message (replay attempt)
      logReplayAttempt(req.body.sessionId, req.body.seq, req.body.timestamp, 'Duplicate message ID');
      return res.status(400).json({
        success: false,
        error: 'Duplicate message detected (replay attempt)'
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
    if (req.user && req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden'
      });
    }

    const pendingMessages = await MessageMeta.find({
      receiver: userId,
      delivered: false
    })
      .sort({ createdAt: 1 })
      .limit(100);

    // Log metadata access
    logMessageMetadataAccess(userId, 'all', 'fetch_pending', {
      count: pendingMessages.length
    });

    res.json({
      success: true,
      data: {
        messages: pendingMessages.map(msg => ({
          messageId: msg.messageId,
          sessionId: msg.sessionId,
          sender: msg.sender,
          type: msg.type,
          timestamp: msg.timestamp,
          seq: msg.seq,
          meta: msg.meta,
          createdAt: msg.createdAt
        }))
      }
    });
  } catch (error) {
    next(error);
  }
}

