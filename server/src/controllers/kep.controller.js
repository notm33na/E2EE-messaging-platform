import { KEPMessage } from '../models/KEPMessage.js';
import { logInvalidKEPMessage, logReplayAttempt, validateTimestamp, generateMessageId } from '../utils/replayProtection.js';

/**
 * Send KEP message
 * POST /api/kep/send
 * 
 * Server acts as relay - stores message metadata and forwards via WebSocket
 */
export async function sendKEPMessage(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    const { to, type, sessionId, timestamp, seq, message } = req.body;

    // Validate required fields
    if (!to || !type || !sessionId || !timestamp || !seq || !message) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    // Validate message type
    if (!['KEP_INIT', 'KEP_RESPONSE'].includes(type)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message type'
      });
    }

    // Validate timestamp freshness
    if (!validateTimestamp(timestamp)) {
      logReplayAttempt(sessionId, seq, timestamp, 'Timestamp out of validity window');
      return res.status(400).json({
        success: false,
        error: 'Timestamp out of validity window'
      });
    }

    // Generate message ID
    const messageId = generateMessageId(sessionId, seq);

    // Store message metadata
    const kepMessage = new KEPMessage({
      messageId,
      sessionId,
      from: req.user.id,
      to,
      type,
      timestamp,
      seq,
      delivered: false
    });

    await kepMessage.save();

    // Forward to recipient via WebSocket if online
    const io = req.app.get('io');
    if (io) {
      // Find socket for recipient user
      const sockets = await io.fetchSockets();
      const recipientSocket = sockets.find(s => s.data.user?.id === to);

      if (recipientSocket) {
        recipientSocket.emit('kep:message', {
          messageId,
          type,
          sessionId,
          from: req.user.id,
          message,
          timestamp,
          seq
        });

        // Mark as delivered
        kepMessage.delivered = true;
        kepMessage.deliveredAt = new Date();
        await kepMessage.save();
      }
    }

    res.json({
      success: true,
      message: 'KEP message sent',
      data: {
        messageId,
        sessionId,
        delivered: kepMessage.delivered
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key (replay attempt)
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
 * Get pending KEP messages
 * GET /api/kep/pending/:userId
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

    const pendingMessages = await KEPMessage.find({
      to: userId,
      delivered: false
    })
      .sort({ createdAt: 1 })
      .limit(100);

    res.json({
      success: true,
      data: {
        messages: pendingMessages.map(msg => ({
          messageId: msg.messageId,
          sessionId: msg.sessionId,
          from: msg.from,
          type: msg.type,
          timestamp: msg.timestamp,
          seq: msg.seq,
          createdAt: msg.createdAt
        }))
      }
    });
  } catch (error) {
    next(error);
  }
}

