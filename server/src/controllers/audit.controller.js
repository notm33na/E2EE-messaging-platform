/**
 * Audit Trail Controller
 * Provides API access to metadata audit logs for non-repudiation
 */

import { MetadataAudit } from '../models/MetadataAudit.js';
import { requireOwnResource } from '../middlewares/authorization.middleware.js';

/**
 * Get audit trail for a specific message
 * GET /api/audit/message/:messageId
 */
export async function getMessageAuditTrail(req, res, next) {
  try {
    const { messageId } = req.params;

    if (!messageId) {
      return res.status(400).json({
        success: false,
        error: 'Message ID is required'
      });
    }

    // Only allow users to view audit trails for their own messages
    // This requires checking if the message belongs to the user
    const { MessageMeta } = await import('../models/MessageMeta.js');
    const message = await MessageMeta.findOne({ messageId }).select('+sender +receiver');
    
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found'
      });
    }

    // Check if user is sender or receiver
    const userId = req.user?.id?.toString();
    const isSender = message.sender?.toString() === userId;
    const isReceiver = message.receiver?.toString() === userId;

    if (!isSender && !isReceiver) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: You can only view audit trails for your own messages'
      });
    }

    // Get audit trail
    const auditTrail = await MetadataAudit.find({ messageId })
      .sort({ timestamp: -1 })
      .limit(100)
      .populate('changedBy', 'email')
      .lean();

    res.json({
      success: true,
      data: {
        messageId,
        auditTrail: auditTrail.map(entry => ({
          action: entry.action,
          changedBy: entry.changedBy ? entry.changedBy.email : 'System',
          timestamp: entry.timestamp,
          ipAddress: entry.ipAddress,
          userAgent: entry.userAgent,
          // Only include value changes if user is authorized
          oldValues: isSender || isReceiver ? entry.oldValues : undefined,
          newValues: isSender || isReceiver ? entry.newValues : undefined
        }))
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get audit trail for a session
 * GET /api/audit/session/:sessionId
 */
export async function getSessionAuditTrail(req, res, next) {
  try {
    const { sessionId } = req.params;

    if (!sessionId) {
      return res.status(400).json({
        success: false,
        error: 'Session ID is required'
      });
    }

    // Get audit trail for session
    const auditTrail = await MetadataAudit.find({ sessionId })
      .sort({ timestamp: -1 })
      .limit(200)
      .populate('changedBy', 'email')
      .lean();

    res.json({
      success: true,
      data: {
        sessionId,
        auditTrail: auditTrail.map(entry => ({
          messageId: entry.messageId,
          action: entry.action,
          changedBy: entry.changedBy ? entry.changedBy.email : 'System',
          timestamp: entry.timestamp
        }))
      }
    });
  } catch (error) {
    next(error);
  }
}

