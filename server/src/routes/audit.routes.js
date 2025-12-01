import express from 'express';
import rateLimit from 'express-rate-limit';
import { getMessageAuditTrail, getSessionAuditTrail } from '../controllers/audit.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Rate limiting for audit endpoints
const auditLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20, // 20 requests per minute
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many audit trail requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Get audit trail for a message
router.get(
  '/message/:messageId',
  auditLimiter,
  verifyTokenMiddleware,
  requireAuth,
  getMessageAuditTrail
);

// Get audit trail for a session
router.get(
  '/session/:sessionId',
  auditLimiter,
  verifyTokenMiddleware,
  requireAuth,
  getSessionAuditTrail
);

export default router;

