import express from 'express';
import rateLimit from 'express-rate-limit';
import { relayMessage, getPendingMessages } from '../controllers/messages.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';
import { requireSenderAuthorization, requireOwnResource } from '../middlewares/authorization.middleware.js';

const router = express.Router();

// Rate limiting for message endpoints
const messageLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 messages per minute per IP
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many messages. Please slow down.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for authenticated users in production (can be adjusted)
    return false; // Apply to all requests
  }
});

const pendingMessagesLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many pending message requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Relay message (requires auth and sender authorization)
router.post(
  '/relay',
  messageLimiter,
  verifyTokenMiddleware,
  requireAuth,
  requireSenderAuthorization,
  relayMessage
);

// Get pending messages (requires auth and own resource access)
router.get(
  '/pending/:userId',
  pendingMessagesLimiter,
  verifyTokenMiddleware,
  requireAuth,
  requireOwnResource,
  getPendingMessages
);

export default router;

