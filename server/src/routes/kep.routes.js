import express from 'express';
import rateLimit from 'express-rate-limit';
import { sendKEPMessage, getPendingMessages } from '../controllers/kep.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';
import { requireOwnResource } from '../middlewares/authorization.middleware.js';

const router = express.Router();

// Rate limiting for KEP endpoints (key exchange is expensive)
const kepLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 key exchanges per 5 minutes per IP
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many key exchange attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const kepPendingLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many pending KEP message requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Send KEP message (requires auth)
router.post(
  '/send',
  kepLimiter,
  verifyTokenMiddleware,
  requireAuth,
  sendKEPMessage
);

// Get pending messages (requires auth and own resource access)
router.get(
  '/pending/:userId',
  kepPendingLimiter,
  verifyTokenMiddleware,
  requireAuth,
  requireOwnResource,
  getPendingMessages
);

export default router;

