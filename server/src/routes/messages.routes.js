import express from 'express';
import { relayMessage, getPendingMessages } from '../controllers/messages.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Relay message (requires auth)
router.post(
  '/relay',
  verifyTokenMiddleware,
  requireAuth,
  relayMessage
);

// Get pending messages (requires auth)
router.get(
  '/pending/:userId',
  verifyTokenMiddleware,
  requireAuth,
  getPendingMessages
);

export default router;

