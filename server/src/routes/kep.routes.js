import express from 'express';
import { sendKEPMessage, getPendingMessages } from '../controllers/kep.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Send KEP message (requires auth)
router.post(
  '/send',
  verifyTokenMiddleware,
  requireAuth,
  sendKEPMessage
);

// Get pending messages (requires auth)
router.get(
  '/pending/:userId',
  verifyTokenMiddleware,
  requireAuth,
  getPendingMessages
);

export default router;

