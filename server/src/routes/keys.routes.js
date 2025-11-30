import express from 'express';
import { uploadPublicKey, getPublicKey, getMyPublicKey } from '../controllers/keys.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Upload public key (requires auth)
router.post(
  '/upload',
  verifyTokenMiddleware,
  requireAuth,
  uploadPublicKey
);

// Get current user's public key (requires auth)
router.get(
  '/me',
  verifyTokenMiddleware,
  requireAuth,
  getMyPublicKey
);

// Get public key by user ID (public endpoint)
router.get('/:userId', getPublicKey);

export default router;

