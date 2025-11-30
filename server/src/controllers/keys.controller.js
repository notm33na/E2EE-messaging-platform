import { PublicKey } from '../models/PublicKey.js';
import { userService } from '../services/user.service.js';

/**
 * Upload public identity key
 * POST /api/keys/upload
 */
export async function uploadPublicKey(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    const { publicIdentityKeyJWK } = req.body;

    if (!publicIdentityKeyJWK) {
      return res.status(400).json({
        success: false,
        error: 'Public key (JWK) is required'
      });
    }

    // Validate JWK structure
    if (!publicIdentityKeyJWK.kty || !publicIdentityKeyJWK.crv || !publicIdentityKeyJWK.x || !publicIdentityKeyJWK.y) {
      return res.status(400).json({
        success: false,
        error: 'Invalid JWK format'
      });
    }

    // Verify it's a P-256 key
    if (publicIdentityKeyJWK.crv !== 'P-256' || publicIdentityKeyJWK.kty !== 'EC') {
      return res.status(400).json({
        success: false,
        error: 'Only ECC P-256 keys are supported'
      });
    }

    // Upsert public key
    const publicKey = await PublicKey.findOneAndUpdate(
      { userId: req.user.id },
      {
        publicIdentityKeyJWK,
        updatedAt: new Date()
      },
      {
        upsert: true,
        new: true
      }
    );

    res.json({
      success: true,
      message: 'Public key uploaded successfully',
      data: {
        userId: publicKey.userId,
        createdAt: publicKey.createdAt,
        updatedAt: publicKey.updatedAt
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get public key by user ID
 * GET /api/keys/:userId
 */
export async function getPublicKey(req, res, next) {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'User ID is required'
      });
    }

    const publicKey = await PublicKey.findOne({ userId });

    if (!publicKey) {
      return res.status(404).json({
        success: false,
        error: 'Public key not found for this user'
      });
    }

    res.json({
      success: true,
      data: {
        userId: publicKey.userId,
        publicIdentityKeyJWK: publicKey.publicIdentityKeyJWK,
        createdAt: publicKey.createdAt,
        updatedAt: publicKey.updatedAt
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get current user's public key
 * GET /api/keys/me
 */
export async function getMyPublicKey(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    const publicKey = await PublicKey.findOne({ userId: req.user.id });

    if (!publicKey) {
      return res.status(404).json({
        success: false,
        error: 'Public key not found. Please upload your public key first.'
      });
    }

    res.json({
      success: true,
      data: {
        userId: publicKey.userId,
        publicIdentityKeyJWK: publicKey.publicIdentityKeyJWK,
        createdAt: publicKey.createdAt,
        updatedAt: publicKey.updatedAt
      }
    });
  } catch (error) {
    next(error);
  }
}

