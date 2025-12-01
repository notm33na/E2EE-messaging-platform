import { PublicKey } from '../models/PublicKey.js';
import { userService } from '../services/user.service.js';
import crypto from 'crypto';
import { logEvent } from '../utils/attackLogging.js';

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

    // Check if public key already exists and verify integrity
    const existingKey = await PublicKey.findOne({ userId: req.user.id });
    if (existingKey) {
      // Verify key hasn't been tampered with by checking hash
      const keyString = JSON.stringify(existingKey.publicIdentityKeyJWK, Object.keys(existingKey.publicIdentityKeyJWK).sort());
      const currentHash = crypto.createHash('sha256').update(keyString).digest('hex');
      
      if (currentHash !== existingKey.keyHash) {
        // Key has been tampered with - log security event
        logEvent('PUBLIC_KEY_TAMPER_DETECTED', existingKey.userId.toString(), 'Public key integrity check failed', {
          userId: existingKey.userId.toString(),
          expectedHash: existingKey.keyHash,
          actualHash: currentHash
        });
        
        return res.status(409).json({
          success: false,
          error: 'Public key integrity violation detected',
          message: 'Existing public key has been modified. Please contact support.'
        });
      }
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

    // Verify key integrity before returning
    const keyString = JSON.stringify(publicKey.publicIdentityKeyJWK, Object.keys(publicKey.publicIdentityKeyJWK).sort());
    const currentHash = crypto.createHash('sha256').update(keyString).digest('hex');
    
    if (currentHash !== publicKey.keyHash) {
      // Key has been tampered with
      logEvent('PUBLIC_KEY_TAMPER_DETECTED', userId, 'Public key integrity check failed on retrieval', {
        userId: userId,
        expectedHash: publicKey.keyHash,
        actualHash: currentHash
      });
      
      return res.status(500).json({
        success: false,
        error: 'Public key integrity violation',
        message: 'Public key verification failed. Please contact support.'
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

