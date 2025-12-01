import jwt from 'jsonwebtoken';
import { loadKeys } from '../config/keys.js';

let privateKey = null;
let publicKey = null;

// Load keys once at module initialization
try {
  const keys = loadKeys();
  privateKey = keys.privateKey;
  publicKey = keys.publicKey;
} catch (error) {
  console.warn('JWT keys not loaded. Generate keys with: npm run generate-keys');
}

/**
 * Signs a JWT token using ECC ES256 algorithm
 * @param {Object} payload - Token payload (should contain userId, email, etc.)
 * @param {string|number} expiresIn - Expiration time (e.g., '15m', '1h', 3600)
 * @returns {string} Signed JWT token
 */
export function signToken(payload, expiresIn = '15m') {
  if (!privateKey) {
    throw new Error('Private key not available. Cannot sign tokens.');
  }

  return jwt.sign(payload, privateKey, {
    algorithm: 'ES256', // ECC P-256 curve
    expiresIn
  });
}

/**
 * Verifies a JWT token using ECC ES256 algorithm
 * @param {string} token - JWT token to verify
 * @returns {Object} Decoded token payload
 * @throws {Error} If token is invalid, expired, or tampered
 */
export function verifyToken(token) {
  if (!publicKey) {
    throw new Error('Public key not available. Cannot verify tokens.');
  }

  try {
    return jwt.verify(token, publicKey, {
      algorithms: ['ES256'] // Only accept ES256, reject HS256
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token has expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else if (error.name === 'NotBeforeError') {
      throw new Error('Token not active yet');
    }
    throw error;
  }
}

/**
 * Generates access token (short-lived) with binding to IP/user-agent
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @param {string} ipAddress - Client IP address (for token binding)
 * @param {string} userAgent - Client user agent (for token binding)
 * @returns {string} Access token
 */
export function generateAccessToken(userId, email, ipAddress = null, userAgent = null) {
  // Create binding hash from IP and user-agent to prevent token theft/replay
  let bindingHash = null;
  if (ipAddress || userAgent) {
    const crypto = require('crypto');
    const bindingString = `${ipAddress || ''}|${userAgent || ''}`;
    bindingHash = crypto.createHash('sha256').update(bindingString).digest('hex').substring(0, 16); // 16 chars for efficiency
  }

  // Minimize payload - only include essential fields
  return signToken(
    {
      userId, // Only include userId, not email (can be looked up from userId)
      type: 'access',
      binding: bindingHash // Token binding to prevent cross-device replay
    },
    process.env.ACCESS_TOKEN_EXPIRY || '5m' // Reduced from 15m to 5m for better security
  );
}

/**
 * Generates refresh token (long-lived)
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @returns {string} Refresh token
 */
export function generateRefreshToken(userId, email) {
  // Minimize payload - only include essential fields
  return signToken(
    {
      userId, // Only include userId, not email
      type: 'refresh'
    },
    process.env.REFRESH_TOKEN_EXPIRY || '7d'
  );
}

/**
 * Decodes token without verification (for inspection)
 * @param {string} token - JWT token
 * @returns {Object} Decoded payload (not verified)
 */
export function decodeToken(token) {
  return jwt.decode(token);
}

