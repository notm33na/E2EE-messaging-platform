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
 * Generates access token (short-lived)
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @returns {string} Access token
 */
export function generateAccessToken(userId, email) {
  return signToken(
    {
      userId,
      email,
      type: 'access'
    },
    process.env.ACCESS_TOKEN_EXPIRY || '15m'
  );
}

/**
 * Generates refresh token (long-lived)
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @returns {string} Refresh token
 */
export function generateRefreshToken(userId, email) {
  return signToken(
    {
      userId,
      email,
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

