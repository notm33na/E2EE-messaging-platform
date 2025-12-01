/**
 * Identity Key Rotation Utilities
 * 
 * Provides functions for rotating identity keys to enhance security
 * and recover from potential key compromise.
 */

import { generateIdentityKeyPair, storePrivateKeyEncrypted, exportPublicKey } from './identityKeys.js';

/**
 * Rotates identity key pair for a user
 * Generates new key pair and stores encrypted private key
 * @param {string} userId - User ID
 * @param {string} password - User password
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey, publicKeyJWK: Object}>}
 */
export async function rotateIdentityKeys(userId, password) {
  try {
    // Generate new identity key pair
    const { privateKey, publicKey } = await generateIdentityKeyPair();
    
    // Store new private key encrypted
    await storePrivateKeyEncrypted(userId, privateKey, password);
    
    // Export public key for upload
    const publicKeyJWK = await exportPublicKey(publicKey);
    
    console.log(`✓ Identity keys rotated for user: ${userId}`);
    
    return {
      privateKey,
      publicKey,
      publicKeyJWK
    };
  } catch (error) {
    throw new Error(`Failed to rotate identity keys: ${error.message}`);
  }
}

/**
 * Checks if identity key rotation is recommended
 * Based on key age or security events
 * @param {Date} keyCreatedAt - When the key was created
 * @param {number} maxAgeDays - Maximum key age in days (default: 90)
 * @returns {boolean} True if rotation is recommended
 */
export function shouldRotateIdentityKey(keyCreatedAt, maxAgeDays = 90) {
  if (!keyCreatedAt) {
    return false;
  }
  
  const ageMs = Date.now() - new Date(keyCreatedAt).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  
  return ageDays > maxAgeDays;
}
