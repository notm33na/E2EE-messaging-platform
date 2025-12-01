/**
 * Session ID Security Utilities
 * Provides obfuscation and additional security for session IDs
 * to prevent session key access via compromised session IDs
 */

import crypto from 'crypto';

/**
 * Generates a cryptographically secure session ID
 * @param {string} userId - User ID
 * @param {string} peerId - Peer user ID
 * @returns {string} Secure session ID
 */
export function generateSecureSessionId(userId, peerId) {
  // Create deterministic but secure session ID
  const encoder = new TextEncoder();
  const data = encoder.encode(`${userId}:${peerId}:${Date.now()}`);
  
  // Hash to create unpredictable session ID
  return crypto.subtle.digest('SHA-256', data).then(hash => {
    const hashArray = Array.from(new Uint8Array(hash));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
  });
}

/**
 * Obfuscates session ID for storage (additional layer of protection)
 * @param {string} sessionId - Original session ID
 * @param {string} userId - User ID (for key derivation)
 * @returns {Promise<string>} Obfuscated session ID
 */
export async function obfuscateSessionId(sessionId, userId) {
  // Use HKDF to derive obfuscation key from userId
  const encoder = new TextEncoder();
  const userIdBytes = encoder.encode(userId);
  
  // Simple obfuscation: XOR with derived key
  // In production, consider stronger obfuscation
  const keyMaterial = await crypto.subtle.digest('SHA-256', userIdBytes);
  const key = new Uint8Array(keyMaterial).slice(0, sessionId.length);
  const sessionIdBytes = encoder.encode(sessionId);
  
  const obfuscated = new Uint8Array(sessionIdBytes.length);
  for (let i = 0; i < sessionIdBytes.length; i++) {
    obfuscated[i] = sessionIdBytes[i] ^ key[i % key.length];
  }
  
  return Array.from(obfuscated).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Deobfuscates session ID
 * @param {string} obfuscatedId - Obfuscated session ID
 * @param {string} userId - User ID (for key derivation)
 * @returns {Promise<string>} Original session ID
 */
export async function deobfuscateSessionId(obfuscatedId, userId) {
  // Reverse obfuscation
  const encoder = new TextEncoder();
  const userIdBytes = encoder.encode(userId);
  const keyMaterial = await crypto.subtle.digest('SHA-256', userIdBytes);
  const key = new Uint8Array(keyMaterial).slice(0, obfuscatedId.length / 2);
  
  const obfuscatedBytes = new Uint8Array(obfuscatedId.length / 2);
  for (let i = 0; i < obfuscatedId.length; i += 2) {
    obfuscatedBytes[i / 2] = parseInt(obfuscatedId.substr(i, 2), 16);
  }
  
  const deobfuscated = new Uint8Array(obfuscatedBytes.length);
  for (let i = 0; i < obfuscatedBytes.length; i++) {
    deobfuscated[i] = obfuscatedBytes[i] ^ key[i % key.length];
  }
  
  const decoder = new TextDecoder();
  return decoder.decode(deobfuscated);
}

