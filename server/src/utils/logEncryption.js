/**
 * Log File Encryption Utility
 * Provides encryption for sensitive log entries to prevent information disclosure
 */

import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Encryption key for logs (should be stored securely in production)
const LOG_ENCRYPTION_KEY = process.env.LOG_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ALGORITHM = 'aes-256-gcm';

/**
 * Encrypts a log entry
 * @param {Object} logEntry - Log entry to encrypt
 * @returns {Promise<string>} Encrypted log entry (base64)
 */
export async function encryptLogEntry(logEntry) {
  try {
    const key = crypto.scryptSync(LOG_ENCRYPTION_KEY, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    const jsonEntry = JSON.stringify(logEntry);
    let encrypted = cipher.update(jsonEntry, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();

    // Return encrypted entry with IV and auth tag
    return JSON.stringify({
      encrypted: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    });
  } catch (error) {
    console.error('Failed to encrypt log entry:', error);
    // Fallback to plaintext if encryption fails (should not happen in production)
    return JSON.stringify(logEntry);
  }
}

/**
 * Decrypts a log entry
 * @param {string} encryptedEntry - Encrypted log entry
 * @returns {Promise<Object>} Decrypted log entry
 */
export async function decryptLogEntry(encryptedEntry) {
  try {
    const entry = JSON.parse(encryptedEntry);
    if (!entry.encrypted || !entry.iv || !entry.authTag) {
      // Not encrypted, return as-is
      return typeof entry === 'string' ? JSON.parse(entry) : entry;
    }

    const key = crypto.scryptSync(LOG_ENCRYPTION_KEY, 'salt', 32);
    const iv = Buffer.from(entry.iv, 'base64');
    const authTag = Buffer.from(entry.authTag, 'base64');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(entry.encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Failed to decrypt log entry:', error);
    throw new Error('Failed to decrypt log entry');
  }
}

/**
 * Writes an encrypted log entry to file
 * @param {string} filename - Log filename
 * @param {Object} logEntry - Log entry to write
 */
export async function writeEncryptedLog(filename, logEntry) {
  try {
    const logsDir = path.join(__dirname, '../../logs');
    await fs.mkdir(logsDir, { recursive: true });
    
    const logPath = path.join(logsDir, filename);
    const encryptedEntry = await encryptLogEntry(logEntry);
    
    await fs.appendFile(logPath, encryptedEntry + '\n', 'utf8');
  } catch (error) {
    console.error('Failed to write encrypted log:', error);
    throw error;
  }
}

/**
 * Sets file permissions to restrict access (Unix-like systems)
 * @param {string} filepath - Path to log file
 */
export async function restrictLogFileAccess(filepath) {
  try {
    // On Windows, this will be a no-op, but on Unix systems it restricts access
    await fs.chmod(filepath, 0o600); // Read/write for owner only
  } catch (error) {
    // Silently fail on Windows or if chmod not supported
    console.warn('Could not set log file permissions:', error.message);
  }
}

