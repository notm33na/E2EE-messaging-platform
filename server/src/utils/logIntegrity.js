/**
 * Log File Integrity Protection
 * 
 * Provides cryptographic integrity protection for log files using HMAC-SHA256.
 * Prevents log tampering and provides non-repudiation.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Get HMAC key from environment or generate (should be set in production)
const HMAC_KEY = process.env.LOG_HMAC_KEY || 'default-log-integrity-key-change-in-production';
const LOG_ENCRYPTION_KEY = process.env.LOG_ENCRYPTION_KEY || null; // Optional encryption key for sensitive fields

/**
 * Computes HMAC-SHA256 for log entry
 * @param {string} logEntry - Log entry JSON string
 * @returns {string} Base64-encoded HMAC
 */
function computeHMAC(logEntry) {
  const hmac = crypto.createHmac('sha256', HMAC_KEY);
  hmac.update(logEntry);
  return hmac.digest('base64');
}

/**
 * Encrypts sensitive fields in log event
 * @param {Object} event - Event data
 * @returns {Object} Event with sensitive fields encrypted
 */
function encryptSensitiveFields(event) {
  if (!LOG_ENCRYPTION_KEY) {
    return event; // No encryption key configured
  }

  const sensitiveFields = ['userId', 'sessionId', 'email', 'ip', 'ipAddress'];
  const encrypted = { ...event };

  for (const field of sensitiveFields) {
    if (encrypted[field]) {
      try {
        const keyBuffer = Buffer.from(LOG_ENCRYPTION_KEY, 'hex').slice(0, 32);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
        let encryptedValue = cipher.update(String(encrypted[field]), 'utf8', 'hex');
        encryptedValue += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        encrypted[field] = `ENC:${iv.toString('hex')}:${encryptedValue}:${authTag.toString('hex')}`;
      } catch (error) {
        // If encryption fails, leave field as-is (don't break logging)
        console.warn(`Failed to encrypt log field ${field}:`, error);
      }
    }
  }

  return encrypted;
}

/**
 * Writes log entry with integrity protection and optional encryption
 * @param {string} filename - Log filename
 * @param {Object} event - Event data
 */
export function writeProtectedLog(filename, event) {
  // Encrypt sensitive fields if encryption key is configured
  const processedEvent = encryptSensitiveFields(event);
  
  const logEntry = JSON.stringify({
    timestamp: new Date().toISOString(),
    ...processedEvent
  });

  // Compute HMAC
  const hmac = computeHMAC(logEntry);

  // Append HMAC to log entry
  const protectedEntry = `${logEntry}|HMAC:${hmac}\n`;

  // Resolve log path
  const prefix = process.env.LOG_PREFIX || '';
  const effectiveName = prefix ? `${prefix}_${filename}` : filename;
  const logsDir = process.env.TEST_LOGS_DIR || path.join(__dirname, '../../logs');
  const logPath = path.join(logsDir, effectiveName);

  // Ensure directory exists
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  // Write protected log entry
  fs.appendFileSync(logPath, protectedEntry, 'utf8');
  
  // Set restrictive file permissions (Unix-like systems)
  try {
    fs.chmodSync(logPath, 0o600); // Read/write for owner only
  } catch (error) {
    // Silently fail on Windows or if chmod not supported
    // File permissions are best-effort
  }
}

/**
 * Verifies log entry integrity
 * @param {string} logLine - Log line with HMAC
 * @returns {{valid: boolean, entry?: Object, error?: string}}
 */
export function verifyLogEntry(logLine) {
  try {
    const parts = logLine.trim().split('|HMAC:');
    if (parts.length !== 2) {
      return { valid: false, error: 'Invalid log format' };
    }

    const [entryJson, hmac] = parts;
    const expectedHMAC = computeHMAC(entryJson);

    if (hmac !== expectedHMAC) {
      return { valid: false, error: 'HMAC verification failed - log entry may be tampered' };
    }

    const entry = JSON.parse(entryJson);
    return { valid: true, entry };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

