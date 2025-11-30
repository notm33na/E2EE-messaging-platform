/**
 * Test Setup and Utilities
 * Provides test database connection and helper functions
 */

import mongoose from 'mongoose';
import { connectDatabase, closeDatabase } from '../src/config/database.js';
import { User } from '../src/models/User.js';
import { PublicKey } from '../src/models/PublicKey.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { MessageMeta } from '../src/models/MessageMeta.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test database URI (use test database)
const TEST_DB_URI = process.env.TEST_MONGO_URI || 'mongodb://localhost:27017/infosec_test';

/**
 * Connect to test database
 */
export async function setupTestDB() {
  try {
    await mongoose.connect(TEST_DB_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log('✓ Connected to test database');
  } catch (error) {
    console.error('Failed to connect to test database:', error.message);
    throw error;
  }
}

/**
 * Clean test database
 */
export async function cleanTestDB() {
  try {
    // Delete all documents
    await User.deleteMany({});
    await PublicKey.deleteMany({});
    await KEPMessage.deleteMany({});
    await MessageMeta.deleteMany({});
    
    // Drop indexes to prevent duplicate key errors from stale indexes
    // Note: We don't drop all indexes, just ensure collections are clean
    // Mongoose will recreate indexes on next connection if needed
    
    console.log('✓ Test database cleaned');
  } catch (error) {
    console.error('Failed to clean test database:', error);
    throw error;
  }
}

/**
 * Close test database connection
 */
export async function closeTestDB() {
  try {
    await mongoose.connection.close();
    console.log('✓ Test database connection closed');
  } catch (error) {
    console.error('Error closing test database:', error);
  }
}

/**
 * Clear test log files
 */
export function clearTestLogs() {
  const logsDir = path.join(__dirname, '../../logs');
  const logFiles = [
    'replay_attempts.log',
    'invalid_signature.log',
    'invalid_kep_message.log',
    'message_metadata_access.log',
    'msg_forwarding.log',
    'file_chunk_forwarding.log',
    'replay_detected.log',
    'key_exchange_attempts.log',
    'authentication_attempts.log',
    'failed_decryption.log'
  ];

  logFiles.forEach(file => {
    const logPath = path.join(logsDir, file);
    if (fs.existsSync(logPath)) {
      fs.writeFileSync(logPath, '', 'utf8');
    }
  });
}

/**
 * Read log file content
 */
export function readLogFile(filename) {
  const logsDir = path.join(__dirname, '../../logs');
  // Ensure logs directory exists
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }
  const logPath = path.join(logsDir, filename);
  if (fs.existsSync(logPath)) {
    return fs.readFileSync(logPath, 'utf8');
  }
  return '';
}

/**
 * Generate test JWK (public key)
 */
export function generateTestJWK() {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: 'testXValue123456789012345678901234567890123456789012345678901234',
    y: 'testYValue123456789012345678901234567890123456789012345678901234'
  };
}

/**
 * Generate test user data
 */
export function generateTestUser() {
  // Use Date.now() + Math.random() to ensure uniqueness even in parallel tests
  const uniqueId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  return {
    email: `test${uniqueId}@example.com`,
    password: 'TestPassword123!'
  };
}

/**
 * Sleep utility for async tests
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

