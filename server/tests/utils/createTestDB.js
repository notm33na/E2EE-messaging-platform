/**
 * Per-suite isolated MongoDB test database helper.
 *
 * Each Jest run/suite gets a unique database name to avoid
 * cross-suite contamination and global connection reuse.
 */

import mongoose from 'mongoose';
import { User } from '../../src/models/User.js';
import { PublicKey } from '../../src/models/PublicKey.js';
import { KEPMessage } from '../../src/models/KEPMessage.js';
import { MessageMeta } from '../../src/models/MessageMeta.js';
import { MetadataAudit } from '../../src/models/MetadataAudit.js';

let currentDbName = null;
let isConnected = false;

/**
 * Generates a unique database name for the current process/run.
 */
function generateDbName() {
  const rand = Math.random().toString(36).substring(2, 9);
  return `test_${process.pid}_${Date.now()}_${rand}`;
}

/**
 * Returns the current test database name (if any).
 */
export function getTestDBName() {
  return currentDbName;
}

/**
 * Connect to an isolated test database.
 * Never connect at import time; this is only invoked from test hooks.
 */
export async function setupTestDB() {
  if (isConnected && currentDbName) {
    return;
  }

  const baseUri =
    process.env.TEST_MONGO_URI || 'mongodb://localhost:27017';

  currentDbName = generateDbName();

  const uriWithDb =
    baseUri.includes('/')
      ? `${baseUri.replace(/\/$/, '')}/${currentDbName}`
      : `${baseUri}/${currentDbName}`;

  await mongoose.connect(uriWithDb, {
    serverSelectionTimeoutMS: 5000,
    dbName: currentDbName,
  });

  isConnected = true;
  // eslint-disable-next-line no-console
  console.log(`✓ Connected to isolated test database: ${currentDbName}`);
}

/**
 * Wipes all documents from known collections but keeps
 * the database/schema itself intact for the suite.
 */
export async function cleanTestDB() {
  if (!isConnected) {
    return;
  }

  const wipePromises = [
    User.deleteMany({}),
    PublicKey.deleteMany({}),
    KEPMessage.deleteMany({}),
    MessageMeta.deleteMany({}),
    MetadataAudit.deleteMany({}),
  ];

  await Promise.all(wipePromises);
  // eslint-disable-next-line no-console
  console.log('✓ Test database collections cleaned');
}

/**
 * Drops the isolated test database and disconnects.
 */
export async function closeTestDB() {
  if (!isConnected) {
    return;
  }

  try {
    if (mongoose.connection.db) {
      await mongoose.connection.db.dropDatabase();
    }
  } finally {
    await mongoose.disconnect();
    isConnected = false;
    // eslint-disable-next-line no-console
    console.log('✓ Isolated test database dropped and connection closed');
  }
}


