/**
 * MongoDB Atlas Connection Test Script
 * Tests connection to MongoDB Atlas and populates sample development data
 */

import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt';

// Load environment variables from .env
dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'infosec';

// Validate required environment variables
if (!MONGODB_URI) {
  console.error('❌ Error: MONGODB_URI is not set in .env file');
  process.exit(1);
}

let client = null;

/**
 * Connect to MongoDB Atlas
 */
async function connectToMongoDB() {
  try {
    console.log('Connecting to MongoDB Atlas...');
    client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
    });
    
    await client.connect();
    console.log('✔ Connection successful');
    return client.db(DB_NAME);
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    if (error.name === 'MongoServerSelectionError') {
      console.error('   Details: Could not connect to MongoDB Atlas');
      console.error('   Check your connection string and network access');
    }
    process.exit(1);
  }
}

/**
 * Create collections if they don't exist
 */
async function createCollections(db) {
  try {
    const collections = [
      'users',
      'identityKeys',
      'messages_meta',
      'files_meta',
      'replay_logs',
      'signature_logs',
      'auth_logs'
    ];

    for (const collectionName of collections) {
      const collectionsList = await db.listCollections({ name: collectionName }).toArray();
      if (collectionsList.length === 0) {
        await db.createCollection(collectionName);
        console.log(`   Created collection: ${collectionName}`);
      }
    }
    console.log('✔ Collections created');
  } catch (error) {
    console.error('❌ Error creating collections:', error.message);
    throw error;
  }
}

/**
 * Insert sample data into collections
 */
async function insertSampleData(db) {
  try {
    // Generate bcrypt password hashes
    const saltRounds = 10;
    const alicePasswordHash = await bcrypt.hash('alicePassword123!', saltRounds);
    const bobPasswordHash = await bcrypt.hash('bobPassword123!', saltRounds);

    // Insert users
    const usersCollection = db.collection('users');
    await usersCollection.insertMany([
      {
        userId: 'U001',
        username: 'alice',
        passwordHash: alicePasswordHash,
        createdAt: new Date(),
        lastLogin: new Date()
      },
      {
        userId: 'U002',
        username: 'bob',
        passwordHash: bobPasswordHash,
        createdAt: new Date(),
        lastLogin: new Date()
      }
    ]);
    console.log('   Inserted sample users');

    // Insert identity keys (PUBLIC KEYS ONLY - no private keys)
    const identityKeysCollection = db.collection('identityKeys');
    await identityKeysCollection.insertMany([
      {
        userId: 'U001',
        identityPublicKey: {
          kty: 'EC',
          crv: 'P-256',
          x: 'dGVzdFhWYWx1ZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA',
          y: 'dGVzdFlWYWx1ZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA'
        },
        createdAt: new Date()
      },
      {
        userId: 'U002',
        identityPublicKey: {
          kty: 'EC',
          crv: 'P-256',
          x: 'dGVzdFhWYWx1ZTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA',
          y: 'dGVzdFlWYWx1ZTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA'
        },
        createdAt: new Date()
      }
    ]);
    console.log('   Inserted sample identity keys (public keys only)');

    // Insert message metadata (NO CIPHERTEXT - server must not store it)
    const messagesMetaCollection = db.collection('messages_meta');
    await messagesMetaCollection.insertMany([
      {
        sessionId: 'S001',
        sender: 'U001',
        receiver: 'U002',
        timestamp: new Date(),
        seq: 1,
        type: 'MSG',
        delivered: false
      },
      {
        sessionId: 'S001',
        sender: 'U001',
        receiver: 'U002',
        timestamp: new Date(Date.now() - 60000), // 1 minute ago
        seq: 2,
        type: 'MSG',
        delivered: true
      },
      {
        sessionId: 'S001',
        sender: 'U002',
        receiver: 'U001',
        timestamp: new Date(Date.now() - 30000), // 30 seconds ago
        seq: 3,
        type: 'MSG',
        delivered: false
      }
    ]);
    console.log('   Inserted sample message metadata (no ciphertext)');

    // Insert file metadata (METADATA ONLY - no file content)
    const filesMetaCollection = db.collection('files_meta');
    await filesMetaCollection.insertMany([
      {
        fileId: 'F001',
        sessionId: 'S001',
        sender: 'U001',
        receiver: 'U002',
        filename: 'lab-report.pdf',
        size: 284312,
        totalChunks: 4,
        uploadedAt: new Date()
      }
    ]);
    console.log('   Inserted sample file metadata');

    // Insert replay log
    const replayLogsCollection = db.collection('replay_logs');
    await replayLogsCollection.insertOne({
      sessionId: 'S001',
      userId: 'U002',
      attemptTime: new Date(),
      reason: 'Duplicate sequence number',
      originalSeq: 3
    });
    console.log('   Inserted sample replay log');

    // Insert signature log
    const signatureLogsCollection = db.collection('signature_logs');
    await signatureLogsCollection.insertOne({
      sessionId: 'S001',
      userId: 'U002',
      attemptTime: new Date(),
      reason: 'Invalid ECDSA signature',
      publicKeyUsed: 'dGVzdFhWYWx1ZTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA'
    });
    console.log('   Inserted sample signature log');

    // Insert auth log
    const authLogsCollection = db.collection('auth_logs');
    await authLogsCollection.insertOne({
      userId: 'U001',
      timestamp: new Date(),
      event: 'LoginSuccess',
      ip: '127.0.0.1'
    });
    console.log('   Inserted sample auth log');

    console.log('✔ Sample data inserted');
  } catch (error) {
    console.error('❌ Error inserting sample data:', error.message);
    throw error;
  }
}

/**
 * Main execution
 */
async function main() {
  try {
    const db = await connectToMongoDB();
    await createCollections(db);
    await insertSampleData(db);
    
    console.log('\n✅ All operations completed successfully!');
    console.log(`✅ Database: ${DB_NAME}`);
    console.log('✅ Collections ready');
    console.log('✅ Sample data populated');
  } catch (error) {
    console.error('\n❌ Script failed:', error.message);
    process.exit(1);
  } finally {
    if (client) {
      await client.close();
      console.log('\n✔ Connection closed');
    }
  }
}

// Run the script
main();

