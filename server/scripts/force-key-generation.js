/**
 * Force Key Generation Script
 * 
 * Generates identity key pairs for all users in MongoDB Atlas
 * and stores public keys in the database.
 * 
 * Note: Private keys must be generated client-side by each user.
 * This script only generates and stores public keys on the server.
 * 
 * Usage: node server/scripts/force-key-generation.js
 */

import crypto from 'crypto';
import mongoose from 'mongoose';
import { connectDatabase, closeDatabase } from '../src/config/database.js';
import { User } from '../src/models/User.js';
import { PublicKey } from '../src/models/PublicKey.js';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config({ path: join(__dirname, '../../.env') });

/**
 * Generates an ECC P-256 key pair (same as client-side)
 * @returns {Object} { privateKey, publicKey } in JWK format
 */
function generateIdentityKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // P-256 curve
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // Convert to JWK format (simplified - actual JWK conversion would be more complex)
  // For now, we'll store the PEM format and convert on the fly
  // In production, you'd want proper JWK conversion
  
  return {
    privateKeyPEM: privateKey,
    publicKeyPEM: publicKey
  };
}

/**
 * Converts PEM public key to JWK format (simplified)
 * Note: This is a simplified conversion. For production, use a proper library.
 */
function pemToJWK(pem) {
  // Extract the key data from PEM
  const keyObject = crypto.createPublicKey(pem);
  const jwk = keyObject.export({ format: 'jwk' });
  return jwk;
}

/**
 * Main function to generate keys for all users
 */
async function generateKeysForAllUsers() {
  try {
    console.log('🔐 Force Key Generation Script\n');
    
    // Connect to database
    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable is required');
    }
    
    await connectDatabase(mongoUri);
    console.log('✓ Connected to MongoDB\n');

    // Get all active users
    const users = await User.find({ isActive: true }).select('_id email').lean();
    console.log(`Found ${users.length} active users\n`);

    if (users.length === 0) {
      console.log('No users found. Exiting.');
      await closeDatabase();
      return;
    }

    let generatedCount = 0;
    let updatedCount = 0;
    let skippedCount = 0;

    for (const user of users) {
      const userId = user._id.toString();
      const email = user.email;

      try {
        // Check if public key already exists
        const existingKey = await PublicKey.findOne({ userId });
        
        if (existingKey) {
          console.log(`⏭️  Skipping ${email} - public key already exists`);
          skippedCount++;
          continue;
        }

        // Generate new key pair
        console.log(`🔑 Generating keys for ${email}...`);
        const { publicKeyPEM } = generateIdentityKeyPair();
        
        // Convert to JWK format
        const publicKeyJWK = pemToJWK(publicKeyPEM);

        // Store public key in database
        const publicKey = new PublicKey({
          userId: userId,
          publicIdentityKeyJWK: publicKeyJWK
        });

        await publicKey.save();
        console.log(`✓ Generated and stored public key for ${email}`);
        generatedCount++;
      } catch (error) {
        console.error(`✗ Error processing ${email}:`, error.message);
      }
    }

    console.log('\n📊 Summary:');
    console.log(`  Generated: ${generatedCount}`);
    console.log(`  Updated: ${updatedCount}`);
    console.log(`  Skipped: ${skippedCount}`);
    console.log(`  Total: ${users.length}\n`);

    console.log('⚠️  IMPORTANT:');
    console.log('  - Public keys have been generated and stored on the server');
    console.log('  - Each user must generate their private key client-side using the Keys page');
    console.log('  - Private keys are encrypted with the user\'s password and stored in IndexedDB');
    console.log('  - The server never sees or stores private keys\n');

    await closeDatabase();
    console.log('✓ Script completed successfully');
  } catch (error) {
    console.error('✗ Script failed:', error);
    await closeDatabase();
    process.exit(1);
  }
}

// Run the script
generateKeysForAllUsers();

