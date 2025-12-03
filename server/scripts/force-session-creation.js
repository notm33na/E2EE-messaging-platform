/**
 * Force Session Creation Script
 * 
 * Generates session IDs for all user pairs and provides instructions
 * for establishing sessions between all users.
 * 
 * Note: Sessions require client-side key exchange (KEP protocol),
 * so this script only generates session IDs. Users must run the
 * client-side batch session establishment tool to actually create sessions.
 * 
 * Usage: node server/scripts/force-session-creation.js
 */

import crypto from 'crypto';
import mongoose from 'mongoose';
import { connectDatabase, closeDatabase } from '../src/config/database.js';
import { User } from '../src/models/User.js';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config({ path: join(__dirname, '../../.env') });

/**
 * Generates a deterministic session ID for a user pair
 * Uses a fixed timestamp to ensure same session ID for same pair
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {string} Session ID (32 hex characters)
 */
function generateDeterministicSessionId(userId1, userId2) {
  // Sort user IDs to ensure same session ID regardless of order
  const sortedIds = [userId1, userId2].sort();
  const sessionData = `${sortedIds[0]}:${sortedIds[1]}:session`;
  
  // Hash to create session ID
  const hash = crypto.createHash('sha256').update(sessionData).digest('hex');
  return hash.substring(0, 32);
}

/**
 * Main function to generate session IDs for all user pairs
 */
async function generateSessionsForAllUsers() {
  try {
    console.log('🔐 Force Session Creation Script\n');
    
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

    if (users.length < 2) {
      console.log('Need at least 2 users to create sessions. Exiting.');
      await closeDatabase();
      return;
    }

    // Generate session IDs for all pairs
    const sessions = [];
    let sessionCount = 0;

    for (let i = 0; i < users.length; i++) {
      for (let j = i + 1; j < users.length; j++) {
        const user1 = users[i];
        const user2 = users[j];
        
        const sessionId = generateDeterministicSessionId(
          user1._id.toString(),
          user2._id.toString()
        );
        
        sessions.push({
          sessionId,
          user1: {
            id: user1._id.toString(),
            email: user1.email
          },
          user2: {
            id: user2._id.toString(),
            email: user2.email
          }
        });
        
        sessionCount++;
      }
    }

    console.log(`📊 Generated ${sessionCount} session IDs for ${users.length} users\n`);
    console.log('Session Pairs:\n');
    
    sessions.forEach((session, index) => {
      console.log(`${index + 1}. Session: ${session.sessionId}`);
      console.log(`   ${session.user1.email} ↔ ${session.user2.email}\n`);
    });

    // Save to JSON file for client-side use
    const fs = await import('fs');
    const sessionsFile = join(__dirname, '../../sessions-to-establish.json');
    fs.writeFileSync(
      sessionsFile,
      JSON.stringify(sessions, null, 2),
      'utf-8'
    );
    
    console.log(`✓ Session data saved to: ${sessionsFile}\n`);
    console.log('⚠️  IMPORTANT:');
    console.log('  - Session IDs have been generated');
    console.log('  - Sessions must be established client-side using the KEP protocol');
    console.log('  - Use the BatchSessionEstablishment component in the client');
    console.log('  - Each user must be logged in and have their identity keys generated');
    console.log('  - Sessions will be created in IndexedDB on each client\n');

    await closeDatabase();
    console.log('✓ Script completed successfully');
  } catch (error) {
    console.error('✗ Script failed:', error);
    await closeDatabase();
    process.exit(1);
  }
}

// Run the script
generateSessionsForAllUsers();

