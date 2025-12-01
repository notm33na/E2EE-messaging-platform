/**
 * Database Cleanup Utilities
 * 
 * Provides automated cleanup of old metadata to prevent database growth
 * and resource exhaustion attacks.
 */

import { MessageMeta } from '../models/MessageMeta.js';
import { KEPMessage } from '../models/KEPMessage.js';

/**
 * Cleans up old message metadata
 * Removes metadata older than specified days (default: 90 days)
 * @param {number} daysOld - Age in days (default: 90)
 * @returns {Promise<{deleted: number}>}
 */
export async function cleanupOldMessageMetadata(daysOld = 90) {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    const result = await MessageMeta.deleteMany({
      createdAt: { $lt: cutoffDate },
      delivered: true // Only delete delivered messages
    });

    console.log(`✓ Cleaned up ${result.deletedCount} old message metadata entries`);
    return { deleted: result.deletedCount };
  } catch (error) {
    console.error('Failed to cleanup old message metadata:', error);
    throw error;
  }
}

/**
 * Cleans up old KEP message metadata
 * Removes KEP messages older than specified days (default: 30 days)
 * @param {number} daysOld - Age in days (default: 30)
 * @returns {Promise<{deleted: number}>}
 */
export async function cleanupOldKEPMessages(daysOld = 30) {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    const result = await KEPMessage.deleteMany({
      createdAt: { $lt: cutoffDate },
      delivered: true // Only delete delivered KEP messages
    });

    console.log(`✓ Cleaned up ${result.deletedCount} old KEP message metadata entries`);
    return { deleted: result.deletedCount };
  } catch (error) {
    console.error('Failed to cleanup old KEP messages:', error);
    throw error;
  }
}

/**
 * Monitors database size and triggers cleanup if needed
 * @param {number} maxMessages - Maximum number of messages before aggressive cleanup (default: 1000000)
 * @returns {Promise<{count: number, needsCleanup: boolean}>}
 */
export async function monitorDatabaseSize(maxMessages = 1000000) {
  try {
    const messageCount = await MessageMeta.countDocuments();
    const kepCount = await KEPMessage.countDocuments();
    const totalCount = messageCount + kepCount;

    return {
      messageCount,
      kepCount,
      totalCount,
      needsCleanup: totalCount > maxMessages
    };
  } catch (error) {
    console.error('Failed to monitor database size:', error);
    throw error;
  }
}

/**
 * Runs periodic cleanup (call from cron job or scheduled task)
 * @param {number} messageMetadataDays - Days to keep message metadata (default: 90)
 * @param {number} kepMessageDays - Days to keep KEP messages (default: 30)
 * @returns {Promise<{messages: number, kep: number}>}
 */
export async function runPeriodicCleanup(messageMetadataDays = 90, kepMessageDays = 30) {
  try {
    // Check database size first
    const sizeCheck = await monitorDatabaseSize();
    if (sizeCheck.needsCleanup) {
      console.warn(`⚠️  Database size exceeded threshold (${sizeCheck.totalCount} records). Running aggressive cleanup.`);
      // Use more aggressive cleanup (reduce retention period by 50%)
      messageMetadataDays = Math.floor(messageMetadataDays * 0.5);
      kepMessageDays = Math.floor(kepMessageDays * 0.5);
    }

    const [messagesResult, kepResult] = await Promise.all([
      cleanupOldMessageMetadata(messageMetadataDays),
      cleanupOldKEPMessages(kepMessageDays)
    ]);

    return {
      messages: messagesResult.deleted,
      kep: kepResult.deleted,
      sizeCheck
    };
  } catch (error) {
    console.error('Periodic cleanup failed:', error);
    throw error;
  }
}

