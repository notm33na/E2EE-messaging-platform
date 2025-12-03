/**
 * Test logging utility
 * Use this to create test logs for debugging
 */

import { logSecurityEvent, logReplayAttempt, logMITMAttack, logMITMDemonstration } from './clientLogger.js';

/**
 * Creates test logs for debugging
 */
export async function createTestLogs(userId = 'test-user') {
  const sessionId = 'test-session-' + Date.now();
  
  console.log('[TestLogging] Creating test logs...');
  
  try {
    // Create a replay attempt log
    await logReplayAttempt(sessionId, 5, Date.now(), 'Duplicate nonce detected', userId);
    console.log('[TestLogging] Created replay attempt log');
    
    // Create a MITM attack log
    await logMITMAttack(
      sessionId,
      'unsigned_dh',
      'MITM attack successful on unsigned DH',
      { attackSuccessful: true },
      userId
    );
    console.log('[TestLogging] Created MITM attack log');
    
    // Create a MITM demonstration log
    await logMITMDemonstration(
      sessionId + '-demo',
      'signed_dh',
      false,
      'MITM attack blocked by signature verification',
      { packetCount: 10 },
      userId
    );
    console.log('[TestLogging] Created MITM demonstration log');
    
    // Create an invalid signature log
    await logSecurityEvent('invalid_signature', {
      userId,
      sessionId,
      reason: 'Signature verification failed',
      messageType: 'KEP_INIT'
    });
    console.log('[TestLogging] Created invalid signature log');
    
    // Create a decryption error log
    await logSecurityEvent('decryption_error', {
      userId,
      sessionId,
      seq: 10,
      reason: 'Decryption failed: Invalid auth tag'
    });
    console.log('[TestLogging] Created decryption error log');
    
    console.log('[TestLogging] All test logs created successfully');
    return true;
  } catch (error) {
    console.error('[TestLogging] Failed to create test logs:', error);
    return false;
  }
}

// Make it available globally for console testing
if (typeof window !== 'undefined') {
  window.createTestLogs = createTestLogs;
  console.log('[TestLogging] Test function available: window.createTestLogs(userId)');
}

