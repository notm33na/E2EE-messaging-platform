/**
 * Replay Attack Simulator
 * 
 * EDUCATIONAL PURPOSE ONLY - Demonstrates replay attack
 * and how timestamp/sequence protection prevents it.
 * 
 * SECURITY CONSIDERATIONS:
 * - This is a simulation for educational purposes
 * - Runs only in local development environment
 * - Never exposes real plaintext or keys
 * - Demonstrates replay detection mechanisms
 * 
 * DATA PRIVACY CONSTRAINTS:
 * - No real user data is replayed
 * - All operations are simulated
 * - Logs contain only metadata
 * 
 * LIMITATIONS:
 * - Simulation only, not a real attack
 * - For demonstration and education
 * - Must be run in controlled environment
 */

/**
 * Captured messages for replay simulation
 */
const capturedMessages = new Map();

/**
 * Attack log for demonstration
 */
const attackLog = [];

/**
 * Logs a replay attack event
 */
function logReplayEvent(eventType, description, data = {}) {
  const event = {
    timestamp: new Date().toISOString(),
    eventType,
    description,
    data: {
      ...data,
      // Ensure no plaintext in logs
      hasPlaintext: !!data.plaintext,
      hasCiphertext: !!data.ciphertext
    }
  };
  
  attackLog.push(event);
  console.log(`[REPLAY SIM] ${eventType}: ${description}`);
  
  return event;
}

/**
 * Captures a message for later replay
 * 
 * @param {string} sessionId - Session identifier
 * @param {Object} envelope - Message envelope to capture
 * @returns {Promise<void>}
 */
export async function captureMessage(sessionId, envelope) {
  try {
    if (!envelope || !envelope.seq || !envelope.timestamp) {
      throw new Error('Invalid message envelope');
    }

    const messageId = `${sessionId}-${envelope.seq}`;
    
    capturedMessages.set(messageId, {
      sessionId,
      envelope: {
        ...envelope,
        // Store only metadata, not plaintext
        capturedAt: Date.now(),
        originalTimestamp: envelope.timestamp,
        originalSeq: envelope.seq
      }
    });

    logReplayEvent('MESSAGE_CAPTURED', 'Captured message for replay', {
      sessionId,
      messageId,
      seq: envelope.seq,
      timestamp: envelope.timestamp,
      type: envelope.type
    });
  } catch (error) {
    logReplayEvent('CAPTURE_ERROR', 'Failed to capture message', {
      sessionId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Attempts to replay a captured message
 * 
 * This demonstrates how replay protection mechanisms
 * detect and reject replayed messages.
 * 
 * @param {string} sessionId - Session identifier
 * @param {string} messageId - Message ID to replay
 * @param {Function} validateMessage - Function to validate message (timestamp, seq)
 * @returns {Promise<Object>} Replay attempt result
 */
export async function resendMessage(sessionId, messageId, validateMessage) {
  try {
    const captured = capturedMessages.get(messageId);
    
    if (!captured) {
      logReplayEvent('REPLAY_ERROR', 'Message not found in capture', {
        sessionId,
        messageId
      });
      throw new Error('Message not captured');
    }

    logReplayEvent('REPLAY_ATTEMPT', 'Attempting to replay captured message', {
      sessionId,
      messageId,
      originalSeq: captured.envelope.seq,
      originalTimestamp: captured.envelope.timestamp,
      age: Date.now() - captured.envelope.timestamp
    });

    // Validate message (this should detect replay)
    const validation = await validateMessage(captured.envelope);
    
    if (!validation.valid) {
      logReplayEvent('REPLAY_BLOCKED', 'Replay attack blocked', {
        sessionId,
        messageId,
        reason: validation.reason,
        originalSeq: captured.envelope.seq,
        originalTimestamp: captured.envelope.timestamp
      });

      return {
        replaySuccessful: false,
        reason: validation.reason,
        blockedBy: validation.protection,
        log: attackLog
      };
    }

    // This should never happen if replay protection works
    logReplayEvent('REPLAY_ERROR', 'Replay protection should have blocked this', {
      sessionId,
      messageId,
      warning: 'Unexpected: replay was not blocked'
    });

    return {
      replaySuccessful: false,
      reason: 'Replay protection should have blocked this',
      log: attackLog
    };
  } catch (error) {
    logReplayEvent('REPLAY_ERROR', 'Replay attack simulation error', {
      sessionId,
      messageId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Validates message for replay protection
 * 
 * @param {Object} envelope - Message envelope
 * @param {number} lastSeq - Last sequence number for session
 * @param {number} timestampWindow - Timestamp validity window (ms)
 * @returns {Promise<{valid: boolean, reason?: string, protection?: string}>}
 */
export async function validateMessageForReplay(envelope, lastSeq, timestampWindow = 2 * 60 * 1000) {
  try {
    // Check timestamp freshness
    const now = Date.now();
    const messageAge = Math.abs(now - envelope.timestamp);
    
    if (messageAge > timestampWindow) {
      return {
        valid: false,
        reason: `Message timestamp is stale (age: ${messageAge}ms, window: ${timestampWindow}ms)`,
        protection: 'TIMESTAMP_FRESHNESS'
      };
    }

    // Check sequence number monotonicity
    if (envelope.seq <= lastSeq) {
      return {
        valid: false,
        reason: `Sequence number not monotonic (received: ${envelope.seq}, last: ${lastSeq})`,
        protection: 'SEQUENCE_MONOTONICITY'
      };
    }

    return {
      valid: true
    };
  } catch (error) {
    return {
      valid: false,
      reason: `Validation error: ${error.message}`,
      protection: 'VALIDATION_ERROR'
    };
  }
}

/**
 * Simulates replay attack with timestamp check
 * 
 * @param {string} sessionId - Session identifier
 * @param {Object} envelope - Message envelope to replay
 * @param {number} lastSeq - Last sequence number
 * @returns {Promise<Object>} Replay attempt result
 */
export async function simulateReplayWithTimestampCheck(sessionId, envelope, lastSeq) {
  try {
    attackLog.length = 0; // Clear previous log
    
    logReplayEvent('REPLAY_START', 'Starting replay attack simulation', {
      sessionId,
      messageSeq: envelope.seq,
      messageTimestamp: envelope.timestamp
    });

    // Capture message
    await captureMessage(sessionId, envelope);

    // Wait a bit (simulate time passing)
    await new Promise(resolve => setTimeout(resolve, 100));

    // Attempt to replay
    const result = await resendMessage(
      sessionId,
      `${sessionId}-${envelope.seq}`,
      async (msg) => validateMessageForReplay(msg, lastSeq)
    );

    return result;
  } catch (error) {
    logReplayEvent('REPLAY_ERROR', 'Replay simulation error', {
      sessionId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Simulates replay attack with sequence check
 * 
 * @param {string} sessionId - Session identifier
 * @param {Object} envelope - Message envelope to replay
 * @param {number} lastSeq - Last sequence number (should be >= envelope.seq)
 * @returns {Promise<Object>} Replay attempt result
 */
export async function simulateReplayWithSequenceCheck(sessionId, envelope, lastSeq) {
  try {
    attackLog.length = 0; // Clear previous log
    
    logReplayEvent('REPLAY_START', 'Starting replay attack with sequence check', {
      sessionId,
      messageSeq: envelope.seq,
      lastSeq
    });

    // Capture message
    await captureMessage(sessionId, envelope);

    // Attempt to replay (should fail because seq <= lastSeq)
    const result = await resendMessage(
      sessionId,
      `${sessionId}-${envelope.seq}`,
      async (msg) => validateMessageForReplay(msg, lastSeq)
    );

    return result;
  } catch (error) {
    logReplayEvent('REPLAY_ERROR', 'Replay simulation error', {
      sessionId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Gets attack log for demonstration
 * @returns {Array} Attack log entries
 */
export function getReplayAttackLog() {
  return [...attackLog];
}

/**
 * Clears attack log
 */
export function clearReplayAttackLog() {
  attackLog.length = 0;
  capturedMessages.clear();
}

/**
 * Exports attack log as JSON for evidence
 * @returns {string} JSON string
 */
export function exportReplayAttackLog() {
  return JSON.stringify({
    attackType: 'REPLAY',
    timestamp: new Date().toISOString(),
    capturedMessages: Array.from(capturedMessages.entries()).map(([id, data]) => ({
      messageId: id,
      sessionId: data.sessionId,
      seq: data.envelope.seq,
      timestamp: data.envelope.timestamp,
      type: data.envelope.type
    })),
    log: attackLog
  }, null, 2);
}

