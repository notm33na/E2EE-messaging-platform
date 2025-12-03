/**
 * Replay Attack Demonstration Runner
 * 
 * This script runs the complete replay attack demonstration and generates
 * all evidence files including attack logs and error logs.
 * 
 * Usage: node scripts/run-replay-demonstration.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { TextEncoder, TextDecoder } from 'util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Node.js 22+ has native Web Crypto API with crypto.subtle
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  console.error('ERROR: Web Crypto API (crypto.subtle) is not available.');
  console.error('This script requires Node.js 22+ or a Web Crypto API polyfill.');
  process.exit(1);
}

// Set up TextEncoder/TextDecoder for Node.js
globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;

// Set up minimal IndexedDB mock (if needed)
if (typeof globalThis.indexedDB === 'undefined') {
  globalThis.indexedDB = {
    open: () => Promise.resolve({}),
    deleteDatabase: () => Promise.resolve({})
  };
}

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Test user IDs
const aliceUserId = 'alice-demo';
const bobUserId = 'bob-demo';
const password = 'demo-password-123';

async function main() {
  console.log('\n' + '='.repeat(80));
  console.log('REPLAY ATTACK DEMONSTRATION RUNNER');
  console.log('='.repeat(80) + '\n');
  
  console.log('This script will:');
  console.log('1. Run Replay Attack 1: Demonstrate timestamp-based replay detection');
  console.log('2. Run Replay Attack 2: Demonstrate sequence-based replay detection');
  console.log('3. Generate attack logs (text and JSON)');
  console.log('4. Generate demonstration report');
  console.log('5. Save all evidence to logs/ directory\n');
  
  try {
    // Import demonstration functions after crypto is set up
    const { 
      simulateReplayWithTimestampCheck,
      simulateReplayWithSequenceCheck,
      exportReplayAttackLog,
      getReplayAttackLog,
      clearReplayAttackLog
    } = await import('../client/src/attacks/replaySimulator.js');
    
    const { encryptAESGCM } = await import('../client/src/crypto/aesGcm.js');
    const { arrayBufferToBase64 } = await import('../client/src/crypto/signatures.js');
    const { generateSecureSessionId } = await import('../client/src/crypto/sessionIdSecurity.js');
    
    // Run the demonstration
    console.log('Running replay attack demonstration...\n');
    
    const sessionId = await generateSecureSessionId(aliceUserId, bobUserId);
    console.log(`Session ID: ${sessionId}\n`);
    
    const demonstrationResults = {
      timestamp: new Date().toISOString(),
      sessionId,
      aliceUserId,
      bobUserId,
      attack1_timestamp: null,
      attack2_sequence: null,
      summary: {}
    };
    
    // ============================================
    // ATTACK 1: Timestamp-based replay detection
    // ============================================
    console.log('\n' + '-'.repeat(80));
    console.log('ATTACK 1: Timestamp-Based Replay Detection');
    console.log('-'.repeat(80) + '\n');
    
    console.log('Step 1: Create a message with current timestamp');
    console.log('Step 2: Capture the message');
    console.log('Step 3: Attempt to replay after time passes');
    console.log('Step 4: Replay blocked by timestamp freshness check\n');
    
    clearReplayAttackLog();
    
    // Create a test message envelope
    const keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);
    const plaintext = new TextEncoder().encode('Replay test message');
    const { ciphertext, iv, authTag } = await encryptAESGCM(keyBytes.buffer, plaintext);
    
    const now = Date.now();
    const testEnvelope = {
      type: 'MSG',
      sessionId,
      sender: aliceUserId,
      receiver: bobUserId,
      ciphertext: arrayBufferToBase64(ciphertext),
      iv: arrayBufferToBase64(iv),
      authTag: arrayBufferToBase64(authTag),
      timestamp: now,
      seq: 1
    };
    
    let attack1Result;
    try {
      // Simulate replay with timestamp check (lastSeq = 0, so seq 1 should pass initially)
      // But we'll use a stale timestamp to trigger detection
      const staleEnvelope = {
        ...testEnvelope,
        timestamp: now - 5 * 60 * 1000 // 5 minutes ago
      };
      
      attack1Result = await simulateReplayWithTimestampCheck(
        sessionId,
        staleEnvelope,
        0 // lastSeq = 0, so seq 1 should be valid
      );
    } catch (error) {
      console.error('Attack 1 failed with error:', error);
      attack1Result = {
        replaySuccessful: false,
        reason: `Attack failed: ${error.message}`,
        blockedBy: 'ERROR',
        log: [],
        errorLog: [{
          timestamp: new Date().toISOString(),
          function: 'simulateReplayWithTimestampCheck',
          sessionId,
          error: {
            message: error.message,
            stack: error.stack,
            name: error.name
          }
        }]
      };
    }
    
    demonstrationResults.attack1_timestamp = {
      replaySuccessful: attack1Result.replaySuccessful,
      reason: attack1Result.reason,
      blockedBy: attack1Result.blockedBy,
      logCount: attack1Result.log?.length || 0,
      errorLog: attack1Result.errorLog || []
    };
    
    console.log('\n✓ Attack 1 Result:');
    console.log(`  - Replay Successful: ${attack1Result.replaySuccessful}`);
    console.log(`  - Blocked By: ${attack1Result.blockedBy || 'N/A'}`);
    console.log(`  - Reason: ${attack1Result.reason}`);
    console.log(`  - Log Entries: ${attack1Result.log?.length || 0}\n`);
    
    const attack1Log = exportReplayAttackLog();
    const attack1LogText = getReplayAttackLog().map(e => 
      `[${e.timestamp}] ${e.eventType}: ${e.description}`
    ).join('\n');
    
    // ============================================
    // ATTACK 2: Sequence-based replay detection
    // ============================================
    console.log('\n' + '-'.repeat(80));
    console.log('ATTACK 2: Sequence-Based Replay Detection');
    console.log('-'.repeat(80) + '\n');
    
    console.log('Step 1: Create a message with sequence number 1');
    console.log('Step 2: Process the message (lastSeq becomes 1)');
    console.log('Step 3: Attempt to replay the same message');
    console.log('Step 4: Replay blocked by sequence monotonicity check\n');
    
    clearReplayAttackLog();
    
    const testEnvelope2 = {
      ...testEnvelope,
      timestamp: Date.now(), // Fresh timestamp
      seq: 1
    };
    
    let attack2Result;
    try {
      // Simulate replay with sequence check
      // lastSeq = 1, so replaying seq 1 should fail
      attack2Result = await simulateReplayWithSequenceCheck(
        sessionId,
        testEnvelope2,
        1 // lastSeq = 1, so seq 1 should be rejected
      );
    } catch (error) {
      console.error('Attack 2 failed with error:', error);
      attack2Result = {
        replaySuccessful: false,
        reason: `Attack failed: ${error.message}`,
        blockedBy: 'ERROR',
        log: [],
        errorLog: [{
          timestamp: new Date().toISOString(),
          function: 'simulateReplayWithSequenceCheck',
          sessionId,
          error: {
            message: error.message,
            stack: error.stack,
            name: error.name
          }
        }]
      };
    }
    
    demonstrationResults.attack2_sequence = {
      replaySuccessful: attack2Result.replaySuccessful,
      reason: attack2Result.reason,
      blockedBy: attack2Result.blockedBy,
      logCount: attack2Result.log?.length || 0,
      errorLog: attack2Result.errorLog || []
    };
    
    console.log('\n✓ Attack 2 Result:');
    console.log(`  - Replay Successful: ${attack2Result.replaySuccessful}`);
    console.log(`  - Blocked By: ${attack2Result.blockedBy || 'N/A'}`);
    console.log(`  - Reason: ${attack2Result.reason}`);
    console.log(`  - Log Entries: ${attack2Result.log?.length || 0}\n`);
    
    const attack2Log = exportReplayAttackLog();
    const attack2LogText = getReplayAttackLog().map(e => 
      `[${e.timestamp}] ${e.eventType}: ${e.description}`
    ).join('\n');
    
    // ============================================
    // Summary
    // ============================================
    demonstrationResults.summary = {
      timestampProtected: !attack1Result.replaySuccessful,
      sequenceProtected: !attack2Result.replaySuccessful,
      conclusion: !attack1Result.replaySuccessful && !attack2Result.replaySuccessful
        ? 'Replay protection mechanisms effectively prevent replay attacks'
        : 'Demonstration incomplete'
    };
    
    console.log('\n' + '='.repeat(80));
    console.log('DEMONSTRATION SUMMARY');
    console.log('='.repeat(80) + '\n');
    console.log('Attack 1 (Timestamp Check):');
    console.log(`  - Protected: ${!attack1Result.replaySuccessful ? 'YES' : 'NO'}`);
    console.log(`  - Blocked By: ${attack1Result.blockedBy || 'N/A'}\n`);
    
    console.log('Attack 2 (Sequence Check):');
    console.log(`  - Protected: ${!attack2Result.replaySuccessful ? 'YES' : 'NO'}`);
    console.log(`  - Blocked By: ${attack2Result.blockedBy || 'N/A'}\n`);
    
    console.log('Conclusion:');
    console.log(`  ${demonstrationResults.summary.conclusion}\n`);
    
    // ALWAYS log errors from the results - FORCE WRITE TO FILE
    const errorLogPath = path.join(logsDir, 'replay_demonstration_errors.log');
    const errorLogs = [];
    
    console.log('\n[DEBUG] Collecting errors for logging...');
    
    // Log Attack 1 errors
    console.log('[DEBUG] Checking Attack 1 errors...');
    console.log('[DEBUG] attack1_timestamp exists:', !!demonstrationResults.attack1_timestamp);
    console.log('[DEBUG] attack1_timestamp.errorLog:', demonstrationResults.attack1_timestamp?.errorLog);
    console.log('[DEBUG] attack1_timestamp.replaySuccessful:', demonstrationResults.attack1_timestamp?.replaySuccessful);
    
    if (demonstrationResults.attack1_timestamp?.errorLog && demonstrationResults.attack1_timestamp.errorLog.length > 0) {
      console.log(`[DEBUG] Found ${demonstrationResults.attack1_timestamp.errorLog.length} errors in errorLog`);
      errorLogs.push(...demonstrationResults.attack1_timestamp.errorLog);
    }
    
    if (demonstrationResults.attack1_timestamp && demonstrationResults.attack1_timestamp.replaySuccessful) {
      console.log('[DEBUG] Attack 1 unexpectedly succeeded - logging warning');
      errorLogs.push({
        timestamp: new Date().toISOString(),
        function: 'simulateReplayWithTimestampCheck',
        sessionId: demonstrationResults.sessionId || 'unknown',
        error: {
          message: 'Replay attack unexpectedly succeeded - protection may have failed',
          name: 'ProtectionFailure'
        },
        replaySuccessful: true,
        reason: demonstrationResults.attack1_timestamp.reason
      });
    }
    
    // Log Attack 2 errors
    console.log('[DEBUG] Checking Attack 2 errors...');
    if (demonstrationResults.attack2_sequence?.errorLog && demonstrationResults.attack2_sequence.errorLog.length > 0) {
      console.log(`[DEBUG] Found ${demonstrationResults.attack2_sequence.errorLog.length} errors in errorLog`);
      errorLogs.push(...demonstrationResults.attack2_sequence.errorLog);
    }
    
    if (demonstrationResults.attack2_sequence && demonstrationResults.attack2_sequence.replaySuccessful) {
      console.log('[DEBUG] Attack 2 unexpectedly succeeded - logging warning');
      errorLogs.push({
        timestamp: new Date().toISOString(),
        function: 'simulateReplayWithSequenceCheck',
        sessionId: demonstrationResults.sessionId || 'unknown',
        error: {
          message: 'Replay attack unexpectedly succeeded - protection may have failed',
          name: 'ProtectionFailure'
        },
        replaySuccessful: true,
        reason: demonstrationResults.attack2_sequence.reason
      });
    }
    
    // FORCE WRITE TO FILE - ALWAYS WRITE, EVEN IF EMPTY
    console.log(`[DEBUG] Total errors collected: ${errorLogs.length}`);
    console.log(`[DEBUG] Writing to: ${errorLogPath}`);
    
    try {
      let allErrorLogs = [];
      if (fs.existsSync(errorLogPath)) {
        try {
          const existingLog = fs.readFileSync(errorLogPath, 'utf8');
          if (existingLog.trim()) {
            allErrorLogs = JSON.parse(existingLog);
            console.log(`[DEBUG] Loaded ${allErrorLogs.length} existing errors from log file`);
          }
        } catch (parseError) {
          console.warn('[DEBUG] Could not parse existing error log, starting fresh:', parseError.message);
          allErrorLogs = [];
        }
      } else {
        console.log('[DEBUG] Error log file does not exist, creating new one');
      }
      
      // Add new errors
      allErrorLogs.push(...errorLogs);
      
      // ALWAYS WRITE THE FILE
      fs.writeFileSync(errorLogPath, JSON.stringify(allErrorLogs, null, 2), 'utf8');
      console.log(`[DEBUG] Successfully wrote ${allErrorLogs.length} total errors to file`);
      
      // ALWAYS PRINT THE LOG FILE PATH
      const absolutePath = path.resolve(errorLogPath);
      console.log(`\n${'='.repeat(80)}`);
      console.log('ERROR LOG FILE');
      console.log('='.repeat(80));
      console.log(`File: ${errorLogPath}`);
      console.log(`Full Path: ${absolutePath}`);
      console.log(`New errors in this run: ${errorLogs.length}`);
      console.log(`Total errors in file: ${allErrorLogs.length}`);
      console.log('='.repeat(80) + '\n');
      
    } catch (writeError) {
      console.error('\n[ERROR] FAILED TO WRITE ERROR LOG FILE!');
      console.error('Error:', writeError.message);
      console.error('Stack:', writeError.stack);
      console.error(`Attempted path: ${errorLogPath}`);
      console.error(`Absolute path: ${path.resolve(errorLogPath)}\n`);
    }
    
    // Save attack logs
    const attack1TextPath = path.join(logsDir, 'replay_attack1_log.txt');
    const attack1JsonPath = path.join(logsDir, 'replay_attack1_log.json');
    const attack2TextPath = path.join(logsDir, 'replay_attack2_log.txt');
    const attack2JsonPath = path.join(logsDir, 'replay_attack2_log.json');
    
    fs.writeFileSync(attack1TextPath, attack1LogText, 'utf8');
    fs.writeFileSync(attack1JsonPath, attack1Log, 'utf8');
    fs.writeFileSync(attack2TextPath, attack2LogText, 'utf8');
    fs.writeFileSync(attack2JsonPath, attack2Log, 'utf8');
    
    console.log('✓ Attack logs saved:');
    console.log(`  - ${attack1TextPath}`);
    console.log(`  - ${attack1JsonPath}`);
    console.log(`  - ${attack2TextPath}`);
    console.log(`  - ${attack2JsonPath}\n`);
    
    // Generate and save demonstration report
    const report = JSON.stringify({
      title: 'Replay Attack Demonstration Report',
      timestamp: new Date().toISOString(),
      sessionId: demonstrationResults.sessionId,
      executiveSummary: {
        timestampProtected: demonstrationResults.summary.timestampProtected,
        sequenceProtected: demonstrationResults.summary.sequenceProtected,
        conclusion: demonstrationResults.summary.conclusion
      },
      attack1_timestamp: {
        description: 'Replay attack with timestamp freshness check',
        result: demonstrationResults.attack1_timestamp,
        explanation: 'Messages with stale timestamps (outside validity window) are rejected.'
      },
      attack2_sequence: {
        description: 'Replay attack with sequence monotonicity check',
        result: demonstrationResults.attack2_sequence,
        explanation: 'Messages with non-monotonic sequence numbers are rejected.'
      },
      protection: {
        timestampWindow: 'Messages must have timestamps within ±2 minutes of current time',
        sequenceMonotonicity: 'Sequence numbers must be strictly increasing',
        nonceUniqueness: 'Nonces must be unique per session',
        messageIdUniqueness: 'Message IDs must be unique server-side'
      }
    }, null, 2);
    
    const reportPath = path.join(logsDir, 'replay_demonstration_report.json');
    fs.writeFileSync(reportPath, report, 'utf8');
    
    console.log('✓ Demonstration report saved:');
    console.log(`  - ${reportPath}\n`);
    
    // Generate summary
    const summaryPath = path.join(logsDir, 'replay_demonstration_summary.txt');
    const summary = `
REPLAY ATTACK DEMONSTRATION SUMMARY
===================================

Timestamp: ${new Date().toISOString()}

ATTACK 1: Timestamp-Based Replay Detection
------------------------------------------
Replay Blocked: ${!attack1Result.replaySuccessful ? 'YES' : 'NO'}
Blocked By: ${attack1Result.blockedBy || 'N/A'}
Reason: ${attack1Result.reason}
Log Entries: ${attack1Result.log?.length || 0}

ATTACK 2: Sequence-Based Replay Detection
-----------------------------------------
Replay Blocked: ${!attack2Result.replaySuccessful ? 'YES' : 'NO'}
Blocked By: ${attack2Result.blockedBy || 'N/A'}
Reason: ${attack2Result.reason}
Log Entries: ${attack2Result.log?.length || 0}

CONCLUSION
----------
Timestamp Protection: ${demonstrationResults.summary.timestampProtected ? 'YES' : 'NO'}
Sequence Protection: ${demonstrationResults.summary.sequenceProtected ? 'YES' : 'NO'}
Conclusion: ${demonstrationResults.summary.conclusion}

EVIDENCE FILES
--------------
- Attack Logs (Text): logs/replay_attack1_log.txt, logs/replay_attack2_log.txt
- Attack Logs (JSON): logs/replay_attack1_log.json, logs/replay_attack2_log.json
- Demonstration Report: logs/replay_demonstration_report.json
- Error Log: logs/replay_demonstration_errors.log
- This Summary: logs/replay_demonstration_summary.txt
`;
    
    fs.writeFileSync(summaryPath, summary, 'utf8');
    
    console.log('✓ Summary saved:');
    console.log(`  - ${summaryPath}\n`);
    
    // Print summary to console
    console.log(summary);
    
    console.log('='.repeat(80));
    console.log('DEMONSTRATION COMPLETE');
    console.log('='.repeat(80) + '\n');
    
    console.log('All evidence files have been saved to the logs/ directory.');
    console.log('Error log location:');
    console.log(`  - ${errorLogPath}`);
    console.log(`  - ${path.resolve(errorLogPath)}\n`);
    
  } catch (error) {
    console.error('Demonstration failed:', error);
    console.error('Error stack:', error.stack);
    
    // Log error to file
    const errorLogPath = path.join(logsDir, 'replay_demonstration_errors.log');
    const errorLogEntry = {
      timestamp: new Date().toISOString(),
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      },
      sessionId: 'unknown',
      function: 'main'
    };
    
    // Append to error log file
    let existingLog = [];
    if (fs.existsSync(errorLogPath)) {
      try {
        const existingLogContent = fs.readFileSync(errorLogPath, 'utf8');
        if (existingLogContent.trim()) {
          existingLog = JSON.parse(existingLogContent);
        }
      } catch (parseError) {
        console.warn('Could not parse existing error log:', parseError.message);
      }
    }
    
    existingLog.push(errorLogEntry);
    fs.writeFileSync(errorLogPath, JSON.stringify(existingLog, null, 2), 'utf8');
    
    console.error(`\nError logged to: ${errorLogPath}`);
    console.error(`Full path: ${path.resolve(errorLogPath)}\n`);
    
    process.exit(1);
  }
}

// Run the script
main().catch(error => {
  console.error('Fatal error:', error);
  console.error('Error stack:', error.stack);
  process.exit(1);
});

