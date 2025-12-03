/**
 * MITM Attack Demonstration Runner
 * 
 * This script runs the complete MITM attack demonstration and generates
 * all evidence files including packet captures and logs.
 * 
 * Usage: node scripts/run-mitm-demonstration.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { TextEncoder, TextDecoder } from 'util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Node.js 22+ has native Web Crypto API with crypto.subtle
// No polyfill needed - native crypto should work
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
  console.log('MITM ATTACK DEMONSTRATION RUNNER');
  console.log('='.repeat(80) + '\n');
  
  console.log('This script will:');
  console.log('1. Run Attack 1: Demonstrate MITM breaking unsigned DH');
  console.log('2. Run Attack 2: Demonstrate signatures preventing MITM');
  console.log('3. Generate packet captures (text and JSON)');
  console.log('4. Generate demonstration report');
  console.log('5. Save all evidence to logs/ directory\n');
  
  try {
    // Import demonstration functions after crypto is set up
    const { runMITMDemonstration, exportDemonstrationReport } = await import('../client/src/attacks/mitmDemonstration.js');
    
    // Run the demonstration
    console.log('Running MITM attack demonstration...\n');
    let results;
    try {
      results = await runMITMDemonstration(aliceUserId, bobUserId, password);
    } catch (error) {
      // Log error before re-throwing
      const errorLogPath = path.join(logsDir, 'mitm_demonstration_errors.log');
      const errorLogEntry = {
        timestamp: new Date().toISOString(),
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name
        },
        sessionId: 'unknown',
        function: 'runMITMDemonstration'
      };
      
      const existingLog = fs.existsSync(errorLogPath) 
        ? fs.readFileSync(errorLogPath, 'utf8') 
        : '';
      const errorLogs = existingLog ? JSON.parse(existingLog) : [];
      errorLogs.push(errorLogEntry);
      fs.writeFileSync(errorLogPath, JSON.stringify(errorLogs, null, 2), 'utf8');
      
      console.error(`\nError logged to: ${errorLogPath}`);
      console.error(`Full path: ${path.resolve(errorLogPath)}\n`);
      
      throw error;
    }
    
    // ALWAYS log errors from the results - FORCE WRITE TO FILE
    const errorLogPath = path.join(logsDir, 'mitm_demonstration_errors.log');
    const errorLogs = [];
    
    console.log('\n[DEBUG] Collecting errors for logging...');
    
    // Log main demonstration error if present
    if (results.error) {
      console.log('[DEBUG] Found main demonstration error');
      errorLogs.push({
        timestamp: new Date().toISOString(),
        error: results.error,
        sessionId: results.results?.sessionId || 'unknown',
        function: 'runMITMDemonstration'
      });
    }
    
    // Log Attack 1 errors - CHECK ALL POSSIBLE SOURCES
    console.log('[DEBUG] Checking Attack 1 errors...');
    console.log('[DEBUG] attack1_unsigned exists:', !!results.results?.attack1_unsigned);
    console.log('[DEBUG] attack1_unsigned.errorLog:', results.results?.attack1_unsigned?.errorLog);
    console.log('[DEBUG] attack1_unsigned.attackSuccessful:', results.results?.attack1_unsigned?.attackSuccessful);
    
    if (results.results?.attack1_unsigned?.errorLog && results.results.attack1_unsigned.errorLog.length > 0) {
      console.log(`[DEBUG] Found ${results.results.attack1_unsigned.errorLog.length} errors in errorLog`);
      errorLogs.push(...results.results.attack1_unsigned.errorLog);
    }
    
    // Also check if attack1 failed and log the reason
    if (results.results?.attack1_unsigned) {
      if (!results.results.attack1_unsigned.attackSuccessful) {
        console.log('[DEBUG] Attack 1 failed - logging failure');
        const attack1Error = {
          timestamp: new Date().toISOString(),
          function: 'attackUnsignedDH',
          sessionId: results.results.sessionId || 'unknown',
          error: {
            message: results.results.attack1_unsigned.reason || 'Attack failed',
            name: 'AttackFailure'
          },
          attackSuccessful: false,
          reason: results.results.attack1_unsigned.reason
        };
        errorLogs.push(attack1Error);
      }
      
      // Also log the error field if it exists
      if (results.results.attack1_unsigned.error) {
        console.log('[DEBUG] Found error field in attack1_unsigned');
        errorLogs.push({
          timestamp: new Date().toISOString(),
          function: 'attackUnsignedDH',
          sessionId: results.results.sessionId || 'unknown',
          error: results.results.attack1_unsigned.error,
          source: 'error_field'
        });
      }
    }
    
    // Log Attack 2 errors
    console.log('[DEBUG] Checking Attack 2 errors...');
    if (results.results?.attack2_signed?.errorLog && results.results.attack2_signed.errorLog.length > 0) {
      console.log(`[DEBUG] Found ${results.results.attack2_signed.errorLog.length} errors in errorLog`);
      errorLogs.push(...results.results.attack2_signed.errorLog);
    }
    
    // Also check if attack2 failed and log the reason
    if (results.results?.attack2_signed && !results.results.attack2_signed.attackSuccessful) {
      console.log('[DEBUG] Attack 2 failed - logging failure');
      const attack2Error = {
        timestamp: new Date().toISOString(),
        function: 'attackSignedDH',
        sessionId: results.results.sessionId || 'unknown',
        error: {
          message: results.results.attack2_signed.reason || 'Attack failed',
          name: 'AttackFailure'
        },
        attackSuccessful: false,
        reason: results.results.attack2_signed.reason
      };
      errorLogs.push(attack2Error);
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
    
    // Save packet logs
    const attack1TextPath = path.join(logsDir, 'mitm_attack1_packets.txt');
    const attack1JsonPath = path.join(logsDir, 'mitm_attack1_packets.json');
    const attack2TextPath = path.join(logsDir, 'mitm_attack2_packets.txt');
    const attack2JsonPath = path.join(logsDir, 'mitm_attack2_packets.json');
    
    fs.writeFileSync(attack1TextPath, results.packetLogs.attack1_text, 'utf8');
    fs.writeFileSync(attack1JsonPath, results.packetLogs.attack1_json, 'utf8');
    fs.writeFileSync(attack2TextPath, results.packetLogs.attack2_text, 'utf8');
    fs.writeFileSync(attack2JsonPath, results.packetLogs.attack2_json, 'utf8');
    
    console.log('✓ Packet logs saved:');
    console.log(`  - ${attack1TextPath}`);
    console.log(`  - ${attack1JsonPath}`);
    console.log(`  - ${attack2TextPath}`);
    console.log(`  - ${attack2JsonPath}\n`);
    
    // Generate and save demonstration report
    const report = exportDemonstrationReport(results.results);
    const reportPath = path.join(logsDir, 'mitm_demonstration_report.json');
    fs.writeFileSync(reportPath, report, 'utf8');
    
    console.log('✓ Demonstration report saved:');
    console.log(`  - ${reportPath}\n`);
    
    // Generate summary
    const summaryPath = path.join(logsDir, 'mitm_demonstration_summary.txt');
    const summary = `
MITM ATTACK DEMONSTRATION SUMMARY
==================================

Timestamp: ${new Date().toISOString()}

ATTACK 1: Breaking Unsigned DH
-------------------------------
Attack Successful: ${results.results.attack1_unsigned.attackSuccessful ? 'YES' : 'NO'}
Attacker Can Decrypt: ${results.results.attack1_unsigned.attackerCanDecrypt ? 'YES' : 'NO'}
Packets Captured: ${results.results.attack1_unsigned.packetCount}
Reason: ${results.results.attack1_unsigned.reason}

ATTACK 2: Signed DH (Should Fail)
----------------------------------
Attack Successful: ${results.results.attack2_signed.attackSuccessful ? 'YES' : 'NO'}
Attacker Can Decrypt: ${results.results.attack2_signed.attackerCanDecrypt ? 'YES' : 'NO'}
Signature Valid: ${results.results.attack2_signed.signatureValid === false ? 'BLOCKED' : 'UNEXPECTED'}
Packets Captured: ${results.results.attack2_signed.packetCount}
Reason: ${results.results.attack2_signed.reason}

CONCLUSION
----------
Unsigned DH Vulnerable: ${results.results.summary.unsignedVulnerable ? 'YES' : 'NO'}
Signed DH Protected: ${results.results.summary.signedProtected ? 'YES' : 'NO'}
Conclusion: ${results.results.summary.conclusion}

EVIDENCE FILES
--------------
- Packet Logs (Text): logs/mitm_attack1_packets.txt, logs/mitm_attack2_packets.txt
- Packet Logs (JSON): logs/mitm_attack1_packets.json, logs/mitm_attack2_packets.json
- Demonstration Report: logs/mitm_demonstration_report.json
- This Summary: logs/mitm_demonstration_summary.txt

For detailed analysis, see: MITM_ATTACK_DEMONSTRATION_REPORT.md
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
    console.log('See MITM_ATTACK_DEMONSTRATION_REPORT.md for detailed analysis.\n');
    
  } catch (error) {
    console.error('Demonstration failed:', error);
    console.error('Error stack:', error.stack);
    
    // Log error to file
    const errorLogPath = path.join(logsDir, 'mitm_demonstration_errors.log');
    const errorLogEntry = {
      timestamp: new Date().toISOString(),
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      },
      sessionId: error.sessionId || 'unknown',
      function: error.function || 'main'
    };
    
    // Append to error log file
    const existingLog = fs.existsSync(errorLogPath) 
      ? fs.readFileSync(errorLogPath, 'utf8') 
      : '';
    const errorLogs = existingLog ? JSON.parse(existingLog) : [];
    errorLogs.push(errorLogEntry);
    fs.writeFileSync(errorLogPath, JSON.stringify(errorLogs, null, 2), 'utf8');
    
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
