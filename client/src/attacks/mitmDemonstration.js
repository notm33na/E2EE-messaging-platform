/**
 * MITM Attack Demonstration Script
 * 
 * This script runs a complete MITM attack demonstration showing:
 * 1. How MITM successfully breaks DH without signatures
 * 2. How digital signatures prevent MITM in the final system
 * 
 * Includes packet captures, logs, and detailed explanations.
 */

import { generateEphemeralKeyPair, exportPublicKey } from '../crypto/ecdh.js';
import { generateIdentityKeyPair, loadPrivateKey } from '../crypto/identityKeys.js';
import { attackUnsignedDH, attackSignedDH, exportPacketLog, getAttackEvidence, clearAttackLogs } from './mitmAttacker.js';
import { generateSecureSessionId } from '../crypto/sessionIdSecurity.js';
import { logMITMDemonstration } from '../utils/clientLogger.js';

/**
 * Runs complete MITM attack demonstration
 */
export async function runMITMDemonstration(aliceUserId, bobUserId, password = 'test-password') {
  console.log('\n' + '='.repeat(80));
  console.log('MITM ATTACK DEMONSTRATION');
  console.log('='.repeat(80) + '\n');
  
  const demonstrationResults = {
    timestamp: new Date().toISOString(),
    aliceUserId,
    bobUserId,
    attack1_unsigned: null,
    attack2_signed: null,
    summary: {}
  };
  
  try {
    // Generate session ID
    const sessionId = await generateSecureSessionId(aliceUserId, bobUserId);
    demonstrationResults.sessionId = sessionId;
    console.log(`Session ID: ${sessionId}\n`);
    
    // ============================================
    // ATTACK 1: Breaking DH without signatures
    // ============================================
    console.log('\n' + '-'.repeat(80));
    console.log('ATTACK 1: Breaking DH without Signatures');
    console.log('-'.repeat(80) + '\n');
    
    // Generate ephemeral keys for Alice and Bob
    const aliceEphKeyPair = await generateEphemeralKeyPair();
    const bobEphKeyPair = await generateEphemeralKeyPair();
    
    const aliceEphPubJWK = await exportPublicKey(aliceEphKeyPair.publicKey);
    const bobEphPubJWK = await exportPublicKey(bobEphKeyPair.publicKey);
    
    console.log('Step 1: Alice and Bob generate ephemeral keys (UNSIGNED)');
    console.log('Step 2: Attacker intercepts and replaces keys');
    console.log('Step 3: Attack succeeds - no signature verification\n');
    
    let attack1Result;
    try {
      attack1Result = await attackUnsignedDH(
        sessionId,
        aliceEphPubJWK,
        bobEphPubJWK,
        aliceUserId,
        bobUserId
      );
    } catch (error) {
      console.error('Attack 1 failed with error:', error);
      attack1Result = {
        attackSuccessful: false,
        reason: `Attack failed: ${error.message}`,
        attackerCanDecrypt: false,
        packetLog: [],
        errorLog: [{
          timestamp: new Date().toISOString(),
          function: 'attackUnsignedDH',
          sessionId,
          error: {
            message: error.message,
            stack: error.stack,
            name: error.name
          }
        }]
      };
    }
    
    demonstrationResults.attack1_unsigned = {
      attackSuccessful: attack1Result.attackSuccessful,
      reason: attack1Result.reason,
      attackerCanDecrypt: attack1Result.attackerCanDecrypt,
      packetCount: attack1Result.packetLog?.length || 0,
      evidence: getAttackEvidence(),
      errorLog: attack1Result.errorLog || [],
      // Include full error details if attack failed
      error: attack1Result.errorLog && attack1Result.errorLog.length > 0 
        ? attack1Result.errorLog[attack1Result.errorLog.length - 1] 
        : (!attack1Result.attackSuccessful ? { message: attack1Result.reason } : null)
    };
    
    console.log('\n✓ Attack 1 Result:');
    console.log(`  - Attack Successful: ${attack1Result.attackSuccessful}`);
    console.log(`  - Attacker Can Decrypt: ${attack1Result.attackerCanDecrypt}`);
    console.log(`  - Packets Captured: ${attack1Result.packetLog.length}`);
    console.log(`  - Reason: ${attack1Result.reason}\n`);
    
    // Log demonstration event
    try {
      await logMITMDemonstration(
        sessionId,
        'unsigned_dh',
        attack1Result.attackSuccessful,
        attack1Result.reason,
        {
          attackerCanDecrypt: attack1Result.attackerCanDecrypt,
          packetCount: attack1Result.packetLog.length
        },
        aliceUserId
      );
    } catch (logError) {
      console.warn('Failed to log MITM demonstration:', logError);
    }
    
    // Export packet log for Attack 1
    const packetLog1 = exportPacketLog('text');
    const packetLog1JSON = exportPacketLog('json');
    
    // ============================================
    // ATTACK 2: Digital signatures prevent MITM
    // ============================================
    console.log('\n' + '-'.repeat(80));
    console.log('ATTACK 2: Digital Signatures Prevent MITM');
    console.log('-'.repeat(80) + '\n');
    
    clearAttackLogs();
    
    // Generate identity keys for Alice and Bob
    console.log('Step 1: Alice and Bob have identity key pairs');
    
    // For demonstration, we'll generate new identity keys
    // In real system, these would be loaded from storage
    const aliceIdentityKeyPair = await generateIdentityKeyPair();
    const bobIdentityKeyPair = await generateIdentityKeyPair();
    
    // Generate new ephemeral keys
    const aliceEphKeyPair2 = await generateEphemeralKeyPair();
    const bobEphKeyPair2 = await generateEphemeralKeyPair();
    
    const aliceEphPubJWK2 = await exportPublicKey(aliceEphKeyPair2.publicKey);
    const bobEphPubJWK2 = await exportPublicKey(bobEphKeyPair2.publicKey);
    
    console.log('Step 2: Alice signs her ephemeral key with identity key');
    console.log('Step 3: Attacker intercepts and tries to replace key');
    console.log('Step 4: Bob verifies signature - ATTACK BLOCKED\n');
    
    const attack2Result = await attackSignedDH(
      sessionId + '-signed',
      aliceEphPubJWK2,
      aliceIdentityKeyPair.privateKey,
      aliceIdentityKeyPair.publicKey,
      bobEphPubJWK2,
      bobIdentityKeyPair.privateKey,
      bobIdentityKeyPair.publicKey,
      aliceUserId,
      bobUserId
    );
    
    demonstrationResults.attack2_signed = {
      attackSuccessful: attack2Result.attackSuccessful,
      reason: attack2Result.reason,
      attackerCanDecrypt: attack2Result.attackerCanDecrypt,
      signatureValid: attack2Result.signatureValid,
      packetCount: attack2Result.packetLog?.length || 0,
      evidence: getAttackEvidence(),
      errorLog: attack2Result.errorLog || [],
      // Include full error details if attack failed
      error: attack2Result.errorLog && attack2Result.errorLog.length > 0 
        ? attack2Result.errorLog[attack2Result.errorLog.length - 1] 
        : (!attack2Result.attackSuccessful ? { message: attack2Result.reason } : null)
    };
    
    console.log('\n✓ Attack 2 Result:');
    console.log(`  - Attack Successful: ${attack2Result.attackSuccessful}`);
    console.log(`  - Attacker Can Decrypt: ${attack2Result.attackerCanDecrypt}`);
    console.log(`  - Signature Valid: ${attack2Result.signatureValid}`);
    console.log(`  - Packets Captured: ${attack2Result.packetLog.length}`);
    console.log(`  - Reason: ${attack2Result.reason}\n`);
    
    // Log demonstration event
    try {
      await logMITMDemonstration(
        sessionId + '-signed',
        'signed_dh',
        attack2Result.attackSuccessful,
        attack2Result.reason,
        {
          attackerCanDecrypt: attack2Result.attackerCanDecrypt,
          signatureValid: attack2Result.signatureValid,
          packetCount: attack2Result.packetLog.length
        },
        aliceUserId
      );
    } catch (logError) {
      console.warn('Failed to log MITM demonstration:', logError);
    }
    
    // Export packet log for Attack 2
    const packetLog2 = exportPacketLog('text');
    const packetLog2JSON = exportPacketLog('json');
    
    // ============================================
    // Summary
    // ============================================
    demonstrationResults.summary = {
      unsignedVulnerable: attack1Result.attackSuccessful,
      signedProtected: !attack2Result.attackSuccessful,
      conclusion: attack1Result.attackSuccessful && !attack2Result.attackSuccessful
        ? 'Digital signatures effectively prevent MITM attacks'
        : 'Demonstration incomplete'
    };
    
    console.log('\n' + '='.repeat(80));
    console.log('DEMONSTRATION SUMMARY');
    console.log('='.repeat(80) + '\n');
    console.log('Attack 1 (Unsigned DH):');
    console.log(`  - Vulnerable: ${attack1Result.attackSuccessful ? 'YES' : 'NO'}`);
    console.log(`  - Attacker can decrypt: ${attack1Result.attackerCanDecrypt ? 'YES' : 'NO'}\n`);
    
    console.log('Attack 2 (Signed DH):');
    console.log(`  - Protected: ${!attack2Result.attackSuccessful ? 'YES' : 'NO'}`);
    console.log(`  - Signature verification: ${attack2Result.signatureValid === false ? 'BLOCKED ATTACK' : 'FAILED'}\n`);
    
    console.log('Conclusion:');
    console.log(`  ${demonstrationResults.summary.conclusion}\n`);
    
    return {
      results: demonstrationResults,
      packetLogs: {
        attack1_text: packetLog1,
        attack1_json: packetLog1JSON,
        attack2_text: packetLog2,
        attack2_json: packetLog2JSON
      }
    };
  } catch (error) {
    console.error('Demonstration error:', error);
    
    // Add error to results
    demonstrationResults.error = {
      timestamp: new Date().toISOString(),
      message: error.message,
      stack: error.stack,
      name: error.name
    };
    
    // Return partial results with error
    return {
      results: demonstrationResults,
      packetLogs: {
        attack1_text: exportPacketLog('text'),
        attack1_json: exportPacketLog('json'),
        attack2_text: '',
        attack2_json: ''
      },
      error: demonstrationResults.error
    };
  }
}

/**
 * Exports demonstration results for report
 */
export function exportDemonstrationReport(demonstrationResults) {
  const report = {
    title: 'MITM Attack Demonstration Report',
    timestamp: new Date().toISOString(),
    executiveSummary: {
      unsignedVulnerable: demonstrationResults.attack1_unsigned?.attackSuccessful || false,
      signedProtected: !demonstrationResults.attack2_signed?.attackSuccessful || false,
      conclusion: demonstrationResults.summary?.conclusion || 'Incomplete'
    },
    attack1_unsigned: {
      description: 'MITM attack on unsigned Diffie-Hellman key exchange',
      result: demonstrationResults.attack1_unsigned,
      explanation: 'When ephemeral keys are not signed, an attacker can intercept and replace them, establishing separate sessions with both parties and decrypting all messages.'
    },
    attack2_signed: {
      description: 'MITM attack on signed Diffie-Hellman key exchange',
      result: demonstrationResults.attack2_signed,
      explanation: 'When ephemeral keys are signed with identity keys, signature verification detects key substitution attempts and blocks the attack.'
    },
    mitigation: {
      digitalSignatures: 'Ephemeral keys are signed with identity private keys using ECDSA-SHA256',
      signatureVerification: 'Recipients verify signatures using sender\'s identity public key before accepting keys',
      keyConfirmation: 'Key confirmation HMAC ensures both parties computed the same shared secret',
      replayProtection: 'Timestamps, nonces, and sequence numbers prevent replay attacks'
    }
  };
  
  return JSON.stringify(report, null, 2);
}

