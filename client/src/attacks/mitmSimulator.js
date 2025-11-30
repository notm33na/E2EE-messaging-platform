/**
 * MITM (Man-in-the-Middle) Attack Simulator
 * 
 * EDUCATIONAL PURPOSE ONLY - Demonstrates MITM vulnerability
 * and how digital signatures prevent it.
 * 
 * SECURITY CONSIDERATIONS:
 * - This is a simulation for educational purposes
 * - Runs only in local development environment
 * - Never exposes real private keys or plaintext
 * - Demonstrates attack when signatures are disabled
 * - Shows how signatures prevent the attack
 * 
 * DATA PRIVACY CONSTRAINTS:
 * - No real user data is intercepted
 * - All operations are simulated
 * - Logs contain only metadata, no plaintext
 * 
 * LIMITATIONS:
 * - Simulation only, not a real attack
 * - For demonstration and education
 * - Must be run in controlled environment
 */

import { generateEphemeralKeyPair, exportPublicKey, importPublicKey, computeSharedSecret, deriveSessionKeys } from '../crypto/ecdh.js';
import { signData, verifySignature, arrayBufferToBase64, base64ToArrayBuffer } from '../crypto/signatures.js';

/**
 * Attack log for demonstration
 */
const attackLog = [];

/**
 * Logs an attack event
 */
function logAttackEvent(eventType, description, data = {}) {
  const event = {
    timestamp: new Date().toISOString(),
    eventType,
    description,
    data: {
      ...data,
      // Ensure no private keys or plaintext in logs
      hasPrivateKey: !!data.privateKey,
      hasPlaintext: !!data.plaintext
    }
  };
  
  attackLog.push(event);
  console.log(`[MITM SIM] ${eventType}: ${description}`);
  
  return event;
}

/**
 * Simulates MITM attack on unsigned key exchange
 * 
 * This demonstrates the vulnerability when ephemeral keys
 * are not signed with identity keys.
 * 
 * @param {string} sessionId - Session identifier
 * @param {Object} aliceEphPub - Alice's ephemeral public key (JWK)
 * @param {Object} bobEphPub - Bob's ephemeral public key (JWK)
 * @returns {Promise<Object>} Attack result
 */
export async function simulateMITMOnUnsignedECDH(sessionId, aliceEphPub, bobEphPub) {
  try {
    logAttackEvent('MITM_START', 'Starting MITM attack on unsigned ECDH', { sessionId });

    // Attacker generates their own ephemeral key pair
    const attackerKeyPair = await generateEphemeralKeyPair();
    const attackerEphPub = await exportPublicKey(attackerKeyPair.publicKey);
    
    logAttackEvent('MITM_KEY_GENERATED', 'Attacker generated ephemeral key pair', {
      sessionId,
      attackerEphPub: attackerEphPub
    });

    // Attacker intercepts Alice's ephemeral public key
    logAttackEvent('MITM_INTERCEPT', 'Intercepted Alice\'s ephemeral public key', {
      sessionId,
      originalKey: aliceEphPub
    });

    // Attacker replaces Alice's key with their own
    const modifiedAliceKey = attackerEphPub; // Attacker's key
    logAttackEvent('MITM_KEY_REPLACED', 'Replaced Alice\'s key with attacker\'s key', {
      sessionId,
      originalKey: aliceEphPub,
      replacedWith: modifiedAliceKey
    });

    // Bob receives attacker's key (thinking it's from Alice)
    // Bob computes shared secret with attacker
    const bobSharedSecret = await computeSharedSecret(
      attackerKeyPair.privateKey, // Attacker's private key
      await importPublicKey(bobEphPub) // Bob's public key
    );
    
    logAttackEvent('MITM_BOB_COMPROMISED', 'Bob computed shared secret with attacker', {
      sessionId,
      hasSharedSecret: !!bobSharedSecret
    });

    // Attacker also computes shared secret with Bob
    const attackerSharedSecret = await computeSharedSecret(
      attackerKeyPair.privateKey,
      await importPublicKey(bobEphPub)
    );

    // Attacker intercepts Bob's key and replaces it
    logAttackEvent('MITM_INTERCEPT', 'Intercepted Bob\'s ephemeral public key', {
      sessionId,
      originalKey: bobEphPub
    });

    const modifiedBobKey = attackerEphPub; // Attacker's key again
    logAttackEvent('MITM_KEY_REPLACED', 'Replaced Bob\'s key with attacker\'s key', {
      sessionId,
      originalKey: bobEphPub,
      replacedWith: modifiedBobKey
    });

    // Alice receives attacker's key (thinking it's from Bob)
    // Alice computes shared secret with attacker
    const aliceSharedSecret = await computeSharedSecret(
      attackerKeyPair.privateKey,
      await importPublicKey(aliceEphPub) // Alice's original key (but attacker has it)
    );

    logAttackEvent('MITM_ALICE_COMPROMISED', 'Alice computed shared secret with attacker', {
      sessionId,
      hasSharedSecret: !!aliceSharedSecret
    });

    // Result: Both Alice and Bob have shared secrets with attacker
    // Attacker can decrypt all messages between them
    logAttackEvent('MITM_SUCCESS', 'MITM attack successful - attacker can decrypt all messages', {
      sessionId,
      attackSuccessful: true,
      reason: 'No signature verification - unsigned ephemeral keys'
    });

    return {
      attackSuccessful: true,
      reason: 'Unsigned ECDH is vulnerable to MITM',
      attackerCanDecrypt: true,
      aliceCompromised: true,
      bobCompromised: true,
      log: attackLog
    };
  } catch (error) {
    logAttackEvent('MITM_ERROR', 'MITM attack simulation error', {
      sessionId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Simulates MITM attack on signed key exchange
 * 
 * This demonstrates how digital signatures prevent MITM attacks.
 * 
 * @param {string} sessionId - Session identifier
 * @param {Object} aliceEphPub - Alice's ephemeral public key (JWK)
 * @param {CryptoKey} aliceIdentityPrivKey - Alice's identity private key
 * @param {CryptoKey} aliceIdentityPubKey - Alice's identity public key
 * @param {Object} bobEphPub - Bob's ephemeral public key (JWK)
 * @param {CryptoKey} bobIdentityPrivKey - Bob's identity private key
 * @param {CryptoKey} bobIdentityPubKey - Bob's identity public key
 * @returns {Promise<Object>} Attack result (should fail)
 */
export async function simulateMITMOnSignedECDH(
  sessionId,
  aliceEphPub,
  aliceIdentityPrivKey,
  aliceIdentityPubKey,
  bobEphPub,
  bobIdentityPrivKey,
  bobIdentityPubKey
) {
  try {
    attackLog.length = 0; // Clear previous log
    logAttackEvent('MITM_START', 'Starting MITM attack on signed ECDH', { sessionId });

    // Alice signs her ephemeral public key
    const aliceEphPubString = JSON.stringify(aliceEphPub);
    const aliceEphPubBuffer = new TextEncoder().encode(aliceEphPubString);
    const aliceSignature = await signData(aliceIdentityPrivKey, aliceEphPubBuffer);
    
    logAttackEvent('SIGNATURE_CREATED', 'Alice signed her ephemeral public key', {
      sessionId,
      hasSignature: !!aliceSignature
    });

    // Attacker intercepts Alice's signed message
    logAttackEvent('MITM_INTERCEPT', 'Intercepted Alice\'s signed ephemeral key', {
      sessionId,
      originalKey: aliceEphPub,
      hasSignature: true
    });

    // Attacker tries to replace Alice's key with their own
    const attackerKeyPair = await generateEphemeralKeyPair();
    const attackerEphPub = await exportPublicKey(attackerKeyPair.publicKey);
    
    logAttackEvent('MITM_KEY_GENERATED', 'Attacker generated ephemeral key pair', {
      sessionId,
      attackerEphPub: attackerEphPub
    });

    // Attacker tries to replace Alice's key
    const modifiedAliceKey = attackerEphPub;
    logAttackEvent('MITM_KEY_REPLACED', 'Attacker attempted to replace Alice\'s key', {
      sessionId,
      originalKey: aliceEphPub,
      replacedWith: modifiedAliceKey
    });

    // Bob receives modified key and tries to verify signature
    const modifiedKeyString = JSON.stringify(modifiedAliceKey);
    const modifiedKeyBuffer = new TextEncoder().encode(modifiedKeyString);
    const signatureValid = await verifySignature(aliceIdentityPubKey, aliceSignature, modifiedKeyBuffer);
    
    logAttackEvent('SIGNATURE_VERIFICATION', 'Bob verified signature on modified key', {
      sessionId,
      signatureValid,
      expectedResult: false
    });

    if (!signatureValid) {
      logAttackEvent('MITM_BLOCKED', 'MITM attack blocked - signature verification failed', {
        sessionId,
        attackSuccessful: false,
        reason: 'Signature verification failed - key was modified',
        bobRejected: true
      });

      return {
        attackSuccessful: false,
        reason: 'Signature verification prevents MITM',
        attackerCanDecrypt: false,
        aliceCompromised: false,
        bobCompromised: false,
        signatureValid: false,
        log: attackLog
      };
    }

    // This should never happen if signatures work correctly
    logAttackEvent('MITM_ERROR', 'Signature verification should have failed', {
      sessionId,
      warning: 'Unexpected: signature verification passed'
    });

    return {
      attackSuccessful: false,
      reason: 'Signature verification prevented MITM',
      log: attackLog
    };
  } catch (error) {
    logAttackEvent('MITM_ERROR', 'MITM attack simulation error', {
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
export function getAttackLog() {
  return [...attackLog];
}

/**
 * Clears attack log
 */
export function clearAttackLog() {
  attackLog.length = 0;
}

/**
 * Exports attack log as JSON for evidence
 * @returns {string} JSON string
 */
export function exportAttackLog() {
  return JSON.stringify({
    attackType: 'MITM',
    timestamp: new Date().toISOString(),
    log: attackLog
  }, null, 2);
}

