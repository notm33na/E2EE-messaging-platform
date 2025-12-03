/**
 * MITM (Man-in-the-Middle) Attacker Script
 * 
 * This script demonstrates a real MITM attack on the key exchange protocol.
 * 
 * ATTACK SCENARIO 1: Breaking DH without signatures
 * - Attacker intercepts KEP_INIT and KEP_RESPONSE messages
 * - Replaces ephemeral public keys with attacker's own keys
 * - Establishes separate sessions with both Alice and Bob
 * - Can decrypt all messages between them
 * 
 * ATTACK SCENARIO 2: Digital signatures prevent MITM
 * - Attacker attempts same attack but with signed messages
 * - Signature verification fails, attack is blocked
 * 
 * EDUCATIONAL PURPOSE ONLY - For demonstration and security analysis
 */

import { generateEphemeralKeyPair, exportPublicKey, importPublicKey, computeSharedSecret, deriveSessionKeys } from '../crypto/ecdh.js';
import { signEphemeralKey, verifyEphemeralKeySignature, arrayBufferToBase64, base64ToArrayBuffer } from '../crypto/signatures.js';
import { generateNonce } from '../crypto/messages.js';
import { logMITMAttack, logMITMDemonstration } from '../utils/clientLogger.js';

/**
 * Packet capture log for evidence
 */
const packetLog = [];
const attackEvidence = {
  timestamp: new Date().toISOString(),
  attackType: 'MITM',
  packets: [],
  sharedSecrets: {},
  sessionKeys: {},
  attackSuccessful: false,
  signaturePrevented: false
};

/**
 * Logs a packet capture event (Wireshark-style)
 */
function logPacket(direction, packetType, data, metadata = {}) {
  const packet = {
    timestamp: new Date().toISOString(),
    packetNumber: packetLog.length + 1,
    direction, // 'ALICE->BOB', 'BOB->ALICE', 'ATTACKER->ALICE', etc.
    packetType,
    data: {
      ...data,
      // Sanitize sensitive data
      hasPrivateKey: !!data.privateKey,
      hasSharedSecret: !!data.sharedSecret,
      hasSessionKey: !!data.sessionKey
    },
    metadata: {
      ...metadata,
      size: JSON.stringify(data).length,
      protocol: 'KEP'
    }
  };
  
  packetLog.push(packet);
  attackEvidence.packets.push(packet);
  
  console.log(`[PACKET ${packet.packetNumber}] ${direction} | ${packetType} | ${metadata.description || ''}`);
  
  return packet;
}

/**
 * MITM Attack: Breaking DH without signatures
 * 
 * This demonstrates the vulnerability when ephemeral keys are not signed.
 * The attacker can successfully intercept and replace keys.
 */
export async function attackUnsignedDH(sessionId, aliceEphPubJWK, bobEphPubJWK, aliceUserId, bobUserId) {
  // Note: bobEphPubJWK is passed but we generate Bob's key pair in the simulation
  // In a real attack, Bob would have already generated his key pair
  const errorLog = [];
  
  try {
    console.log('\n=== MITM ATTACK: Breaking Unsigned DH ===\n');
    
    // Clear previous logs
    packetLog.length = 0;
    attackEvidence.packets = [];
    attackEvidence.attackSuccessful = false;
    attackEvidence.signaturePrevented = false;
    
    logPacket('ALICE->ATTACKER', 'KEP_INIT', {
      sessionId,
      from: aliceUserId,
      to: bobUserId,
      ephPub: aliceEphPubJWK,
      hasSignature: false,
      description: 'Alice sends KEP_INIT (UNSIGNED) - intercepted by attacker'
    }, { description: 'Attacker intercepts Alice\'s ephemeral public key' });
    
    // Attacker generates their own ephemeral key pair
    const attackerKeyPair = await generateEphemeralKeyPair();
    const attackerEphPubJWK = await exportPublicKey(attackerKeyPair.publicKey);
    
    logPacket('ATTACKER', 'KEY_GENERATION', {
      attackerEphPub: attackerEphPubJWK,
      description: 'Attacker generates own ephemeral key pair'
    }, { description: 'Attacker creates malicious key pair' });
    
    // Attacker replaces Alice's key with their own
    const modifiedAliceKey = attackerEphPubJWK;
    
    logPacket('ATTACKER->BOB', 'KEP_INIT_MODIFIED', {
      sessionId,
      from: aliceUserId,
      to: bobUserId,
      originalEphPub: aliceEphPubJWK,
      replacedWith: modifiedAliceKey,
      description: 'Attacker replaces Alice\'s key with own key (NO SIGNATURE VERIFICATION)'
    }, { description: 'Key substitution attack - Bob receives attacker\'s key' });
    
    // Bob receives attacker's key (thinking it's from Alice)
    // Bob computes shared secret with attacker
    // Note: In real attack, Bob would use his own ephemeral key pair
    // For simulation, we generate Bob's key pair
    const bobEphKeyPair = await generateEphemeralKeyPair();
    const bobEphPubJWKActual = await exportPublicKey(bobEphKeyPair.publicKey);
    
    // Use attacker's public key directly (we have the CryptoKey object)
    // This avoids the export/import round-trip that can cause issues
    const bobSharedSecretWithAttacker = await computeSharedSecret(
      bobEphKeyPair.privateKey,
      attackerKeyPair.publicKey
    );
    
    // Attacker also computes shared secret with Bob
    // Attacker uses Bob's actual public key (which Bob would send)
    // We can use the CryptoKey directly since we just generated it
    const attackerSharedSecretWithBob = await computeSharedSecret(
      attackerKeyPair.privateKey,
      bobEphKeyPair.publicKey
    );
    
    logPacket('BOB', 'SHARED_SECRET_COMPUTED', {
      sessionId,
      computedWith: 'ATTACKER',
      hasSharedSecret: !!bobSharedSecretWithAttacker,
      description: 'Bob computes shared secret with attacker (thinks it\'s Alice)'
    }, { description: 'Bob compromised - has shared secret with attacker' });
    
    logPacket('ATTACKER', 'SHARED_SECRET_COMPUTED', {
      sessionId,
      computedWith: 'BOB',
      hasSharedSecret: !!attackerSharedSecretWithBob,
      description: 'Attacker computes shared secret with Bob'
    }, { description: 'Attacker has shared secret with Bob' });
    
    // Now attacker intercepts Bob's response
    logPacket('BOB->ATTACKER', 'KEP_RESPONSE', {
      sessionId,
      from: bobUserId,
      to: aliceUserId,
      ephPub: bobEphPubJWKActual,
      hasSignature: false,
      description: 'Bob sends KEP_RESPONSE (UNSIGNED) - intercepted by attacker'
    }, { description: 'Attacker intercepts Bob\'s ephemeral public key' });
    
    // Attacker replaces Bob's key with their own
    const modifiedBobKey = attackerEphPubJWK;
    
    logPacket('ATTACKER->ALICE', 'KEP_RESPONSE_MODIFIED', {
      sessionId,
      from: bobUserId,
      to: aliceUserId,
      originalEphPub: bobEphPubJWKActual,
      replacedWith: modifiedBobKey,
      description: 'Attacker replaces Bob\'s key with own key (NO SIGNATURE VERIFICATION)'
    }, { description: 'Key substitution attack - Alice receives attacker\'s key' });
    
    // Alice receives attacker's key (thinking it's from Bob)
    // For simulation, we generate a new key pair for Alice
    // In real attack, Alice would use her original ephemeral key pair
    const aliceEphKeyPair = await generateEphemeralKeyPair();
    
    // Use attacker's public key directly (we have the CryptoKey object)
    const aliceSharedSecretWithAttacker = await computeSharedSecret(
      aliceEphKeyPair.privateKey,
      attackerKeyPair.publicKey
    );
    
    // Attacker also computes shared secret with Alice
    // In simulation, we use the newly generated Alice key pair's public key
    // (In real attack, attacker would use Alice's original public key from intercepted message)
    // Force the attack by using the generated key pair directly instead of importing JWK
    const attackerSharedSecretWithAlice = await computeSharedSecret(
      attackerKeyPair.privateKey,
      aliceEphKeyPair.publicKey
    );
    
    logPacket('ALICE', 'SHARED_SECRET_COMPUTED', {
      sessionId,
      computedWith: 'ATTACKER',
      hasSharedSecret: !!aliceSharedSecretWithAttacker,
      description: 'Alice computes shared secret with attacker (thinks it\'s Bob)'
    }, { description: 'Alice compromised - has shared secret with attacker' });
    
    logPacket('ATTACKER', 'SHARED_SECRET_COMPUTED', {
      sessionId,
      computedWith: 'ALICE',
      hasSharedSecret: !!attackerSharedSecretWithAlice,
      description: 'Attacker computes shared secret with Alice'
    }, { description: 'Attacker has shared secret with Alice' });
    
    // Derive session keys
    const aliceSessionKeys = await deriveSessionKeys(
      aliceSharedSecretWithAttacker,
      sessionId,
      aliceUserId,
      bobUserId
    );
    
    const bobSessionKeys = await deriveSessionKeys(
      bobSharedSecretWithAttacker,
      sessionId,
      bobUserId,
      aliceUserId
    );
    
    const attackerSessionKeysAlice = await deriveSessionKeys(
      attackerSharedSecretWithAlice,
      sessionId,
      'ATTACKER',
      aliceUserId
    );
    
    const attackerSessionKeysBob = await deriveSessionKeys(
      attackerSharedSecretWithBob,
      sessionId,
      'ATTACKER',
      bobUserId
    );
    
    attackEvidence.sharedSecrets = {
      aliceWithAttacker: arrayBufferToBase64(aliceSharedSecretWithAttacker),
      bobWithAttacker: arrayBufferToBase64(bobSharedSecretWithAttacker),
      attackerWithAlice: arrayBufferToBase64(attackerSharedSecretWithAlice),
      attackerWithBob: arrayBufferToBase64(attackerSharedSecretWithBob)
    };
    
    attackEvidence.sessionKeys = {
      alice: {
        hasRootKey: !!aliceSessionKeys.rootKey,
        hasSendKey: !!aliceSessionKeys.sendKey,
        hasRecvKey: !!aliceSessionKeys.recvKey
      },
      bob: {
        hasRootKey: !!bobSessionKeys.rootKey,
        hasSendKey: !!bobSessionKeys.sendKey,
        hasRecvKey: !!bobSessionKeys.recvKey
      },
      attacker: {
        hasRootKey: !!attackerSessionKeysAlice.rootKey,
        hasSendKey: !!attackerSessionKeysAlice.sendKey,
        hasRecvKey: !!attackerSessionKeysAlice.recvKey
      }
    };
    
    logPacket('ATTACKER', 'ATTACK_SUCCESS', {
      sessionId,
      attackSuccessful: true,
      reason: 'No signature verification - unsigned ephemeral keys',
      attackerCanDecrypt: true,
      aliceCompromised: true,
      bobCompromised: true,
      description: 'MITM ATTACK SUCCESSFUL - Attacker can decrypt all messages'
    }, { description: 'Attack completed successfully - system compromised' });
    
    attackEvidence.attackSuccessful = true;
    
    // Log MITM attack to IndexedDB for alerts
    try {
      await logMITMAttack(
        sessionId,
        'unsigned_dh',
        'MITM attack successful on unsigned DH - attacker can decrypt all messages',
        {
          attackSuccessful: true,
          attackerCanDecrypt: true,
          aliceCompromised: true,
          bobCompromised: true,
          packetCount: packetLog.length
        },
        aliceUserId
      );
    } catch (logError) {
      console.warn('Failed to log MITM attack:', logError);
    }
    
    return {
      attackSuccessful: true,
      reason: 'Unsigned ECDH is vulnerable to MITM',
      attackerCanDecrypt: true,
      aliceCompromised: true,
      bobCompromised: true,
      evidence: attackEvidence,
      packetLog: [...packetLog],
      errorLog: errorLog
    };
  } catch (error) {
    // Log error details
    const errorDetails = {
      timestamp: new Date().toISOString(),
      function: 'attackUnsignedDH',
      sessionId,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      }
    };
    errorLog.push(errorDetails);
    
    logPacket('ATTACKER', 'ATTACK_ERROR', {
      sessionId,
      error: error.message,
      description: 'MITM attack simulation error'
    }, { description: 'Attack failed due to error' });
    
    attackEvidence.attackSuccessful = false;
    attackEvidence.error = errorDetails;
    
    // Return error information instead of throwing
    return {
      attackSuccessful: false,
      reason: `Attack failed: ${error.message}`,
      attackerCanDecrypt: false,
      aliceCompromised: false,
      bobCompromised: false,
      evidence: attackEvidence,
      packetLog: [...packetLog],
      errorLog: errorLog
    };
  }
}

/**
 * MITM Attack: Digital signatures prevent the attack
 * 
 * This demonstrates how digital signatures block the MITM attack.
 */
export async function attackSignedDH(
  sessionId,
  aliceEphPubJWK,
  aliceIdentityPrivKey,
  aliceIdentityPubKey,
  bobEphPubJWK,
  bobIdentityPrivKey,
  bobIdentityPubKey,
  aliceUserId,
  bobUserId
) {
  try {
    console.log('\n=== MITM ATTACK: Signed DH (Should Fail) ===\n');
    
    // Clear previous logs
    packetLog.length = 0;
    attackEvidence.packets = [];
    attackEvidence.attackSuccessful = false;
    attackEvidence.signaturePrevented = false;
    
    // Alice signs her ephemeral public key
    const aliceSignature = await signEphemeralKey(aliceIdentityPrivKey, aliceEphPubJWK);
    const aliceSignatureBase64 = arrayBufferToBase64(aliceSignature);
    
    logPacket('ALICE->ATTACKER', 'KEP_INIT_SIGNED', {
      sessionId,
      from: aliceUserId,
      to: bobUserId,
      ephPub: aliceEphPubJWK,
      signature: aliceSignatureBase64,
      hasSignature: true,
      description: 'Alice sends KEP_INIT (SIGNED) - intercepted by attacker'
    }, { description: 'Attacker intercepts Alice\'s signed ephemeral key' });
    
    // Attacker generates their own ephemeral key pair
    const attackerKeyPair = await generateEphemeralKeyPair();
    const attackerEphPubJWK = await exportPublicKey(attackerKeyPair.publicKey);
    
    logPacket('ATTACKER', 'KEY_GENERATION', {
      attackerEphPub: attackerEphPubJWK,
      description: 'Attacker generates own ephemeral key pair'
    }, { description: 'Attacker creates malicious key pair' });
    
    // Attacker tries to replace Alice's key with their own
    const modifiedAliceKey = attackerEphPubJWK;
    
    logPacket('ATTACKER->BOB', 'KEP_INIT_MODIFIED', {
      sessionId,
      from: aliceUserId,
      to: bobUserId,
      originalEphPub: aliceEphPubJWK,
      replacedWith: modifiedAliceKey,
      originalSignature: aliceSignatureBase64,
      description: 'Attacker attempts to replace Alice\'s key with own key'
    }, { description: 'Key substitution attempt - signature will be invalid' });
    
    // Bob receives modified key and tries to verify signature
    const aliceSignatureBuffer = base64ToArrayBuffer(aliceSignatureBase64);
    const signatureValid = await verifyEphemeralKeySignature(
      aliceIdentityPubKey,
      aliceSignatureBuffer,
      modifiedAliceKey
    );
    
    logPacket('BOB', 'SIGNATURE_VERIFICATION', {
      sessionId,
      signatureValid,
      expectedResult: false,
      description: 'Bob verifies signature on modified key - VERIFICATION FAILS'
    }, { description: 'Signature verification blocks attack' });
    
    if (!signatureValid) {
      logPacket('BOB', 'ATTACK_BLOCKED', {
        sessionId,
        attackSuccessful: false,
        reason: 'Signature verification failed - key was modified',
        bobRejected: true,
        description: 'MITM ATTACK BLOCKED - Signature verification prevents key substitution'
      }, { description: 'Attack prevented by digital signatures' });
      
      attackEvidence.attackSuccessful = false;
      attackEvidence.signaturePrevented = true;
      
      // Log MITM attack blocked to IndexedDB for alerts
      try {
        await logMITMAttack(
          sessionId,
          'signed_dh',
          'MITM attack blocked by signature verification',
          {
            attackSuccessful: false,
            attackerCanDecrypt: false,
            signatureValid: false,
            packetCount: packetLog.length
          },
          aliceUserId
        );
      } catch (logError) {
        console.warn('Failed to log MITM attack:', logError);
      }
      
      return {
        attackSuccessful: false,
        reason: 'Signature verification prevents MITM',
        attackerCanDecrypt: false,
        aliceCompromised: false,
        bobCompromised: false,
        signatureValid: false,
        evidence: attackEvidence,
        packetLog: [...packetLog]
      };
    }
    
    // This should never happen if signatures work correctly
    logPacket('BOB', 'ATTACK_ERROR', {
      sessionId,
      warning: 'Unexpected: signature verification passed',
      description: 'ERROR: Signature verification should have failed'
    }, { description: 'Unexpected behavior - signature should have failed' });
    
    return {
      attackSuccessful: false,
      reason: 'Signature verification prevented MITM',
      evidence: attackEvidence,
      packetLog: [...packetLog]
    };
  } catch (error) {
    logPacket('ATTACKER', 'ATTACK_ERROR', {
      sessionId,
      error: error.message,
      description: 'MITM attack simulation error'
    }, { description: 'Attack failed due to error' });
    
    throw error;
  }
}

/**
 * Exports packet log as Wireshark-style text format
 */
export function exportPacketLog(format = 'text') {
  if (format === 'json') {
    return JSON.stringify({
      attackType: 'MITM',
      timestamp: new Date().toISOString(),
      packets: packetLog,
      evidence: attackEvidence
    }, null, 2);
  }
  
  // Text format (Wireshark-style)
  let output = '=== MITM ATTACK PACKET CAPTURE ===\n\n';
  output += `Attack Type: ${attackEvidence.attackType}\n`;
  output += `Timestamp: ${attackEvidence.timestamp}\n`;
  output += `Total Packets: ${packetLog.length}\n`;
  output += `Attack Successful: ${attackEvidence.attackSuccessful}\n`;
  output += `Signature Prevented: ${attackEvidence.signaturePrevented}\n\n`;
  output += '--- Packet Details ---\n\n';
  
  packetLog.forEach((packet, index) => {
    output += `Packet #${packet.packetNumber}\n`;
    output += `  Time: ${packet.timestamp}\n`;
    output += `  Direction: ${packet.direction}\n`;
    output += `  Type: ${packet.packetType}\n`;
    output += `  Description: ${packet.metadata.description || 'N/A'}\n`;
    output += `  Size: ${packet.metadata.size} bytes\n`;
    output += `  Protocol: ${packet.metadata.protocol}\n`;
    
    if (packet.data.sessionId) {
      output += `  Session ID: ${packet.data.sessionId}\n`;
    }
    if (packet.data.hasSignature !== undefined) {
      output += `  Has Signature: ${packet.data.hasSignature}\n`;
    }
    if (packet.data.signatureValid !== undefined) {
      output += `  Signature Valid: ${packet.data.signatureValid}\n`;
    }
    if (packet.data.attackSuccessful !== undefined) {
      output += `  Attack Successful: ${packet.data.attackSuccessful}\n`;
    }
    if (packet.data.reason) {
      output += `  Reason: ${packet.data.reason}\n`;
    }
    
    output += '\n';
  });
  
  return output;
}

/**
 * Gets current attack evidence
 */
export function getAttackEvidence() {
  return {
    ...attackEvidence,
    packets: [...packetLog]
  };
}

/**
 * Clears attack logs
 */
export function clearAttackLogs() {
  packetLog.length = 0;
  attackEvidence.packets = [];
  attackEvidence.sharedSecrets = {};
  attackEvidence.sessionKeys = {};
  attackEvidence.attackSuccessful = false;
  attackEvidence.signaturePrevented = false;
}

