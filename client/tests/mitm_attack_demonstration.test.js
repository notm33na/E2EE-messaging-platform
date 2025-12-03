/**
 * MITM Attack Demonstration Test
 * 
 * This test runs the complete MITM attack demonstration and verifies:
 * 1. Attack succeeds on unsigned DH
 * 2. Attack fails on signed DH
 * 3. All evidence is captured correctly
 */

import { runMITMDemonstration, exportDemonstrationReport } from '../src/attacks/mitmDemonstration.js';
import { generateEphemeralKeyPair, exportPublicKey } from '../src/crypto/ecdh.js';
import { generateIdentityKeyPair } from '../src/crypto/identityKeys.js';
import { generateSecureSessionId } from '../src/crypto/sessionIdSecurity.js';
import { attackUnsignedDH, attackSignedDH, exportPacketLog, clearAttackLogs } from '../src/attacks/mitmAttacker.js';

describe('MITM Attack Demonstration', () => {
  const aliceUserId = 'alice-test-id';
  const bobUserId = 'bob-test-id';
  const password = 'test-password-123';

  test('Attack 1: Unsigned DH is vulnerable to MITM', async () => {
    const sessionId = await generateSecureSessionId(aliceUserId, bobUserId);
    
    // Generate ephemeral keys
    const aliceEphKeyPair = await generateEphemeralKeyPair();
    const bobEphKeyPair = await generateEphemeralKeyPair();
    
    const aliceEphPubJWK = await exportPublicKey(aliceEphKeyPair.publicKey);
    const bobEphPubJWK = await exportPublicKey(bobEphKeyPair.publicKey);
    
    clearAttackLogs();
    
    const result = await attackUnsignedDH(
      sessionId,
      aliceEphPubJWK,
      bobEphPubJWK,
      aliceUserId,
      bobUserId
    );
    
    // Verify attack succeeded
    expect(result.attackSuccessful).toBe(true);
    expect(result.attackerCanDecrypt).toBe(true);
    expect(result.aliceCompromised).toBe(true);
    expect(result.bobCompromised).toBe(true);
    expect(result.reason).toContain('Unsigned ECDH');
    
    // Verify packet log captured
    expect(result.packetLog.length).toBeGreaterThan(0);
    expect(result.evidence.packets.length).toBeGreaterThan(0);
    
    // Verify evidence structure
    expect(result.evidence.attackSuccessful).toBe(true);
    expect(result.evidence.signaturePrevented).toBe(false);
    expect(result.evidence.sharedSecrets).toBeDefined();
    expect(result.evidence.sessionKeys).toBeDefined();
  }, 30000);

  test('Attack 2: Signed DH prevents MITM', async () => {
    const sessionId = await generateSecureSessionId(aliceUserId, bobUserId) + '-signed';
    
    // Generate identity keys
    const aliceIdentityKeyPair = await generateIdentityKeyPair();
    const bobIdentityKeyPair = await generateIdentityKeyPair();
    
    // Generate ephemeral keys
    const aliceEphKeyPair = await generateEphemeralKeyPair();
    const bobEphKeyPair = await generateEphemeralKeyPair();
    
    const aliceEphPubJWK = await exportPublicKey(aliceEphKeyPair.publicKey);
    const bobEphPubJWK = await exportPublicKey(bobEphKeyPair.publicKey);
    
    clearAttackLogs();
    
    const result = await attackSignedDH(
      sessionId,
      aliceEphPubJWK,
      aliceIdentityKeyPair.privateKey,
      aliceIdentityKeyPair.publicKey,
      bobEphPubJWK,
      bobIdentityKeyPair.privateKey,
      bobIdentityKeyPair.publicKey,
      aliceUserId,
      bobUserId
    );
    
    // Verify attack failed
    expect(result.attackSuccessful).toBe(false);
    expect(result.attackerCanDecrypt).toBe(false);
    expect(result.aliceCompromised).toBe(false);
    expect(result.bobCompromised).toBe(false);
    expect(result.signatureValid).toBe(false);
    expect(result.reason).toContain('Signature verification');
    
    // Verify packet log captured
    expect(result.packetLog.length).toBeGreaterThan(0);
    expect(result.evidence.packets.length).toBeGreaterThan(0);
    
    // Verify evidence structure
    expect(result.evidence.attackSuccessful).toBe(false);
    expect(result.evidence.signaturePrevented).toBe(true);
  }, 30000);

  test('Complete demonstration runs successfully', async () => {
    const demonstration = await runMITMDemonstration(aliceUserId, bobUserId, password);
    
    // Verify demonstration results
    expect(demonstration.results).toBeDefined();
    expect(demonstration.results.attack1_unsigned).toBeDefined();
    expect(demonstration.results.attack2_signed).toBeDefined();
    expect(demonstration.results.summary).toBeDefined();
    
    // Verify Attack 1 succeeded
    expect(demonstration.results.attack1_unsigned.attackSuccessful).toBe(true);
    expect(demonstration.results.attack1_unsigned.attackerCanDecrypt).toBe(true);
    
    // Verify Attack 2 failed
    expect(demonstration.results.attack2_signed.attackSuccessful).toBe(false);
    expect(demonstration.results.attack2_signed.attackerCanDecrypt).toBe(false);
    
    // Verify summary
    expect(demonstration.results.summary.unsignedVulnerable).toBe(true);
    expect(demonstration.results.summary.signedProtected).toBe(true);
    expect(demonstration.results.summary.conclusion).toContain('effectively prevent');
    
    // Verify packet logs exported
    expect(demonstration.packetLogs.attack1_text).toBeDefined();
    expect(demonstration.packetLogs.attack1_json).toBeDefined();
    expect(demonstration.packetLogs.attack2_text).toBeDefined();
    expect(demonstration.packetLogs.attack2_json).toBeDefined();
    
    // Verify packet logs contain expected content
    expect(demonstration.packetLogs.attack1_text).toContain('MITM ATTACK');
    expect(demonstration.packetLogs.attack1_text).toContain('Packet #');
    expect(demonstration.packetLogs.attack2_text).toContain('MITM ATTACK');
    expect(demonstration.packetLogs.attack2_text).toContain('ATTACK_BLOCKED');
  }, 60000);

  test('Packet log export formats are valid', async () => {
    const sessionId = await generateSecureSessionId(aliceUserId, bobUserId);
    
    const aliceEphKeyPair = await generateEphemeralKeyPair();
    const bobEphKeyPair = await generateEphemeralKeyPair();
    
    const aliceEphPubJWK = await exportPublicKey(aliceEphKeyPair.publicKey);
    const bobEphPubJWK = await exportPublicKey(bobEphKeyPair.publicKey);
    
    clearAttackLogs();
    
    await attackUnsignedDH(
      sessionId,
      aliceEphPubJWK,
      bobEphPubJWK,
      aliceUserId,
      bobUserId
    );
    
    // Export text format
    const textLog = exportPacketLog('text');
    expect(textLog).toBeDefined();
    expect(textLog).toContain('MITM ATTACK PACKET CAPTURE');
    expect(textLog).toContain('Packet #');
    expect(textLog).toContain('Direction:');
    expect(textLog).toContain('Type:');
    
    // Export JSON format
    const jsonLog = exportPacketLog('json');
    expect(jsonLog).toBeDefined();
    
    const parsed = JSON.parse(jsonLog);
    expect(parsed.attackType).toBe('MITM');
    expect(parsed.packets).toBeDefined();
    expect(Array.isArray(parsed.packets)).toBe(true);
    expect(parsed.evidence).toBeDefined();
  }, 30000);

  test('Demonstration report export is valid', async () => {
    const demonstration = await runMITMDemonstration(aliceUserId, bobUserId, password);
    
    const report = exportDemonstrationReport(demonstration.results);
    expect(report).toBeDefined();
    
    const parsed = JSON.parse(report);
    expect(parsed.title).toBe('MITM Attack Demonstration Report');
    expect(parsed.executiveSummary).toBeDefined();
    expect(parsed.attack1_unsigned).toBeDefined();
    expect(parsed.attack2_signed).toBeDefined();
    expect(parsed.mitigation).toBeDefined();
    
    // Verify executive summary
    expect(parsed.executiveSummary.unsignedVulnerable).toBe(true);
    expect(parsed.executiveSummary.signedProtected).toBe(true);
  }, 60000);
});

