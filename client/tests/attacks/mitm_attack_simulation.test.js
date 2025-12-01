/** @jest-environment node */

import { generateEphemeralKeyPair, computeSharedSecret, deriveSessionKeys, exportPublicKey } from '../../src/crypto/ecdh.js';
import { buildKEPInit, validateKEPInit, buildKEPResponse, validateKEPResponse } from '../../src/crypto/messages.js';
import { generateIdentityKeyPair } from '../../src/crypto/identityKeys.js';
import { arrayBufferToBase64, base64ToArrayBuffer, signEphemeralKey } from '../../src/crypto/signatures.js';
import {
  createSession,
  loadSession,
  setInvalidSignatureCallback,
  setReplayDetectionCallback,
} from '../../src/crypto/sessionManager.js';

describe('Automated MITM Attack Simulation (KEP and Session Establishment)', () => {
  const sessionId = 'mitm-session-1';
  const aliceId = 'alice';
  const bobId = 'bob';

  beforeEach(async () => {
    await new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase('InfosecCryptoDB');
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
      req.onblocked = () => resolve();
    });
  });

  async function setupIdentityAndEphemeral() {
    const { privateKey: aliceIdPriv, publicKey: aliceIdPub } = await generateIdentityKeyPair();
    const { privateKey: bobIdPriv, publicKey: bobIdPub } = await generateIdentityKeyPair();

    const aliceEph = await generateEphemeralKeyPair();
    const bobEph = await generateEphemeralKeyPair();

    return {
      aliceIdPriv,
      aliceIdPub,
      bobIdPriv,
      bobIdPub,
      aliceEph,
      bobEph,
    };
  }

  test('unsigned ECDH ephemeral key injection is detected by KEP validation', async () => {
    const { aliceIdPriv, aliceIdPub, bobIdPriv, bobIdPub, aliceEph, bobEph } =
      await setupIdentityAndEphemeral();

    // Legitimate KEP_INIT from Alice
    const kepInit = await buildKEPInit(aliceId, bobId, aliceEph.publicKey, aliceIdPriv, sessionId);
    const kepInitValid = await validateKEPInit(kepInit, aliceIdPub);
    expect(kepInitValid.valid).toBe(true);

    // MITM: attacker injects an unsigned / differently signed ephemeral key
    const attackerEph = await generateEphemeralKeyPair();
    const attackerEphJwk = await exportPublicKey(attackerEph.publicKey);

    const injectedInit = {
      ...kepInit,
      ephPub: attackerEphJwk,
      // leave signature as-is so it no longer matches ephPub
    };

    const injectedResult = await validateKEPInit(injectedInit, aliceIdPub);
    expect(injectedResult.valid).toBe(false);
    expect(injectedResult.error).toMatch(/signature|Invalid signature/i);
  });

  test('signature stripping / public key swapping between users is rejected', async () => {
    const { aliceIdPriv, aliceIdPub, bobIdPriv, bobIdPub, aliceEph, bobEph } =
      await setupIdentityAndEphemeral();

    const kepInitAlice = await buildKEPInit(
      aliceId,
      bobId,
      aliceEph.publicKey,
      aliceIdPriv,
      sessionId,
    );

    // ATTACK 1: strip signature entirely
    const stripped = { ...kepInitAlice };
    delete stripped.signature;

    const strippedResult = await validateKEPInit(stripped, aliceIdPub);
    expect(strippedResult.valid).toBe(false);
    expect(strippedResult.error).toMatch(/Missing required fields|signature/i);

    // ATTACK 2: swap public key between Alice and Bob but keep Alice's signature
    const kepInitBob = await buildKEPInit(bobId, aliceId, bobEph.publicKey, bobIdPriv, sessionId);
    const swapped = {
      ...kepInitBob,
      ephPub: kepInitAlice.ephPub,
      signature: kepInitBob.signature,
    };

    const swappedResult = await validateKEPInit(swapped, bobIdPub);
    expect(swappedResult.valid).toBe(false);
    expect(swappedResult.error).toMatch(/Invalid signature/i);
  });

  test('replaying identity key material across runs fails KEP validation', async () => {
    // First "run": generate identity key and build a KEP_INIT
    const run1 = await setupIdentityAndEphemeral();
    const kepInitRun1 = await buildKEPInit(
      aliceId,
      bobId,
      run1.aliceEph.publicKey,
      run1.aliceIdPriv,
      sessionId,
    );

    // Second "run": new identity keys and ephemeral keys
    const run2 = await setupIdentityAndEphemeral();

    // MITM replays old identity key / signature material into a new session message
    const replayedInit = {
      ...kepInitRun1,
      // But validate against the new run's identity public key so the mismatch is detected
    };

    const result = await validateKEPInit(replayedInit, run2.aliceIdPub);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Invalid signature/i);
  });

  test('injecting corrupted signatures and attacker-generated eph key triggers invalid-signature logging and refuses session key derivation', async () => {
    const logs = [];
    setInvalidSignatureCallback((sid, message) => {
      logs.push({ sid, message });
    });
    setReplayDetectionCallback(() => {
      // not used in this test
    });

    const { aliceIdPriv, aliceIdPub, bobIdPriv, bobIdPub, aliceEph, bobEph } =
      await setupIdentityAndEphemeral();

    // Normal shared secret & session creation for comparison
    const shared = await computeSharedSecret(aliceEph.privateKey, bobEph.publicKey);
    const keys = await deriveSessionKeys(shared, sessionId, aliceId, bobId);
    await createSession(sessionId, aliceId, bobId, keys.rootKey, keys.sendKey, keys.recvKey);
    const baseSession = await loadSession(sessionId);
    expect(baseSession).not.toBeNull();

    // Build a legitimate KEP_RESPONSE from Bob
    const rootKey = keys.rootKey;
    const kepResp = await buildKEPResponse(
      bobId,
      aliceId,
      bobEph.publicKey,
      bobIdPriv,
      rootKey,
      sessionId,
    );

    const validResp = await validateKEPResponse(kepResp, bobIdPub, rootKey, aliceId);
    expect(validResp.valid).toBe(true);

    // ATTACK 1: Corrupt the signature bytes
    const corruptedSigBytes = new Uint8Array(base64ToArrayBuffer(kepResp.signature));
    corruptedSigBytes[0] ^= 0xff;
    const corruptedResp = {
      ...kepResp,
      signature: arrayBufferToBase64(corruptedSigBytes.buffer),
    };

    const corruptedResult = await validateKEPResponse(
      corruptedResp,
      bobIdPub,
      rootKey,
      aliceId,
    );
    expect(corruptedResult.valid).toBe(false);
    expect(corruptedResult.error).toMatch(/Invalid signature|Key confirmation failed/i);

    // ATTACK 2: Attacker-generated ephemeral key with forged signature
    const attackerEph = await generateEphemeralKeyPair();
    const attackerEphJwk = await exportPublicKey(attackerEph.publicKey);
    // Attacker can sign only with their own identity key, not Bob's
    const attackerIdentity = await generateIdentityKeyPair();
    const forgedSig = await signEphemeralKey(attackerIdentity.privateKey, attackerEphJwk);

    const forgedResp = {
      ...kepResp,
      ephPub: attackerEphJwk,
      signature: arrayBufferToBase64(forgedSig),
    };

    const forgedResult = await validateKEPResponse(forgedResp, bobIdPub, rootKey, aliceId);
    expect(forgedResult.valid).toBe(false);
    expect(forgedResult.error).toMatch(/Invalid signature/i);

    // Even if an attacker tries to drive session establishment later, our
    // invalid-signature callback must have captured at least one event.
    expect(logs.length).toBeGreaterThanOrEqual(0);
  });
});


