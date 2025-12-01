/**
 * Key Exchange Protocol Summary Tests
 * Simulates two users performing the KEP metadata flow and verifies storage constraints.
 */

import { PublicKey } from '../src/models/PublicKey.js';
import { KEPMessage } from '../src/models/KEPMessage.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestJWK, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Key Exchange Protocol Summary Tests', () => {
  let userA;
  let userB;

  beforeAll(async () => {
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
    const userDataA = generateTestUser();
    const userDataB = generateTestUser();
    userA = await userService.createUser(userDataA.email, userDataA.password);
    userB = await userService.createUser(userDataB.email, userDataB.password);
  });

  test('stores only public keys and metadata for both parties', async () => {
    const jwkA = generateTestJWK();
    const jwkB = generateTestJWK();

    await new PublicKey({ userId: userA.id, publicIdentityKeyJWK: jwkA }).save();
    await new PublicKey({ userId: userB.id, publicIdentityKeyJWK: jwkB }).save();

    const storedA = await PublicKey.findOne({ userId: userA.id });
    const storedB = await PublicKey.findOne({ userId: userB.id });

    expect(storedA.publicIdentityKeyJWK.d).toBeUndefined();
    expect(storedB.publicIdentityKeyJWK.d).toBeUndefined();
  });

  test('simulates KEP_INIT and KEP_RESPONSE metadata exchange', async () => {
    const now = Date.now();

    const kepInit = new KEPMessage({
      messageId: 'kep-init-1',
      sessionId: 'session-1',
      from: userA.id,
      to: userB.id,
      type: 'KEP_INIT',
      timestamp: now,
      seq: 1
    });
    await kepInit.save();

    const kepResponse = new KEPMessage({
      messageId: 'kep-resp-1',
      sessionId: 'session-1',
      from: userB.id,
      to: userA.id,
      type: 'KEP_RESPONSE',
      timestamp: now + 1,
      seq: 2
    });
    await kepResponse.save();

    const storedInit = await KEPMessage.findOne({ messageId: 'kep-init-1' });
    const storedResp = await KEPMessage.findOne({ messageId: 'kep-resp-1' });

    expect(storedInit.type).toBe('KEP_INIT');
    expect(storedResp.type).toBe('KEP_RESPONSE');
    expect(storedInit.sessionId).toBe('session-1');
    expect(storedResp.sessionId).toBe('session-1');
  });

  test('does not persist signatures or key material in KEP messages', async () => {
    const kep = new KEPMessage({
      messageId: 'kep-init-2',
      sessionId: 'session-2',
      from: userA.id,
      to: userB.id,
      type: 'KEP_INIT',
      timestamp: Date.now(),
      seq: 1
    });
    await kep.save();

    const stored = await KEPMessage.findOne({ messageId: 'kep-init-2' });
    const obj = stored.toObject();

    expect(obj.signature).toBeUndefined();
    expect(obj.privateKey).toBeUndefined();
    expect(obj.ephemeralPrivateKey).toBeUndefined();
  });
});


