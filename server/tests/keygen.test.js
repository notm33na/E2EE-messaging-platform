/**
 * Key Generation & Storage Tests
 * Verifies that only public keys are stored and private key material is rejected.
 */

import { PublicKey } from '../src/models/PublicKey.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestJWK, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Key Generation & Storage Tests', () => {
  let testUser;

  beforeAll(async () => {
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
    const userData = generateTestUser();
    testUser = await userService.createUser(userData.email, userData.password);
  });

  test('registration metadata contains only approved user fields', async () => {
    const userInDb = await userService.getUserByEmail(testUser.email);

    const userObj = userInDb.toObject();
    const allowedUserFields = ['_id', 'email', 'lastLoginAt', 'isActive', 'createdAt', 'updatedAt', '__v'];

    Object.keys(userObj).forEach(field => {
      expect(allowedUserFields).toContain(field);
    });
    // Ensure no password or key material fields are ever exposed
    expect(userObj.password).toBeUndefined();
    expect(userObj.passwordHash).toBeUndefined();
    expect(userObj.privateKey).toBeUndefined();
  });

  test('backend does NOT store private key component when saving PublicKey', async () => {
    const jwk = {
      ...generateTestJWK(),
      d: 'private-key-component-should-be-stripped'
    };

    // Direct model usage enforces schema validation & pre-save hook
    const publicKey = new PublicKey({
      userId: testUser.id,
      publicIdentityKeyJWK: jwk
    });

    await expect(publicKey.save()).rejects.toThrow(
      /Invalid JWK structure/i
    );
  });

  test('public key records contain only non-secret JWK fields', async () => {
    const jwk = generateTestJWK();
    const publicKey = new PublicKey({
      userId: testUser.id,
      publicIdentityKeyJWK: jwk
    });
    await publicKey.save();

    const stored = await PublicKey.findOne({ userId: testUser.id });
    expect(stored).toBeDefined();

    const jwkStored = stored.publicIdentityKeyJWK;
    const allowedJwkFields = ['kty', 'crv', 'x', 'y'];

    Object.keys(jwkStored).forEach(field => {
      expect(allowedJwkFields).toContain(field);
    });
    expect(jwkStored.d).toBeUndefined();
  });
});


