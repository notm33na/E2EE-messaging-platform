/**
 * E2EE Key Generation Tests
 * 
 * Tests identity key creation (ECDSA P-256), ephemeral key creation (ECDH P-256),
 * password-derived encryption for private key storage, and retrieval from IndexedDB.
 */

import { generateIdentityKeyPair, storePrivateKeyEncrypted, loadPrivateKey, exportPublicKey, hasIdentityKey, deleteIdentityKey } from '../../src/crypto/identityKeys.js';
import { generateEphemeralKeyPair, exportPublicKey as exportEphPublicKey } from '../../src/crypto/ecdh.js';
import { clearIndexedDB, generateTestUser, cryptoKeysEqual, ensureNoPlaintext } from './testHelpers.js';

describe('E2EE Key Generation Tests', () => {
  let testUser;

  beforeEach(async () => {
    // Clear IndexedDB before each test
    await clearIndexedDB();
    testUser = generateTestUser('testuser');
  });

  afterEach(async () => {
    // Clean up after each test
    try {
      await deleteIdentityKey(testUser.userId);
    } catch (error) {
      // Ignore if key doesn't exist
    }
    await clearIndexedDB();
  });

  describe('Identity Key Generation (ECDSA P-256)', () => {
    test('should generate identity key pair with correct algorithm', async () => {
      const { privateKey, publicKey } = await generateIdentityKeyPair();

      expect(privateKey).toBeDefined();
      expect(publicKey).toBeDefined();
      expect(privateKey.algorithm.name).toBe('ECDSA');
      expect(privateKey.algorithm.namedCurve).toBe('P-256');
      expect(publicKey.algorithm.name).toBe('ECDSA');
      expect(publicKey.algorithm.namedCurve).toBe('P-256');
    });

    test('should generate extractable keys', async () => {
      const { privateKey, publicKey } = await generateIdentityKeyPair();

      // Keys should be extractable for storage
      expect(privateKey.extractable).toBe(true);
      expect(publicKey.extractable).toBe(true);
    });

    test('should generate keys with correct usages', async () => {
      const { privateKey, publicKey } = await generateIdentityKeyPair();

      expect(privateKey.usages).toContain('sign');
      expect(publicKey.usages).toContain('verify');
    });

    test('should generate unique key pairs on each call', async () => {
      const keyPair1 = await generateIdentityKeyPair();
      const keyPair2 = await generateIdentityKeyPair();

      // Public keys should be different
      const pubKey1JWK = await exportPublicKey(keyPair1.publicKey);
      const pubKey2JWK = await exportPublicKey(keyPair2.publicKey);

      expect(pubKey1JWK.x).not.toBe(pubKey2JWK.x);
      expect(pubKey1JWK.y).not.toBe(pubKey2JWK.y);
    });

    test('should export public key in JWK format', async () => {
      const { publicKey } = await generateIdentityKeyPair();
      const jwk = await exportPublicKey(publicKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
      expect(jwk.d).toBeUndefined(); // Private key component should not be in public key
    });
  });

  describe('Ephemeral Key Generation (ECDH P-256)', () => {
    test('should generate ephemeral key pair with correct algorithm', async () => {
      const { privateKey, publicKey } = await generateEphemeralKeyPair();

      expect(privateKey).toBeDefined();
      expect(publicKey).toBeDefined();
      expect(privateKey.algorithm.name).toBe('ECDH');
      expect(privateKey.algorithm.namedCurve).toBe('P-256');
      expect(publicKey.algorithm.name).toBe('ECDH');
      expect(publicKey.algorithm.namedCurve).toBe('P-256');
    });

    test('should generate extractable ephemeral keys', async () => {
      const { privateKey, publicKey } = await generateEphemeralKeyPair();

      expect(privateKey.extractable).toBe(true);
      expect(publicKey.extractable).toBe(true);
    });

    test('should generate keys with correct usages', async () => {
      const { privateKey, publicKey } = await generateEphemeralKeyPair();

      expect(privateKey.usages).toContain('deriveKey');
      expect(privateKey.usages).toContain('deriveBits');
    });

    test('should generate unique ephemeral key pairs on each call', async () => {
      const keyPair1 = await generateEphemeralKeyPair();
      const keyPair2 = await generateEphemeralKeyPair();

      const pubKey1JWK = await exportEphPublicKey(keyPair1.publicKey);
      const pubKey2JWK = await exportEphPublicKey(keyPair2.publicKey);

      expect(pubKey1JWK.x).not.toBe(pubKey2JWK.x);
      expect(pubKey1JWK.y).not.toBe(pubKey2JWK.y);
    });

    test('should export ephemeral public key in JWK format', async () => {
      const { publicKey } = await generateEphemeralKeyPair();
      const jwk = await exportEphPublicKey(publicKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
      expect(jwk.d).toBeUndefined(); // Private key component should not be in public key
    });
  });

  describe('Password-Derived Encryption for Private Key Storage', () => {
    test('should store private key encrypted with password', async () => {
      const { privateKey } = await generateIdentityKeyPair();
      
      await storePrivateKeyEncrypted(testUser.userId, privateKey, testUser.password);

      // Verify key was stored
      const hasKey = await hasIdentityKey(testUser.userId);
      expect(hasKey).toBe(true);
    });

    test('should retrieve and decrypt private key with correct password', async () => {
      const { privateKey: originalKey } = await generateIdentityKeyPair();
      
      await storePrivateKeyEncrypted(testUser.userId, originalKey, testUser.password);
      const loadedKey = await loadPrivateKey(testUser.userId, testUser.password);

      // Keys should be functionally equivalent
      const keysEqual = await cryptoKeysEqual(originalKey, loadedKey);
      expect(keysEqual).toBe(true);
    });

    test('should fail to decrypt with incorrect password', async () => {
      const { privateKey } = await generateIdentityKeyPair();
      
      await storePrivateKeyEncrypted(testUser.userId, privateKey, testUser.password);

      await expect(
        loadPrivateKey(testUser.userId, 'wrong-password')
      ).rejects.toThrow();
    });

    test('should store encrypted private key without plaintext in IndexedDB', async () => {
      const { privateKey } = await generateIdentityKeyPair();
      const originalJWK = await crypto.subtle.exportKey('jwk', privateKey);
      const originalJWKString = JSON.stringify(originalJWK);
      
      await storePrivateKeyEncrypted(testUser.userId, privateKey, testUser.password);

      // Verify IndexedDB doesn't contain plaintext
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('InfosecCryptoDB', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });

      const transaction = db.transaction(['identityKeys'], 'readonly');
      const store = transaction.objectStore('identityKeys');
      const stored = await new Promise((resolve, reject) => {
        const request = store.get(testUser.userId);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });

      expect(stored).toBeDefined();
      expect(stored.encryptedData).toBeDefined();
      
      // Verify plaintext JWK is not in stored data
      const storedString = JSON.stringify(stored);
      expect(ensureNoPlaintext(storedString, originalJWKString)).toBe(true);
    });

    test('should use different IVs for each encryption', async () => {
      const { privateKey } = await generateIdentityKeyPair();
      
      await storePrivateKeyEncrypted(testUser.userId, privateKey, testUser.password);
      
      // Delete and store again
      await deleteIdentityKey(testUser.userId);
      await storePrivateKeyEncrypted(testUser.userId, privateKey, testUser.password);

      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('InfosecCryptoDB', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });

      const transaction = db.transaction(['identityKeys'], 'readonly');
      const store = transaction.objectStore('identityKeys');
      const stored = await new Promise((resolve, reject) => {
        const request = store.get(testUser.userId);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });

      expect(stored.iv).toBeDefined();
      expect(stored.iv.length).toBe(12); // 96 bits = 12 bytes
    });
  });

  describe('IndexedDB Retrieval', () => {
    test('should check if identity key exists', async () => {
      expect(await hasIdentityKey(testUser.userId)).toBe(false);

      const { privateKey } = await generateIdentityKeyPair();
      await storePrivateKeyEncrypted(testUser.userId, privateKey, testUser.password);

      expect(await hasIdentityKey(testUser.userId)).toBe(true);
    });

    test('should load private key from IndexedDB', async () => {
      const { privateKey: originalKey } = await generateIdentityKeyPair();
      await storePrivateKeyEncrypted(testUser.userId, originalKey, testUser.password);

      const loadedKey = await loadPrivateKey(testUser.userId, testUser.password);
      expect(loadedKey).toBeDefined();
      expect(loadedKey.algorithm.name).toBe('ECDSA');
      expect(loadedKey.algorithm.namedCurve).toBe('P-256');
    });

    test('should throw error when loading non-existent key', async () => {
      await expect(
        loadPrivateKey(testUser.userId, testUser.password)
      ).rejects.toThrow('Private key not found');
    });
  });
});
