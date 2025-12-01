/**
 * Authentication Tests
 * Tests user registration, login, password hashing, and token operations
 */

// Jest globals are available in test environment
import bcrypt from 'bcrypt';
import { User } from '../src/models/User.js';
import { userService } from '../src/services/user.service.js';
import { generateAccessToken, generateRefreshToken, verifyToken } from '../src/utils/jwt.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';

describe('Authentication Tests', () => {
  beforeAll(async () => {
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
  });

  describe('User Registration', () => {
    test('should register a new user successfully', async () => {
      const userData = generateTestUser();
      const user = await userService.createUser(userData.email, userData.password);

      expect(user).toBeDefined();
      expect(user.email).toBe(userData.email);
      expect(user.id).toBeDefined();
      expect(user.passwordHash).toBeUndefined(); // Should not be in response
    });

    test('should hash password with bcrypt', async () => {
      const userData = generateTestUser();
      const user = await userService.createUser(userData.email, userData.password);

      // Fetch user with password hash
      const dbUser = await userService.getUserByEmail(userData.email, true);
      expect(dbUser.passwordHash).toBeDefined();
      expect(dbUser.passwordHash).not.toBe(userData.password); // Should be hashed

      // Verify password hash
      const isValid = await bcrypt.compare(userData.password, dbUser.passwordHash);
      expect(isValid).toBe(true);
    });

    test('should reject duplicate email registration', async () => {
      const userData = generateTestUser();
      await userService.createUser(userData.email, userData.password);

      await expect(
        userService.createUser(userData.email, 'DifferentPassword123!')
      ).rejects.toThrow();
    });

    test('should NOT store plaintext passwords', async () => {
      const userData = generateTestUser();
      await userService.createUser(userData.email, userData.password);

      const dbUser = await User.findOne({ email: userData.email }).select('+passwordHash');
      expect(dbUser.passwordHash).not.toBe(userData.password);
      expect(dbUser.passwordHash.length).toBeGreaterThan(50); // bcrypt hash length
    });
  });

  describe('Password Hashing', () => {
    test('should use bcrypt with appropriate rounds', async () => {
      const userData = generateTestUser();
      await userService.createUser(userData.email, userData.password);

      const dbUser = await userService.getUserByEmail(userData.email, true);
      const hashInfo = dbUser.passwordHash.split('$');
      expect(hashInfo[1]).toBe('2b'); // bcrypt version
      expect(parseInt(hashInfo[2])).toBeGreaterThanOrEqual(10); // rounds
    });

    test('should verify password correctly', async () => {
      const userData = generateTestUser();
      await userService.createUser(userData.email, userData.password);

      const isValid = await userService.verifyPassword(userData.email, userData.password);
      expect(isValid).toBe(true);

      const isInvalid = await userService.verifyPassword(userData.email, 'WrongPassword123!');
      expect(isInvalid).toBe(false);
    });
  });

  describe('Token Operations', () => {
    test('should generate access token', () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';
      const token = generateAccessToken(userId, email);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3); // JWT has 3 parts
    });

    test('should generate refresh token', () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';
      const token = generateRefreshToken(userId, email);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3);
    });

    test('should verify valid token', () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';
      const token = generateAccessToken(userId, email);

      const decoded = verifyToken(token);
      expect(decoded.userId).toBe(userId);
      // Email removed from token payload for security (minimized payload)
      expect(decoded.type).toBe('access');
    });

    test('should reject invalid token', () => {
      const invalidToken = 'invalid.token.here';
      expect(() => verifyToken(invalidToken)).toThrow();
    });

    test('should reject tampered token', () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';
      const token = generateAccessToken(userId, email);
      const tamperedToken = token.slice(0, -5) + 'XXXXX';

      expect(() => verifyToken(tamperedToken)).toThrow();
    });
  });

  describe('User Service', () => {
    test('should return safe user object (no password hash)', async () => {
      const userData = generateTestUser();
      const user = await userService.createUser(userData.email, userData.password);

      expect(user.passwordHash).toBeUndefined();
      expect(user.refreshTokens).toBeUndefined();
      expect(user.email).toBeDefined();
      expect(user.id).toBeDefined();
    });

    test('should update last login timestamp', async () => {
      const userData = generateTestUser();
      const user = await userService.createUser(userData.email, userData.password);

      await userService.updateLastLogin(user.id);
      const updatedUser = await userService.getUserById(user.id);
      expect(updatedUser.lastLoginAt).toBeDefined();
      expect(updatedUser.lastLoginAt).toBeInstanceOf(Date);
    });
  });
});

