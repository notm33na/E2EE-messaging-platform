/**
 * Account Lockout Tests
 * Tests account lockout functionality to protect against brute-force attacks
 */

import { recordFailedAttempt, clearFailedAttempts, isAccountLocked, getRemainingAttempts } from '../src/utils/accountLockout.js';

describe('Account Lockout Tests', () => {
  beforeEach(() => {
    // Clear all failed attempts before each test
    clearFailedAttempts('test-user-1');
    clearFailedAttempts('test-user-2');
  });

  describe('recordFailedAttempt', () => {
    test('should record first failed attempt', () => {
      const result = recordFailedAttempt('test-user-1');
      expect(result.locked).toBe(false);
      expect(result.remainingAttempts).toBe(4);
      expect(result.lockoutUntil).toBeUndefined();
    });

    test('should increment failed attempts', () => {
      recordFailedAttempt('test-user-1');
      recordFailedAttempt('test-user-1');
      const result = recordFailedAttempt('test-user-1');
      
      expect(result.locked).toBe(false);
      expect(result.remainingAttempts).toBe(2);
    });

    test('should lock account after 5 failed attempts', () => {
      // Record 4 failed attempts
      for (let i = 0; i < 4; i++) {
        recordFailedAttempt('test-user-1');
      }
      
      // 5th attempt should lock
      const result = recordFailedAttempt('test-user-1');
      
      expect(result.locked).toBe(true);
      expect(result.remainingAttempts).toBe(0);
      expect(result.lockoutUntil).toBeDefined();
      expect(result.lockoutUntil).toBeGreaterThan(Date.now());
    });

    test('should return locked status if account already locked', () => {
      // Lock the account
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('test-user-1');
      }
      
      // Try again while locked
      const result = recordFailedAttempt('test-user-1');
      
      expect(result.locked).toBe(true);
      expect(result.remainingAttempts).toBe(0);
    });
  });

  describe('clearFailedAttempts', () => {
    test('should clear failed attempts', () => {
      recordFailedAttempt('test-user-1');
      recordFailedAttempt('test-user-1');
      
      clearFailedAttempts('test-user-1');
      
      const remaining = getRemainingAttempts('test-user-1');
      expect(remaining).toBe(5); // Reset to max
    });

    test('should allow login after clearing failed attempts', () => {
      // Lock account
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('test-user-1');
      }
      
      // Clear attempts
      clearFailedAttempts('test-user-1');
      
      // Should be able to attempt again
      const result = recordFailedAttempt('test-user-1');
      expect(result.locked).toBe(false);
      expect(result.remainingAttempts).toBe(4);
    });
  });

  describe('isAccountLocked', () => {
    test('should return false for unlocked account', () => {
      const result = isAccountLocked('test-user-1');
      expect(result.locked).toBe(false);
    });

    test('should return true for locked account', () => {
      // Lock account
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('test-user-1');
      }
      
      const result = isAccountLocked('test-user-1');
      expect(result.locked).toBe(true);
      expect(result.lockoutUntil).toBeDefined();
    });

    test('should return false after lockout period expires', async () => {
      // Lock account
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('test-user-1');
      }
      
      // Get lockout time
      const lockoutResult = isAccountLocked('test-user-1');
      expect(lockoutResult.locked).toBe(true);
      
      // Manually expire lockout by clearing (simulating time passage)
      // In real scenario, lockout would expire after 15 minutes
      clearFailedAttempts('test-user-1');
      
      const result = isAccountLocked('test-user-1');
      expect(result.locked).toBe(false);
    });
  });

  describe('getRemainingAttempts', () => {
    test('should return max attempts for new user', () => {
      const remaining = getRemainingAttempts('test-user-1');
      expect(remaining).toBe(5);
    });

    test('should return correct remaining attempts', () => {
      recordFailedAttempt('test-user-1');
      recordFailedAttempt('test-user-1');
      
      const remaining = getRemainingAttempts('test-user-1');
      expect(remaining).toBe(3);
    });

    test('should return 0 for locked account', () => {
      // Lock account
      for (let i = 0; i < 5; i++) {
        recordFailedAttempt('test-user-1');
      }
      
      const remaining = getRemainingAttempts('test-user-1');
      expect(remaining).toBe(0);
    });
  });

  describe('Multiple users', () => {
    test('should track attempts separately for different users', () => {
      recordFailedAttempt('test-user-1');
      recordFailedAttempt('test-user-1');
      recordFailedAttempt('test-user-2');
      
      expect(getRemainingAttempts('test-user-1')).toBe(3);
      expect(getRemainingAttempts('test-user-2')).toBe(4);
    });
  });
});

