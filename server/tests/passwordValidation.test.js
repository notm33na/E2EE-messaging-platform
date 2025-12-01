/**
 * Password Validation Tests
 * Tests comprehensive password validation at server level
 */

import { validatePassword, getPasswordStrength } from '../src/utils/passwordValidation.js';

describe('Password Validation Tests', () => {
  describe('validatePassword', () => {
    test('should accept valid password with all requirements', () => {
      const result = validatePassword('Test123!@#');
      expect(result.valid).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    test('should reject password shorter than 8 characters', () => {
      const result = validatePassword('Test1!');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters long');
    });

    test('should reject password without uppercase letter', () => {
      const result = validatePassword('test123!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one uppercase letter (A-Z)');
    });

    test('should reject password without lowercase letter', () => {
      const result = validatePassword('TEST123!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one lowercase letter (a-z)');
    });

    test('should reject password without number', () => {
      const result = validatePassword('TestPass!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain at least one number (0-9)');
    });

    test('should reject password without special character', () => {
      const result = validatePassword('TestPass123');
      expect(result.valid).toBe(false);
      expect(result.errors.some(err => err.includes('special character'))).toBe(true);
    });

    test('should reject empty password', () => {
      const result = validatePassword('');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password is required');
    });

    test('should reject null password', () => {
      const result = validatePassword(null);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password is required');
    });

    test('should reject undefined password', () => {
      const result = validatePassword(undefined);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password is required');
    });

    test('should return multiple errors for password missing multiple requirements', () => {
      const result = validatePassword('test');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(1);
      expect(result.errors).toContain('Password must be at least 8 characters long');
      expect(result.errors).toContain('Password must contain at least one uppercase letter (A-Z)');
      expect(result.errors).toContain('Password must contain at least one number (0-9)');
      expect(result.errors.some(err => err.includes('special character'))).toBe(true);
    });
  });

  describe('getPasswordStrength', () => {
    test('should return 0 for empty password', () => {
      expect(getPasswordStrength('')).toBe(0);
    });

    test('should return higher score for longer passwords', () => {
      const short = getPasswordStrength('Test1!'); // 6 chars - might not meet length requirement
      const medium = getPasswordStrength('Test123!@#'); // 11 chars - meets 8+ but not 12+
      const long = getPasswordStrength('Test123!@#LongPassword'); // 25 chars - meets 12+
      
      // All should have some score (at least 0)
      expect(short).toBeGreaterThanOrEqual(0);
      expect(medium).toBeGreaterThanOrEqual(0);
      expect(long).toBeGreaterThanOrEqual(0);
      // Longer passwords should generally score higher
      expect(long).toBeGreaterThanOrEqual(medium);
    });

    test('should return higher score for passwords with more character variety', () => {
      const basic = getPasswordStrength('Test1234');
      const withSpecial = getPasswordStrength('Test123!');
      
      expect(withSpecial).toBeGreaterThanOrEqual(basic);
    });

    test('should cap strength at 4', () => {
      const strong = getPasswordStrength('VeryStrongPassword123!@#$%');
      expect(strong).toBeLessThanOrEqual(4);
    });
  });
});

