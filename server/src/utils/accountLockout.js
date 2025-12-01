/**
 * Account Lockout Utility
 * Implements account lockout after failed authentication attempts
 * to protect against brute-force attacks on encrypted keys
 */

const MAX_FAILED_ATTEMPTS = 5; // Maximum failed attempts before lockout
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes lockout duration

// In-memory store for failed attempts (in production, use Redis or database)
const failedAttempts = new Map(); // userId -> { count: number, lockoutUntil: number }

/**
 * Records a failed authentication attempt
 * @param {string} userId - User ID
 * @returns {{locked: boolean, remainingAttempts: number, lockoutUntil?: number}}
 */
export function recordFailedAttempt(userId) {
  const now = Date.now();
  const userAttempts = failedAttempts.get(userId) || { count: 0, lockoutUntil: 0 };

  // Check if account is currently locked
  if (userAttempts.lockoutUntil > now) {
    return {
      locked: true,
      remainingAttempts: 0,
      lockoutUntil: userAttempts.lockoutUntil
    };
  }

  // Reset if lockout period has passed
  if (userAttempts.lockoutUntil > 0 && userAttempts.lockoutUntil <= now) {
    userAttempts.count = 0;
    userAttempts.lockoutUntil = 0;
  }

  // Increment failed attempts
  userAttempts.count++;
  
  // Lock account if threshold exceeded
  if (userAttempts.count >= MAX_FAILED_ATTEMPTS) {
    userAttempts.lockoutUntil = now + LOCKOUT_DURATION;
    failedAttempts.set(userId, userAttempts);
    return {
      locked: true,
      remainingAttempts: 0,
      lockoutUntil: userAttempts.lockoutUntil
    };
  }

  failedAttempts.set(userId, userAttempts);
  return {
    locked: false,
    remainingAttempts: MAX_FAILED_ATTEMPTS - userAttempts.count,
    lockoutUntil: undefined
  };
}

/**
 * Clears failed attempts for a user (on successful authentication)
 * @param {string} userId - User ID
 */
export function clearFailedAttempts(userId) {
  failedAttempts.delete(userId);
}

/**
 * Checks if an account is locked
 * @param {string} userId - User ID
 * @returns {{locked: boolean, lockoutUntil?: number}}
 */
export function isAccountLocked(userId) {
  const userAttempts = failedAttempts.get(userId);
  if (!userAttempts) {
    return { locked: false };
  }

  const now = Date.now();
  if (userAttempts.lockoutUntil > now) {
    return {
      locked: true,
      lockoutUntil: userAttempts.lockoutUntil
    };
  }

  // Lockout period expired, clear it
  if (userAttempts.lockoutUntil > 0) {
    failedAttempts.delete(userId);
  }

  return { locked: false };
}

/**
 * Gets remaining attempts before lockout
 * @param {string} userId - User ID
 * @returns {number} Remaining attempts
 */
export function getRemainingAttempts(userId) {
  const userAttempts = failedAttempts.get(userId);
  if (!userAttempts) {
    return MAX_FAILED_ATTEMPTS;
  }

  const now = Date.now();
  if (userAttempts.lockoutUntil > now) {
    return 0; // Account is locked
  }

  return Math.max(0, MAX_FAILED_ATTEMPTS - userAttempts.count);
}

