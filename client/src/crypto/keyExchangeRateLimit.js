/**
 * Client-Side Key Exchange Rate Limiting
 * Prevents resource exhaustion from excessive key exchange operations
 */

const MAX_KEY_EXCHANGES_PER_MINUTE = 5; // Maximum key exchanges per minute
const MAX_KEY_EXCHANGES_PER_HOUR = 20; // Maximum key exchanges per hour

const rateLimitStore = {
  perMinute: new Map(), // sessionId -> { count, resetAt }
  perHour: new Map()    // sessionId -> { count, resetAt }
};

/**
 * Checks if a key exchange is allowed for the given session
 * @param {string} sessionId - Session ID
 * @returns {Promise<{allowed: boolean, reason?: string}>}
 */
export async function checkKeyExchangeRateLimit(sessionId) {
  const now = Date.now();
  const minuteWindow = 60 * 1000; // 1 minute
  const hourWindow = 60 * 60 * 1000; // 1 hour

  // Check per-minute limit
  const minuteLimit = rateLimitStore.perMinute.get(sessionId) || { count: 0, resetAt: now + minuteWindow };
  if (now > minuteLimit.resetAt) {
    minuteLimit.count = 0;
    minuteLimit.resetAt = now + minuteWindow;
  }
  if (minuteLimit.count >= MAX_KEY_EXCHANGES_PER_MINUTE) {
    return {
      allowed: false,
      reason: `Key exchange rate limit exceeded: Maximum ${MAX_KEY_EXCHANGES_PER_MINUTE} exchanges per minute`
    };
  }
  minuteLimit.count++;
  rateLimitStore.perMinute.set(sessionId, minuteLimit);

  // Check per-hour limit
  const hourLimit = rateLimitStore.perHour.get(sessionId) || { count: 0, resetAt: now + hourWindow };
  if (now > hourLimit.resetAt) {
    hourLimit.count = 0;
    hourLimit.resetAt = now + hourWindow;
  }
  if (hourLimit.count >= MAX_KEY_EXCHANGES_PER_HOUR) {
    return {
      allowed: false,
      reason: `Key exchange rate limit exceeded: Maximum ${MAX_KEY_EXCHANGES_PER_HOUR} exchanges per hour`
    };
  }
  hourLimit.count++;
  rateLimitStore.perHour.set(sessionId, hourLimit);

  return { allowed: true };
}

/**
 * Resets rate limit for a session (useful for testing or manual reset)
 * @param {string} sessionId - Session ID
 */
export function resetKeyExchangeRateLimit(sessionId) {
  rateLimitStore.perMinute.delete(sessionId);
  rateLimitStore.perHour.delete(sessionId);
}

