/**
 * Password Validation Utility
 * Centralized password validation with comprehensive rules
 */

/**
 * Validates password strength
 * Requirements:
 * - At least 8 characters
 * - At least one uppercase letter (A-Z)
 * - At least one lowercase letter (a-z)
 * - At least one number (0-9)
 * - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
 * 
 * @param {string} password - Password to validate
 * @returns {{valid: boolean, errors: string[]}} Validation result
 */
export function validatePassword(password) {
  const errors = [];

  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'] };
  }

  // Minimum length
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }

  // Uppercase letter
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter (A-Z)');
  }

  // Lowercase letter
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter (a-z)');
  }

  // Number
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number (0-9)');
  }

  // Special character
  if (!/[^A-Za-z0-9]/.test(password)) {
    errors.push('Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Gets password strength score (0-4)
 * @param {string} password - Password to score
 * @returns {number} Strength score (0 = weak, 4 = very strong)
 */
export function getPasswordStrength(password) {
  if (!password) return 0;

  let score = 0;

  // Length check
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;

  // Character variety
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  // Cap at 4
  return Math.min(score, 4);
}

/**
 * Express-validator compatible password validation
 * Can be used as middleware
 */
export const passwordValidationMiddleware = (req, res, next) => {
  const { password } = req.body;
  const validation = validatePassword(password);

  if (!validation.valid) {
    return res.status(400).json({
      success: false,
      error: 'Password validation failed',
      errors: validation.errors
    });
  }

  next();
};

