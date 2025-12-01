/**
 * Client-Side Password Validation Utility
 * Provides consistent password validation matching server-side rules
 */

/**
 * Validates password strength
 * Requirements:
 * - At least 8 characters
 * - At least one uppercase letter (A-Z)
 * - At least one lowercase letter (a-z)
 * - At least one number (0-9)
 * - At least one special character
 * 
 * @param {string} password - Password to validate
 * @returns {{valid: boolean, errors: string[], strength: number}} Validation result
 */
export function validatePassword(password) {
  const errors = [];

  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'], strength: 0 };
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

  // Calculate strength (0-4)
  let strength = 0;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) strength++;
  if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) strength++;
  strength = Math.min(strength, 4);

  return {
    valid: errors.length === 0,
    errors,
    strength
  };
}

/**
 * Gets password strength label
 * @param {number} strength - Strength score (0-4)
 * @returns {string} Strength label
 */
export function getPasswordStrengthLabel(strength) {
  const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
  return labels[Math.min(strength, 4)] || 'Unknown';
}

/**
 * Gets password strength color for UI
 * @param {number} strength - Strength score (0-4)
 * @returns {string} Color class or hex
 */
export function getPasswordStrengthColor(strength) {
  const colors = ['#ff0000', '#ff6600', '#ffaa00', '#88cc00', '#00aa00'];
  return colors[Math.min(strength, 4)] || '#cccccc';
}

