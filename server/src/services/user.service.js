import bcrypt from 'bcrypt';
import { User } from '../models/User.js';

/**
 * User Service
 * Handles all user-related business logic
 */
class UserService {
  /**
   * Creates a new user
   * @param {string} email - User email
   * @param {string} password - Plain text password
   * @returns {Promise<Object>} Created user object (sanitized)
   */
  async createUser(email, password) {
    // Validate password strength
    const { validatePassword } = await import('../utils/passwordValidation.js');
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      const error = new Error(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
      error.name = 'PasswordValidationError';
      error.errors = passwordValidation.errors;
      throw error;
    }

    // Check if user already exists
    const existingUser = await this.getUserByEmail(email);
    if (existingUser) {
      const error = new Error('User with this email already exists');
      error.name = 'DuplicateUserError';
      throw error;
    }

    // Hash password with bcrypt (12 rounds - increased from 10 for better security)
    const passwordHash = await bcrypt.hash(password, 12);

    const user = new User({
      email,
      passwordHash,
      isActive: true
    });

    try {
      await user.save();
    } catch (error) {
      // Handle duplicate key error from MongoDB
      if (error.code === 11000) {
        const duplicateError = new Error('User with this email already exists');
        duplicateError.name = 'DuplicateUserError';
        throw duplicateError;
      }
      throw error;
    }
    return this.safeUser(user);
  }

  /**
   * Gets user by email
   * @param {string} email - User email
   * @param {boolean} includePassword - Include password hash in result
   * @returns {Promise<Object|null>} User object or null
   */
  async getUserByEmail(email, includePassword = false) {
    const selectFields = includePassword ? '+passwordHash' : '';
    return await User.findOne({ email }).select(selectFields);
  }

  /**
   * Gets user by ID
   * @param {string} userId - User ID
   * @returns {Promise<Object|null>} User object or null
   */
  async getUserById(userId) {
    return await User.findById(userId);
  }

  /**
   * Updates user's last login timestamp
   * @param {string} userId - User ID
   * @returns {Promise<void>}
   */
  async updateLastLogin(userId) {
    await User.findByIdAndUpdate(userId, {
      lastLoginAt: new Date()
    });
  }

  /**
   * Adds a refresh token to user's token list
   * @param {string} userId - User ID
   * @param {string} token - Refresh token
   * @param {string} userAgent - User agent string
   * @param {string} ip - IP address
   * @returns {Promise<void>}
   */
  async addRefreshToken(userId, token, userAgent = '', ip = '') {
    await User.findByIdAndUpdate(
      userId,
      {
        $push: {
          refreshTokens: {
            token,
            createdAt: new Date(),
            userAgent,
            ip
          }
        }
      },
      { new: true }
    );
  }

  /**
   * Removes a refresh token from user's token list
   * @param {string} userId - User ID
   * @param {string} token - Refresh token to remove
   * @returns {Promise<void>}
   */
  async removeRefreshToken(userId, token) {
    await User.findByIdAndUpdate(
      userId,
      {
        $pull: {
          refreshTokens: { token }
        }
      }
    );
  }

  /**
   * Revokes all refresh tokens for a user
   * @param {string} userId - User ID
   * @returns {Promise<void>}
   */
  async revokeAllRefreshTokens(userId) {
    await User.findByIdAndUpdate(userId, {
      $set: { refreshTokens: [] }
    });
  }

  /**
   * Checks if a refresh token exists for a user
   * @param {string} userId - User ID
   * @param {string} token - Refresh token
   * @returns {Promise<boolean>} True if token exists
   */
  async hasRefreshToken(userId, token) {
    const user = await User.findOne({
      _id: userId,
      'refreshTokens.token': token
    }).select('+refreshTokens');

    return !!user;
  }

  /**
   * Verifies a password for a user by email
   * @param {string} email - User email
   * @param {string} password - Plain text password
   * @returns {Promise<boolean>} True if password matches
   */
  async verifyPassword(email, password) {
    const user = await this.getUserByEmail(email, true);
    if (!user || !user.passwordHash) {
      return false;
    }
    return await bcrypt.compare(password, user.passwordHash);
  }

  /**
   * Returns a sanitized user object (no sensitive data)
   * @param {Object} user - Mongoose user document
   * @returns {Object} Sanitized user object
   */
  safeUser(user) {
    if (!user) return null;

    const userObj = user.toObject ? user.toObject() : user;
    
    return {
      id: userObj._id.toString(),
      email: userObj.email,
      createdAt: userObj.createdAt,
      updatedAt: userObj.updatedAt,
      lastLoginAt: userObj.lastLoginAt,
      isActive: userObj.isActive
    };
  }

  /**
   * Deactivates a user account
   * @param {string} userId - User ID
   * @returns {Promise<void>}
   */
  async deactivateUser(userId) {
    await User.findByIdAndUpdate(userId, {
      isActive: false
    });
  }

  /**
   * Reactivates a user account
   * @param {string} userId - User ID
   * @returns {Promise<void>}
   */
  async reactivateUser(userId) {
    await User.findByIdAndUpdate(userId, {
      isActive: true
    });
  }
}

export const userService = new UserService();

