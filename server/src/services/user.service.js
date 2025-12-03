import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
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
    // Normalize email to lowercase and trim (matching schema behavior)
    const normalizedEmail = email ? email.trim().toLowerCase() : email;
    const selectFields = includePassword ? '+passwordHash' : '';
    return await User.findOne({ email: normalizedEmail }).select(selectFields);
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

  /**
   * Changes user password
   * @param {string} userId - User ID
   * @param {string} oldPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<void>}
   */
  async changePassword(userId, oldPassword, newPassword) {
    // Validate new password strength
    const { validatePassword } = await import('../utils/passwordValidation.js');
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) {
      const error = new Error(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
      error.name = 'PasswordValidationError';
      error.errors = passwordValidation.errors;
      throw error;
    }

    // Get user with password hash
    const user = await User.findById(userId).select('+passwordHash');
    if (!user || !user.passwordHash) {
      throw new Error('User not found');
    }

    // Verify old password
    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!isOldPasswordValid) {
      const error = new Error('Current password is incorrect');
      error.name = 'InvalidPasswordError';
      throw error;
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // Update password
    await User.findByIdAndUpdate(userId, {
      passwordHash: newPasswordHash
    });
  }

  /**
   * Gets all refresh tokens for a user
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Array of refresh token objects
   */
  async getRefreshTokens(userId) {
    const user = await User.findById(userId).select('+refreshTokens');
    if (!user) {
      return [];
    }
    return user.refreshTokens || [];
  }

  /**
   * Searches for users by email (excluding current user)
   * @param {string} query - Search query (email)
   * @param {string} excludeUserId - User ID to exclude from results
   * @param {number} limit - Maximum number of results (default: 10)
   * @returns {Promise<Array>} Array of sanitized user objects
   */
  async searchUsers(query, excludeUserId, limit = 10) {
    if (!query || query.trim().length < 2) {
      return [];
    }

    const trimmedQuery = query.trim().toLowerCase(); // Normalize to lowercase since emails are stored lowercase
    
    // Escape special regex characters in the query
    const escapedQuery = trimmedQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // Build search conditions
    // Since emails are stored lowercase, we can use case-insensitive regex or exact match
    const searchConditions = {
      $or: [
        { email: trimmedQuery }, // Exact match (emails are lowercase in DB)
        { email: { $regex: new RegExp(`^${escapedQuery}`, 'i') } }, // Starts with
        { email: { $regex: new RegExp(escapedQuery, 'i') } } // Contains
      ],
      isActive: true
    };
    
    // Exclude current user if provided
    if (excludeUserId) {
      // Convert to ObjectId if valid, otherwise keep as string
      // MongoDB's $ne will handle the comparison correctly
      let excludeId;
      try {
        if (mongoose.Types.ObjectId.isValid(excludeUserId)) {
          excludeId = new mongoose.Types.ObjectId(excludeUserId);
        } else {
          excludeId = excludeUserId;
        }
      } catch (e) {
        excludeId = excludeUserId;
      }
      searchConditions._id = { $ne: excludeId };
    }
    
    // Debug logging in development
    if (process.env.NODE_ENV === 'development') {
      console.log('User search query:', {
        originalQuery: query,
        trimmedQuery,
        escapedQuery,
        excludeUserId,
        searchConditions: JSON.stringify(searchConditions, null, 2)
      });
    }
    
    const users = await User.find(searchConditions)
      .limit(limit)
      .select('-refreshTokens -passwordHash')
      .sort({ email: 1 }); // Sort by email for consistent results

    // Debug logging in development
    if (process.env.NODE_ENV === 'development') {
      console.log('User search results:', {
        query: trimmedQuery,
        found: users.length,
        emails: users.map(u => u.email)
      });
    }

    return users.map(user => this.safeUser(user));
  }
}

export const userService = new UserService();

