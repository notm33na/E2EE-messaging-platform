import { validationResult } from 'express-validator';
import { userService } from '../services/user.service.js';
import { generateAccessToken, generateRefreshToken, verifyToken } from '../utils/jwt.js';
import { logAuthenticationAttempt } from '../utils/attackLogging.js';

/**
 * Register a new user
 * POST /api/auth/register
 */
export async function register(req, res, next) {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await userService.getUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'User already exists',
        message: 'An account with this email already exists'
      });
    }

    // Create user
    const user = await userService.createUser(email, password);

    // Generate tokens
    const accessToken = generateAccessToken(user.id, user.email);
    const refreshToken = generateRefreshToken(user.id, user.email);

    // Store refresh token in database
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress || '';
    await userService.addRefreshToken(user.id, refreshToken, userAgent, ip);

    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user,
        accessToken
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Login user
 * POST /api/auth/login
 */
export async function login(req, res, next) {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Get user with password hash
    const user = await userService.getUserByEmail(email, true);
    if (!user) {
      logAuthenticationAttempt(null, false, 'User not found');
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      logAuthenticationAttempt(user._id.toString(), false, 'Account deactivated');
      return res.status(403).json({
        success: false,
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact support.'
      });
    }

    // Verify password
    const isValidPassword = await userService.verifyPassword(email, password);

    if (!isValidPassword) {
      logAuthenticationAttempt(user._id.toString(), false, 'Invalid password');
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }

    // Log successful authentication
    logAuthenticationAttempt(user._id.toString(), true, 'Login successful');

    // Update last login
    await userService.updateLastLogin(user._id.toString());

    // Generate tokens
    const userId = user._id.toString();
    const accessToken = generateAccessToken(userId, user.email);
    const refreshToken = generateRefreshToken(userId, user.email);

    // Store refresh token in database
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress || '';
    await userService.addRefreshToken(userId, refreshToken, userAgent, ip);

    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userService.safeUser(user),
        accessToken
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Logout user
 * POST /api/auth/logout
 */
export async function logout(req, res, next) {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken && req.user) {
      // Revoke refresh token from database
      await userService.removeRefreshToken(req.user.id, refreshToken);
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Refresh access token
 * POST /api/auth/refresh
 */
export async function refresh(req, res, next) {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'No refresh token',
        message: 'Refresh token not found'
      });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = verifyToken(refreshToken);
    } catch (error) {
      // Token invalid or expired
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        message: 'Refresh token is invalid or expired'
      });
    }

    // Verify token type
    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token type',
        message: 'Token is not a refresh token'
      });
    }

    // Check if token exists in database (token rotation check)
    const hasToken = await userService.hasRefreshToken(decoded.userId, refreshToken);
    if (!hasToken) {
      // Token reuse detected - possible attack
      // Revoke all tokens for this user
      await userService.revokeAllRefreshTokens(decoded.userId);
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
      return res.status(401).json({
        success: false,
        error: 'Token reuse detected',
        message: 'Security violation: token has been revoked'
      });
    }

    // Get user
    const user = await userService.getUserById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'User not found',
        message: 'User account not found or deactivated'
      });
    }

    // Revoke old refresh token (token rotation)
    await userService.removeRefreshToken(decoded.userId, refreshToken);

    // Generate new tokens
    const userId = user._id.toString();
    const newAccessToken = generateAccessToken(userId, user.email);
    const newRefreshToken = generateRefreshToken(userId, user.email);

    // Store new refresh token
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress || '';
    await userService.addRefreshToken(userId, newRefreshToken, userAgent, ip);

    // Set new refresh token cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: newAccessToken
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get current user
 * GET /api/auth/me
 */
export async function getMe(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Not authenticated',
        message: 'Please log in to access this resource'
      });
    }

    const user = await userService.getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        message: 'User account not found'
      });
    }

    res.json({
      success: true,
      data: {
        user: userService.safeUser(user)
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Deactivate user account (placeholder)
 * POST /api/auth/deactivate
 */
export async function deactivate(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Not authenticated'
      });
    }

    // Revoke all refresh tokens
    await userService.revokeAllRefreshTokens(req.user.id);
    
    // Deactivate account
    await userService.deactivateUser(req.user.id);

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.json({
      success: true,
      message: 'Account deactivated successfully'
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Reactivate user account (placeholder)
 * POST /api/auth/reactivate
 */
export async function reactivate(req, res, next) {
  try {
    // This would typically require admin privileges or email verification
    // For now, it's a placeholder
    return res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Account reactivation is not yet implemented'
    });
  } catch (error) {
    next(error);
  }
}

