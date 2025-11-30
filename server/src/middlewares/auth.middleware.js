import { verifyToken } from '../utils/jwt.js';
import { userService } from '../services/user.service.js';

/**
 * Verifies JWT token and attaches user to request
 * Does not require authentication (optional auth)
 */
export async function verifyTokenMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      req.user = null;
      return next();
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    try {
      const decoded = verifyToken(token);

      // Verify token type is access token
      if (decoded.type !== 'access') {
        req.user = null;
        return next();
      }

      // Get user from database
      const user = await userService.getUserById(decoded.userId);

      if (!user || !user.isActive) {
        req.user = null;
        return next();
      }

      // Attach user to request
      req.user = {
        id: user._id.toString(),
        email: user.email
      };

      next();
    } catch (error) {
      // Token invalid, expired, or tampered
      req.user = null;
      next();
    }
  } catch (error) {
    req.user = null;
    next();
  }
}

/**
 * Requires authentication - returns 401 if not authenticated
 */
export function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      message: 'Please log in to access this resource'
    });
  }
  next();
}

/**
 * Error handler for authentication errors
 */
export function authErrorHandler(error, req, res, next) {
  if (error.name === 'JsonWebTokenError' || error.message?.includes('token')) {
    return res.status(401).json({
      success: false,
      error: 'Invalid token',
      message: 'Authentication token is invalid or expired'
    });
  }

  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      error: 'Token expired',
      message: 'Your session has expired. Please log in again.'
    });
  }

  next(error);
}

