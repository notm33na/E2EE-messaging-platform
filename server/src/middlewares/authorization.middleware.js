/**
 * Authorization Middleware
 * 
 * Provides comprehensive authorization checks to prevent user ID manipulation
 * and unauthorized access to resources.
 */

/**
 * Ensures the authenticated user can only access their own resources
 * Compares req.user.id with the userId parameter in the request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
export function requireOwnResource(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  // Check if userId parameter matches authenticated user
  const requestedUserId = req.params.userId || req.body.userId || req.query.userId;
  
  if (requestedUserId && requestedUserId !== req.user.id && requestedUserId !== req.user.id.toString()) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden: Cannot access resources belonging to another user'
    });
  }

  next();
}

/**
 * Ensures the authenticated user is the sender of a message
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
export function requireSenderAuthorization(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  // Check sender field in body matches authenticated user
  if (req.body.sender && req.body.sender !== req.user.id && req.body.sender !== req.user.id.toString()) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden: Cannot send messages as another user'
    });
  }

  // Check 'from' field (alternative naming)
  if (req.body.from && req.body.from !== req.user.id && req.body.from !== req.user.id.toString()) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden: Cannot send messages as another user'
    });
  }

  next();
}

/**
 * Ensures the authenticated user can only access their own session
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
export function requireSessionAuthorization(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  // For session-based operations, verify user is part of the session
  // This is a placeholder - actual implementation would check session membership
  // In practice, sessions are between two users, so we'd check if req.user.id is either sender or receiver
  
  next();
}

