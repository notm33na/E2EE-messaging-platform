import express from 'express';
import { body } from 'express-validator';
import rateLimit from 'express-rate-limit';
import {
  register,
  login,
  logout,
  refresh,
  getMe,
  deactivate,
  reactivate
} from '../controllers/auth.controller.js';
import { verifyTokenMiddleware, requireAuth } from '../middlewares/auth.middleware.js';

const router = express.Router();

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: {
    success: false,
    error: 'Too many requests',
    message: 'Too many authentication attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Password validation rules
const passwordRules = [
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[^A-Za-z0-9]/)
    .withMessage('Password must contain at least one special character')
];

// Email validation
const emailValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .toLowerCase()
];

// Register route
router.post(
  '/register',
  authLimiter,
  emailValidation,
  passwordRules,
  register
);

// Login route
router.post(
  '/login',
  authLimiter,
  emailValidation,
  body('password').notEmpty().withMessage('Password is required'),
  login
);

// Logout route (requires auth)
router.post(
  '/logout',
  verifyTokenMiddleware,
  requireAuth,
  logout
);

// Refresh token route
router.post('/refresh', refresh);

// Get current user route (requires auth)
router.get(
  '/me',
  verifyTokenMiddleware,
  requireAuth,
  getMe
);

// Deactivate account route (requires auth)
router.post(
  '/deactivate',
  verifyTokenMiddleware,
  requireAuth,
  deactivate
);

// Reactivate account route (placeholder)
router.post('/reactivate', reactivate);

export default router;

