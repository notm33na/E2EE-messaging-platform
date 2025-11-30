import helmet from 'helmet';
import cors from 'cors';

/**
 * Security middleware configuration
 * Sets up Helmet and CORS with secure defaults
 */
export function setupSecurityMiddleware(app) {
  // Helmet: Sets various HTTP headers for security
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }));

  // CORS: Configure cross-origin resource sharing
  app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.CLIENT_URL || 'https://localhost:5173'
      : ['http://localhost:5173', 'https://localhost:5173'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));
}

