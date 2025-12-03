import express from 'express';
import http from 'http';
import https from 'https';
import dotenv from 'dotenv';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { connectDatabase, closeDatabase } from './config/database.js';
import { setupSecurityMiddleware } from './middleware/security.js';
import { generateSelfSignedCert } from './utils/https-cert.js';
import { initializeWebSocket } from './websocket/socket-handler.js';
import { authErrorHandler } from './middlewares/auth.middleware.js';
import { runPeriodicCleanup } from './utils/databaseCleanup.js';
import healthRouter from './routes/health.js';
import authRouter from './routes/auth.routes.js';
import keysRouter from './routes/keys.routes.js';
import kepRouter from './routes/kep.routes.js';
import messagesRouter from './routes/messages.routes.js';
import auditRouter from './routes/audit.routes.js';
// AI engine removed - not required for E2EE cryptography system

// Load environment variables from project root
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, '../../.env') });

const app = express();
const PORT_HTTP = parseInt(process.env.PORT_HTTP || '8080', 10);
const PORT_HTTPS = parseInt(process.env.PORT_HTTPS || '8443', 10);

// Trust proxy for proper HTTPS detection behind reverse proxies (nginx, etc.)
// In development, disable it to avoid rate limiting warnings (we're running directly)
// In production, this should be configured based on your reverse proxy setup
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', true);
} else {
  // In development, disable trust proxy to avoid rate limiting warnings
  // This is safe since we're running directly without a reverse proxy
  app.set('trust proxy', false);
}

// Middleware
app.use(express.json({ limit: '10mb' })); // Limit request body size
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Limit URL-encoded body size
app.use(cookieParser()); // Parse cookies for refresh tokens
app.use(morgan('combined'));

// Security middleware
setupSecurityMiddleware(app);

// Routes
app.use('/api/health', healthRouter);
app.use('/api/auth', authRouter);
app.use('/api/keys', keysRouter);
app.use('/api/kep', kepRouter);
app.use('/api/messages', messagesRouter);
app.use('/api/audit', auditRouter);
// AI routes removed - not required for E2EE cryptography system

// Error handling middleware
app.use(authErrorHandler);

// Global error handler
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  // Determine user-friendly error message
  let userMessage = 'An unexpected error occurred. Please try again.';
  let statusCode = error.status || 500;
  
  // Handle specific error types with user-friendly messages
  if (error.name === 'PasswordValidationError') {
    userMessage = error.errors?.join(', ') || 'Password does not meet requirements';
    statusCode = 400;
  } else if (error.name === 'DuplicateUserError') {
    userMessage = 'An account with this email already exists. Please use a different email or try logging in.';
    statusCode = 409;
  } else if (error.name === 'ValidationError') {
    userMessage = error.message || 'Invalid input data';
    statusCode = 400;
  } else if (error.message) {
    // Use error message if it's already user-friendly
    userMessage = error.message;
  }
  
  res.status(statusCode).json({
    success: false,
    error: userMessage,
    message: userMessage, // Also include in message field for consistency
    ...(process.env.NODE_ENV === 'development' && { 
      stack: error.stack,
      technicalError: error.message 
    })
  });
});

// HTTP server: Redirect all traffic to HTTPS
const httpServer = http.createServer((req, res) => {
  const host = req.headers.host.replace(/:\d+$/, '');
  const httpsUrl = `https://${host}:${PORT_HTTPS}${req.url}`;
  res.writeHead(301, { Location: httpsUrl });
  res.end();
});

// HTTPS server: Main application server
const httpsOptions = generateSelfSignedCert();
const httpsServer = https.createServer(httpsOptions, app);

// Initialize WebSocket on HTTPS server
const io = initializeWebSocket(httpsServer);

// Store io instance for potential use in routes
app.set('io', io);

/**
 * Start servers
 */
async function startServers() {
  try {
    // Connect to MongoDB
    if (process.env.MONGO_URI) {
      await connectDatabase(process.env.MONGO_URI);
    } else {
      console.warn('⚠️  MONGO_URI not set. MongoDB connection skipped.');
    }

    // Start HTTP server (redirects to HTTPS)
    httpServer.listen(PORT_HTTP, () => {
      console.log(`✓ HTTP server running on port ${PORT_HTTP} (redirects to HTTPS)`);
    });

    // Start HTTPS server
    httpsServer.listen(PORT_HTTPS, () => {
      console.log(`✓ HTTPS server running on port ${PORT_HTTPS}`);
      console.log(`✓ API available at: https://localhost:${PORT_HTTPS}/api`);
      console.log(`✓ WebSocket available at: https://localhost:${PORT_HTTPS}`);
    });

    // Schedule periodic database cleanup (daily at 2 AM)
    const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
    setInterval(async () => {
      try {
        await runPeriodicCleanup(90, 30); // 90 days for messages, 30 days for KEP
      } catch (error) {
        console.error('Scheduled cleanup failed:', error);
      }
    }, CLEANUP_INTERVAL);

    // Run initial cleanup after 1 minute (to allow server to start)
    setTimeout(async () => {
      try {
        await runPeriodicCleanup(90, 30);
      } catch (error) {
        console.error('Initial cleanup failed:', error);
      }
    }, 60000);

  } catch (error) {
    console.error('Failed to start servers:', error);
    process.exit(1);
  }
}

/**
 * Graceful shutdown
 */
async function shutdown() {
  console.log('\nShutting down gracefully...');
  
  httpServer.close(() => {
    console.log('✓ HTTP server closed');
  });
  
  httpsServer.close(() => {
    console.log('✓ HTTPS server closed');
  });

  if (io) {
    io.close();
    console.log('✓ WebSocket server closed');
  }

  await closeDatabase();
  process.exit(0);
}

// Handle shutdown signals
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start the application
startServers();

