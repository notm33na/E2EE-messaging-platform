import express from 'express';
import http from 'http';
import https from 'https';
import dotenv from 'dotenv';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import { connectDatabase, closeDatabase } from './config/database.js';
import { setupSecurityMiddleware } from './middleware/security.js';
import { generateSelfSignedCert } from './utils/https-cert.js';
import { initializeWebSocket } from './websocket/socket-handler.js';
import { authErrorHandler } from './middlewares/auth.middleware.js';
import healthRouter from './routes/health.js';
import authRouter from './routes/auth.routes.js';
import keysRouter from './routes/keys.routes.js';
import kepRouter from './routes/kep.routes.js';
import messagesRouter from './routes/messages.routes.js';
// AI engine removed - not required for E2EE cryptography system

// Load environment variables
dotenv.config();

const app = express();
const PORT_HTTP = parseInt(process.env.PORT_HTTP || '8080', 10);
const PORT_HTTPS = parseInt(process.env.PORT_HTTPS || '8443', 10);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
// AI routes removed - not required for E2EE cryptography system

// Error handling middleware
app.use(authErrorHandler);

// Global error handler
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(error.status || 500).json({
    success: false,
    error: error.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
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

