import { Server } from 'socket.io';
import { verifyToken } from '../utils/jwt.js';
import { userService } from '../services/user.service.js';
import { KEPMessage } from '../models/KEPMessage.js';
import { MessageMeta } from '../models/MessageMeta.js';
import { logInvalidKEPMessage, logReplayAttempt, validateTimestamp, generateMessageId } from '../utils/replayProtection.js';
import { logMessageForwarding, logFileChunkForwarding, logReplayDetected } from '../utils/messageLogging.js';

/**
 * Initializes and configures Socket.IO server with JWT authentication
 * @param {Object} httpsServer - HTTPS server instance
 * @returns {Server} Socket.IO server instance
 */
export function initializeWebSocket(httpsServer) {
  const io = new Server(httpsServer, {
    cors: {
      origin: process.env.NODE_ENV === 'production'
        ? process.env.CLIENT_URL || 'https://localhost:5173'
        : ['http://localhost:5173', 'https://localhost:5173'],
      methods: ['GET', 'POST'],
      credentials: true
    }
  });

  // Authentication middleware for WebSocket connections
  io.use(async (socket, next) => {
    try {
      // Get token from query parameter or handshake auth
      const token = socket.handshake.auth?.token || 
                   socket.handshake.query?.token ||
                   socket.handshake.headers?.authorization?.replace('Bearer ', '');

      if (!token) {
        // Allow connection but mark as unauthenticated
        socket.data.user = null;
        return next();
      }

      try {
        // Verify JWT token
        const decoded = verifyToken(token);

        // Verify token type is access token
        if (decoded.type !== 'access') {
          socket.data.user = null;
          return next();
        }

        // Get user from database
        const user = await userService.getUserById(decoded.userId);

        if (!user || !user.isActive) {
          socket.data.user = null;
          return next();
        }

        // Attach user identity to socket
        socket.data.user = {
          id: user._id.toString(),
          email: user.email
        };

        next();
      } catch (error) {
        // Token invalid - allow connection but mark as unauthenticated
        socket.data.user = null;
        next();
      }
    } catch (error) {
      socket.data.user = null;
      next();
    }
  });

  // Connection handling
  io.on('connection', (socket) => {
    const isAuthenticated = !!socket.data.user;

    if (isAuthenticated) {
      console.log(`✓ Authenticated WebSocket client connected: ${socket.id} (${socket.data.user.email})`);
    } else {
      console.log(`✓ Unauthenticated WebSocket client connected: ${socket.id}`);
    }

    // Send welcome message with identity
    socket.emit('hello', {
      message: isAuthenticated 
        ? 'Connected to secure WebSocket server' 
        : 'Connected (unauthenticated)',
      timestamp: new Date().toISOString(),
      socketId: socket.id,
      authenticated: isAuthenticated,
      user: isAuthenticated ? socket.data.user : null
    });

    // Auth:hello event - echoes back identity
    socket.on('auth:hello', () => {
      if (isAuthenticated) {
        socket.emit('auth:hello', {
          success: true,
          user: socket.data.user,
          timestamp: new Date().toISOString()
        });
      } else {
        socket.emit('auth:hello', {
          success: false,
          message: 'Not authenticated',
          timestamp: new Date().toISOString()
        });
      }
    });

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      if (isAuthenticated) {
        console.log(`WebSocket client disconnected: ${socket.id} (${socket.data.user.email}) - ${reason}`);
      } else {
        console.log(`WebSocket client disconnected: ${socket.id} - ${reason}`);
      }
    });

    // Message handler (requires authentication)
    socket.on('message', (data) => {
      if (!isAuthenticated) {
        socket.emit('error', {
          message: 'Authentication required',
          timestamp: new Date().toISOString()
        });
        return;
      }

      console.log(`Message from ${socket.data.user.email} (${socket.id}):`, data);
      socket.emit('message', {
        echo: data,
        from: socket.data.user.email,
        timestamp: new Date().toISOString()
      });
    });

    // KEP:INIT event handler
    socket.on('kep:init', async (data) => {
      if (!isAuthenticated) {
        socket.emit('error', {
          message: 'Authentication required for KEP',
          timestamp: new Date().toISOString()
        });
        return;
      }

      try {
        const { to, sessionId, timestamp, seq, message } = data;

        // Validate required fields
        if (!to || !sessionId || !timestamp || !seq || !message) {
          logInvalidKEPMessage(socket.data.user.id, sessionId, 'Missing required fields');
          socket.emit('error', {
            message: 'Invalid KEP_INIT message: missing fields',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Validate timestamp
        if (!validateTimestamp(timestamp)) {
          logReplayAttempt(sessionId, seq, timestamp, 'Timestamp out of validity window');
          socket.emit('error', {
            message: 'KEP_INIT rejected: timestamp out of validity window',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Store message metadata
        const messageId = `${sessionId}:${seq}:${Date.now()}`;
        const kepMessage = new KEPMessage({
          messageId,
          sessionId,
          from: socket.data.user.id,
          to,
          type: 'KEP_INIT',
          timestamp,
          seq,
          delivered: false
        });

        await kepMessage.save();

        // Forward to recipient if online
        const sockets = await io.fetchSockets();
        const recipientSocket = sockets.find(s => s.data.user?.id === to);

        if (recipientSocket) {
          recipientSocket.emit('kep:init', {
            messageId,
            from: socket.data.user.id,
            sessionId,
            message,
            timestamp,
            seq
          });

          kepMessage.delivered = true;
          kepMessage.deliveredAt = new Date();
          await kepMessage.save();
        }

        socket.emit('kep:sent', {
          messageId,
          sessionId,
          delivered: kepMessage.delivered
        });
      } catch (error) {
        console.error('KEP_INIT error:', error);
        socket.emit('error', {
          message: 'Failed to process KEP_INIT',
          timestamp: new Date().toISOString()
        });
      }
    });

    // KEP:RESPONSE event handler
    socket.on('kep:response', async (data) => {
      if (!isAuthenticated) {
        socket.emit('error', {
          message: 'Authentication required for KEP',
          timestamp: new Date().toISOString()
        });
        return;
      }

      try {
        const { to, sessionId, timestamp, seq, message } = data;

        // Validate required fields
        if (!to || !sessionId || !timestamp || !seq || !message) {
          logInvalidKEPMessage(socket.data.user.id, sessionId, 'Missing required fields');
          socket.emit('error', {
            message: 'Invalid KEP_RESPONSE message: missing fields',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Validate timestamp
        if (!validateTimestamp(timestamp)) {
          logReplayAttempt(sessionId, seq, timestamp, 'Timestamp out of validity window');
          socket.emit('error', {
            message: 'KEP_RESPONSE rejected: timestamp out of validity window',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Store message metadata
        const messageId = `${sessionId}:${seq}:${Date.now()}`;
        const kepMessage = new KEPMessage({
          messageId,
          sessionId,
          from: socket.data.user.id,
          to,
          type: 'KEP_RESPONSE',
          timestamp,
          seq,
          delivered: false
        });

        await kepMessage.save();

        // Forward to recipient if online
        const sockets = await io.fetchSockets();
        const recipientSocket = sockets.find(s => s.data.user?.id === to);

        if (recipientSocket) {
          recipientSocket.emit('kep:response', {
            messageId,
            from: socket.data.user.id,
            sessionId,
            message,
            timestamp,
            seq
          });

          kepMessage.delivered = true;
          kepMessage.deliveredAt = new Date();
          await kepMessage.save();
        }

        socket.emit('kep:sent', {
          messageId,
          sessionId,
          delivered: kepMessage.delivered
        });
      } catch (error) {
        if (error.code === 11000) {
          // Duplicate message (replay attempt)
          logReplayAttempt(data.sessionId, data.seq, data.timestamp, 'Duplicate message ID');
          socket.emit('error', {
            message: 'KEP_RESPONSE rejected: duplicate message (replay attempt)',
            timestamp: new Date().toISOString()
          });
        } else {
          console.error('KEP_RESPONSE error:', error);
          socket.emit('error', {
            message: 'Failed to process KEP_RESPONSE',
            timestamp: new Date().toISOString()
          });
        }
      }
    });

    // MSG:SEND event handler - Encrypted message sending
    socket.on('msg:send', async (envelope) => {
      if (!isAuthenticated) {
        socket.emit('error', {
          message: 'Authentication required for messaging',
          timestamp: new Date().toISOString()
        });
        return;
      }

      try {
        const { type, sessionId, receiver, timestamp, seq } = envelope;

        // Validate required fields
        if (!type || !sessionId || !receiver || !timestamp || !seq) {
          socket.emit('error', {
            message: 'Invalid message envelope: missing fields',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Validate timestamp
        if (!validateTimestamp(timestamp)) {
          logReplayAttempt(sessionId, seq, timestamp, 'Timestamp out of validity window');
          logReplayDetected(socket.data.user.id, sessionId, seq, 'Timestamp out of validity window');
          socket.emit('error', {
            message: 'Message rejected: timestamp out of validity window',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Generate message ID
        const messageId = generateMessageId(sessionId, seq);

        // Store message metadata
        const messageMeta = new MessageMeta({
          messageId,
          sessionId,
          sender: socket.data.user.id,
          receiver,
          type,
          timestamp,
          seq,
          meta: envelope.meta || {},
          delivered: false
        });

        await messageMeta.save();

        // Forward to recipient if online
        const sockets = await io.fetchSockets();
        const recipientSocket = sockets.find(s => s.data.user?.id === receiver);

        if (recipientSocket) {
          recipientSocket.emit('msg:receive', envelope);

          if (type === 'FILE_CHUNK') {
            logFileChunkForwarding(socket.data.user.id, receiver, sessionId, envelope.meta?.chunkIndex);
          } else {
            logMessageForwarding(socket.data.user.id, receiver, sessionId, type);
          }

          messageMeta.delivered = true;
          messageMeta.deliveredAt = new Date();
          await messageMeta.save();
        }

        socket.emit('msg:sent', {
          messageId,
          sessionId,
          delivered: messageMeta.delivered
        });
      } catch (error) {
        if (error.code === 11000) {
          // Duplicate message (replay attempt)
          logReplayAttempt(envelope.sessionId, envelope.seq, envelope.timestamp, 'Duplicate message ID');
          logReplayDetected(socket.data.user.id, envelope.sessionId, envelope.seq, 'Duplicate message ID');
          socket.emit('error', {
            message: 'Message rejected: duplicate message (replay attempt)',
            timestamp: new Date().toISOString()
          });
        } else {
          console.error('MSG:SEND error:', error);
          socket.emit('error', {
            message: 'Failed to process message',
            timestamp: new Date().toISOString()
          });
        }
      }
    });

    // KEY_UPDATE event handler (Phase 6: Forward Secrecy)
    socket.on('key:update', async (keyUpdateMessage) => {
      if (!isAuthenticated) {
        socket.emit('error', {
          message: 'Authentication required for key updates',
          timestamp: new Date().toISOString()
        });
        return;
      }

      try {
        const { sessionId, from, to, timestamp, rotationSeq } = keyUpdateMessage;

        // Validate required fields
        if (!sessionId || !from || !to || !timestamp || rotationSeq === undefined) {
          socket.emit('error', {
            message: 'Invalid KEY_UPDATE message: missing fields',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Validate timestamp freshness (±2 minutes)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 2 * 60 * 1000) {
          socket.emit('error', {
            message: 'KEY_UPDATE rejected: timestamp out of validity window',
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Store key update metadata (server does not decrypt or verify signatures)
        // Client-side signature verification happens on recipient
        const messageId = `${sessionId}:KEY_UPDATE:${rotationSeq}:${timestamp}`;
        
        // Forward to recipient if online
        const sockets = await io.fetchSockets();
        const recipientSocket = sockets.find(s => s.data.user?.id === to);

        if (recipientSocket) {
          recipientSocket.emit('key:update', {
            messageId,
            from: socket.data.user.id,
            sessionId,
            keyUpdateMessage,
            timestamp
          });

          socket.emit('key:update:sent', {
            messageId,
            sessionId,
            delivered: true
          });
        } else {
          // Store as pending if recipient offline
          // TODO: Store in database for offline delivery
          socket.emit('key:update:sent', {
            messageId,
            sessionId,
            delivered: false
          });
        }
      } catch (error) {
        console.error('KEY_UPDATE error:', error);
        socket.emit('error', {
          message: 'Failed to process key update',
          timestamp: new Date().toISOString()
        });
      }
    });
  });

  console.log('✓ WebSocket server initialized with JWT authentication, messaging, and key rotation');
  return io;
}

