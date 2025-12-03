/**
 * useE2EE Hook
 * 
 * React hook for end-to-end encrypted messaging with forward secrecy.
 * 
 * FORWARD SECRECY:
 * - Session keys rotated periodically
 * - Old keys cannot decrypt new messages
 * - Ephemeral keys discarded after use
 * 
 * SECURITY CONSIDERATIONS:
 * - All encryption/decryption happens client-side
 * - Keys stored in memory or secure local storage
 * - Server never sees plaintext or private keys
 * 
 * DATA PRIVACY CONSTRAINTS:
 * - Only encrypted ciphertext sent to server
 * - Metadata-only server storage
 * - Private keys never transmitted
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { sendEncryptedMessage, handleIncomingMessage } from '../crypto/messageFlow';
import { encryptFile } from '../crypto/fileEncryption';
import { decryptFile } from '../crypto/fileDecryption';
import { initiateKeyRotation, respondToKeyRotation } from '../crypto/keyRotation';
import { loadSession, getSendKey, getRecvKey } from '../crypto/sessionManager';
import { importPublicKey } from '../crypto/ecdh';
import api from '../services/api';

/**
 * useE2EE hook for encrypted messaging
 * @param {string} sessionId - Session identifier
 * @param {string} peerId - Peer user ID
 * @returns {Object} E2EE messaging functions and state
 */
export function useE2EE(sessionId, peerId) {
  const { user } = useAuth();
  const [messages, setMessages] = useState([]);
  const [files, setFiles] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const socketRef = useRef(null);
  const pendingKeyRotationRef = useRef(null);

  /**
   * Sends an encrypted text message
   */
  const sendMessage = useCallback(async (plaintext) => {
    if (!sessionId || !plaintext) {
      setError('Session ID and message content required');
      return;
    }

    try {
      const envelope = await sendEncryptedMessage(sessionId, plaintext);
      
      // Send via WebSocket if connected
      if (socketRef.current && socketRef.current.connected) {
        socketRef.current.emit('msg:send', envelope);
      } else {
        // Fallback to REST API
        await api.post('/messages/relay', envelope);
      }

      // Optimistically add to messages (will be confirmed when received back)
      setMessages(prev => [...prev, {
        id: `${sessionId}-${envelope.seq}`,
        type: 'sent',
        content: plaintext,
        timestamp: envelope.timestamp,
        seq: envelope.seq
      }]);
    } catch (err) {
      setError(`Failed to send message: ${err.message}`);
      throw err;
    }
  }, [sessionId]);

  /**
   * Sends an encrypted file
   */
  const sendFile = useCallback(async (file) => {
    if (!sessionId || !file) {
      setError('Session ID and file required');
      return;
    }

    try {
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        sessionId,
        user.id,
        peerId
      );

      // Send via WebSocket if connected
      if (socketRef.current && socketRef.current.connected) {
        socketRef.current.emit('msg:send', fileMetaEnvelope);
        
        // Send chunks sequentially
        for (const chunkEnvelope of chunkEnvelopes) {
          socketRef.current.emit('msg:send', chunkEnvelope);
        }
      } else {
        // Fallback to REST API
        await api.post('/messages/relay', fileMetaEnvelope);
        for (const chunkEnvelope of chunkEnvelopes) {
          await api.post('/messages/relay', chunkEnvelope);
        }
      }
    } catch (err) {
      setError(`Failed to send file: ${err.message}`);
      throw err;
    }
  }, [sessionId, user?.id, peerId]);

  /**
   * Initiates key rotation for forward secrecy
   */
  const rotateKeys = useCallback(async (password) => {
    if (!sessionId || !password) {
      setError('Session ID and password required for key rotation');
      return;
    }

    try {
      // Get peer's identity public key
      const peerKeyResponse = await api.get(`/keys/${peerId}`);
      const peerIdentityPubKeyJWK = peerKeyResponse.data.publicKey;
      const peerIdentityPubKey = await importPublicKey(peerIdentityPubKeyJWK);

      // Initiate rotation
      const { keyUpdateMessage, newEphPrivateKey } = await initiateKeyRotation(
        sessionId,
        user.id,
        peerId,
        password
      );

      // Store pending rotation state
      pendingKeyRotationRef.current = {
        newEphPrivateKey,
        peerIdentityPubKey
      };

      // Send key update via WebSocket
      if (socketRef.current && socketRef.current.connected) {
        socketRef.current.emit('key:update', keyUpdateMessage);
      } else {
        // Fallback to REST API (if implemented)
        await api.post('/crypto/key-update', keyUpdateMessage);
      }
    } catch (err) {
      setError(`Failed to rotate keys: ${err.message}`);
      throw err;
    }
  }, [sessionId, user?.id, peerId]);

  /**
   * Handles incoming encrypted messages
   */
  const handleMessage = useCallback(async (envelope) => {
    try {
      if (envelope.type === 'MSG') {
        const plaintext = await handleIncomingMessage(envelope);
        setMessages(prev => [...prev, {
          id: `${envelope.sessionId}-${envelope.seq}`,
          type: 'received',
          content: plaintext,
          timestamp: envelope.timestamp,
          seq: envelope.seq
        }]);
      } else if (envelope.type === 'FILE_META') {
        // Handle file metadata (start file reconstruction)
        // Implementation depends on file decryption flow
        console.log('File metadata received:', envelope);
      } else if (envelope.type === 'FILE_CHUNK') {
        // Handle file chunk
        console.log('File chunk received:', envelope);
      }
    } catch (err) {
      setError(`Failed to handle message: ${err.message}`);
      console.error('Message handling error:', err);
    }
  }, []);

  /**
   * Handles key update messages
   */
  const handleKeyUpdate = useCallback(async (keyUpdateData, password) => {
    try {
      const { keyUpdateMessage, from } = keyUpdateData;

      // Get sender's identity public key
      const senderKeyResponse = await api.get(`/keys/${from}`);
      const senderIdentityPubKeyJWK = senderKeyResponse.data.publicKey;
      const senderIdentityPubKey = await importPublicKey(senderIdentityPubKeyJWK);

      // Respond to key rotation
      const { keyUpdateMessage: responseKeyUpdate } = await respondToKeyRotation(
        keyUpdateMessage,
        senderIdentityPubKey,
        sessionId,
        user.id,
        peerId,
        password
      );

      // Send response
      if (socketRef.current && socketRef.current.connected) {
        socketRef.current.emit('key:update', responseKeyUpdate);
      }
    } catch (err) {
      setError(`Failed to handle key update: ${err.message}`);
      throw err;
    }
  }, [sessionId, user?.id, peerId]);

  // WebSocket connection setup
  useEffect(() => {
    if (!sessionId || !user) return;

    // Import socket.io-client dynamically
    import('socket.io-client').then(({ default: io }) => {
      const token = localStorage.getItem('accessToken') || '';
      
      // In development, use Vite proxy to avoid mixed content issues
      const wsURL = import.meta.env.DEV 
        ? window.location.origin // Use same origin (Vite proxy will handle it)
        : 'https://localhost:8443';
      
      socketRef.current = io(wsURL, {
        transports: ['polling', 'websocket'], // Try polling first in dev (works through proxy)
        auth: {
          token
        },
        secure: true,
        rejectUnauthorized: false, // For self-signed certs in dev
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: Infinity, // Always try to reconnect
        reconnectionDelayMax: 10000,
        timeout: 20000,
        forceNew: false // Reuse connection if possible
      });

      socketRef.current.on('connect', () => {
        setIsConnected(true);
        setError(null);
        // Set up keep-alive ping to maintain connection
        const keepAliveInterval = setInterval(() => {
          if (socketRef.current && socketRef.current.connected) {
            socketRef.current.emit('ping', { timestamp: Date.now() });
          } else {
            clearInterval(keepAliveInterval);
          }
        }, 30000); // Ping every 30 seconds
        
        // Store interval ID for cleanup
        socketRef.current._keepAliveInterval = keepAliveInterval;
      });

      socketRef.current.on('disconnect', () => {
        setIsConnected(false);
      });

      socketRef.current.on('error', (error) => {
        setError(error.message || 'WebSocket error');
      });

      // Handle incoming messages
      socketRef.current.on('msg:receive', handleMessage);

      // Handle key updates
      socketRef.current.on('key:update', async (keyUpdateData) => {
        // Prompt for password to handle key rotation
        // In production, this should be handled more securely
        const password = prompt('Enter password to process key rotation:');
        if (password) {
          await handleKeyUpdate(keyUpdateData, password);
        }
      });

      return () => {
        if (socketRef.current) {
          socketRef.current.disconnect();
        }
      };
    });

    return () => {
      if (socketRef.current) {
        // Clear keep-alive interval
        if (socketRef.current._keepAliveInterval) {
          clearInterval(socketRef.current._keepAliveInterval);
        }
        socketRef.current.disconnect();
      }
    };
  }, [sessionId, user, handleMessage, handleKeyUpdate]);

  return {
    messages,
    files,
    isConnected,
    error,
    sendMessage,
    sendFile,
    rotateKeys,
    handleMessage,
    handleKeyUpdate
  };
}

