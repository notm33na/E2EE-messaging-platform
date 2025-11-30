import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { sendEncryptedMessage } from '../crypto/messageFlow.js';
import { handleIncomingMessage } from '../crypto/messageFlow.js';
import { encryptFile } from '../crypto/fileEncryption.js';
import { decryptFile } from '../crypto/fileDecryption.js';
import { loadSession } from '../crypto/sessionManager.js';

/**
 * Custom hook for chat functionality
 * @param {string} sessionId - Session identifier
 * @param {Object} socket - Socket.IO socket instance
 * @returns {Object} Chat functions and state
 */
export function useChat(sessionId, socket) {
  const { user } = useAuth();
  const [messages, setMessages] = useState([]);
  const [files, setFiles] = useState([]); // Pending file reconstructions
  const [isDecrypting, setIsDecrypting] = useState(false);
  const fileChunksRef = useRef(new Map()); // sessionId -> {meta, chunks}

  // Handle incoming messages
  useEffect(() => {
    if (!socket || !sessionId) return;

    const handleMessage = async (envelope) => {
      try {
        setIsDecrypting(true);

        const result = await handleIncomingMessage(envelope);

        if (result.valid) {
          if (envelope.type === 'MSG') {
            // Text message
            setMessages(prev => [...prev, {
              id: `${envelope.sessionId}-${envelope.seq}`,
              type: 'text',
              content: result.plaintext,
              sender: envelope.sender,
              timestamp: envelope.timestamp,
              seq: envelope.seq
            }]);
          } else if (envelope.type === 'FILE_META') {
            // File metadata - start file reconstruction
            const fileId = `${envelope.sessionId}-${envelope.seq}`;
            fileChunksRef.current.set(fileId, {
              meta: envelope,
              chunks: []
            });
          } else if (envelope.type === 'FILE_CHUNK') {
            // File chunk - find matching file metadata by sessionId
            // We need to find the most recent FILE_META for this session
            let fileData = null;
            let fileId = null;
            
            // Find the file metadata entry
            for (const [id, data] of fileChunksRef.current.entries()) {
              if (data.meta.sessionId === envelope.sessionId && 
                  data.meta.meta.totalChunks === envelope.meta.totalChunks) {
                fileData = data;
                fileId = id;
                break;
              }
            }
            
            if (fileData) {
              // Sort chunks by index and add
              fileData.chunks.push(envelope);
              fileData.chunks.sort((a, b) => a.meta.chunkIndex - b.meta.chunkIndex);
              
              // Check if all chunks received
              if (fileData.chunks.length === fileData.meta.meta.totalChunks) {
                try {
                  // Decrypt and reconstruct file
                  const decrypted = await decryptFile(fileData.meta, fileData.chunks, sessionId);
                  
                  setFiles(prev => [...prev, {
                    id: fileId,
                    filename: decrypted.filename,
                    blob: decrypted.blob,
                    mimetype: decrypted.mimetype,
                    size: decrypted.size,
                    timestamp: envelope.timestamp
                  }]);

                  // Clean up
                  fileChunksRef.current.delete(fileId);
                } catch (error) {
                  console.error('Failed to decrypt file:', error);
                }
              }
            } else {
              console.warn('Received FILE_CHUNK without matching FILE_META');
            }
          }
        } else {
          console.error('Invalid message:', result.error);
        }
      } catch (error) {
        console.error('Error handling message:', error);
      } finally {
        setIsDecrypting(false);
      }
    };

    socket.on('msg:receive', handleMessage);

    return () => {
      socket.off('msg:receive', handleMessage);
    };
  }, [socket, sessionId]);

  /**
   * Sends an encrypted text message
   */
  const sendMessage = useCallback(async (plaintext) => {
    if (!socket || !sessionId || !plaintext.trim()) {
      return;
    }

    try {
      const envelope = await sendEncryptedMessage(sessionId, plaintext, (event, data) => {
        socket.emit(event, data);
      });

      // Add to local messages immediately (optimistic update)
      setMessages(prev => [...prev, {
        id: `${sessionId}-${envelope.seq}`,
        type: 'text',
        content: plaintext,
        sender: user.id,
        timestamp: envelope.timestamp,
        seq: envelope.seq,
        sent: true
      }]);
    } catch (error) {
      console.error('Failed to send message:', error);
      throw error;
    }
  }, [socket, sessionId, user]);

  /**
   * Sends an encrypted file
   */
  const sendFile = useCallback(async (file, receiverId) => {
    if (!socket || !sessionId || !file) {
      return;
    }

    try {
      const session = await loadSession(sessionId);
      if (!session) {
        throw new Error('Session not found');
      }

      // Encrypt file
      const { fileMetaEnvelope, chunkEnvelopes } = await encryptFile(
        file,
        sessionId,
        session.userId,
        receiverId || session.peerId
      );

      // Send metadata first
      socket.emit('msg:send', fileMetaEnvelope);

      // Send chunks
      for (const chunkEnvelope of chunkEnvelopes) {
        socket.emit('msg:send', chunkEnvelope);
      }

      console.log(`✓ File sent: ${file.name}`);
    } catch (error) {
      console.error('Failed to send file:', error);
      throw error;
    }
  }, [socket, sessionId]);

  return {
    messages,
    files,
    isDecrypting,
    sendMessage,
    sendFile
  };
}

