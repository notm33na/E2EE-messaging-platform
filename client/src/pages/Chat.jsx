import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useChat } from '../hooks/useChat';
import { io } from 'socket.io-client';
import { getAccessToken } from '../utils/tokenStore';
import './Chat.css';

export function Chat() {
  const { sessionId } = useParams();
  const navigate = useNavigate();
  const { user, accessToken, logout } = useAuth();
  const [socket, setSocket] = useState(null);
  const [messageInput, setMessageInput] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef(null);

  const { messages, files, isDecrypting, sendMessage, sendFile } = useChat(sessionId, socket);

  // Initialize WebSocket connection
  useEffect(() => {
    if (!accessToken || !sessionId) return;

    const newSocket = io('https://localhost:8443', {
      transports: ['websocket'],
      rejectUnauthorized: false,
      auth: {
        token: accessToken
      }
    });

    newSocket.on('connect', () => {
      console.log('Chat WebSocket connected');
    });

    newSocket.on('msg:sent', (data) => {
      console.log('Message sent confirmation:', data);
    });

    newSocket.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, [accessToken, sessionId]);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, files]);

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!messageInput.trim() || sending) return;

    setSending(true);
    try {
      await sendMessage(messageInput);
      setMessageInput('');
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message. Please try again.');
    } finally {
      setSending(false);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleSendFile = async () => {
    if (!selectedFile || sending) return;

    setSending(true);
    try {
      await sendFile(selectedFile);
      setSelectedFile(null);
      // Reset file input
      const fileInput = document.getElementById('file-input');
      if (fileInput) fileInput.value = '';
    } catch (error) {
      console.error('Failed to send file:', error);
      alert('Failed to send file. Please try again.');
    } finally {
      setSending(false);
    }
  };

  const handleDownloadFile = (file) => {
    const url = URL.createObjectURL(file.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  if (!sessionId) {
    return (
      <div className="chat-container">
        <div className="chat-error">
          <p>No session selected</p>
          <button onClick={() => navigate('/dashboard')}>Go to Dashboard</button>
        </div>
      </div>
    );
  }

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h1>Encrypted Chat</h1>
        <div className="chat-header-actions">
          <span className="session-id">Session: {sessionId.substring(0, 8)}...</span>
          <button onClick={handleLogout} className="logout-btn">Logout</button>
        </div>
      </div>

      <div className="chat-messages">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`message ${msg.sender === user.id ? 'message-sent' : 'message-received'}`}
          >
            <div className="message-content">
              {msg.type === 'text' ? (
                <p>{msg.content}</p>
              ) : (
                <p className="message-meta">[File]</p>
              )}
              <span className="message-time">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </span>
            </div>
          </div>
        ))}

        {files.map((file) => (
          <div key={file.id} className="message message-received">
            <div className="message-content file-message">
              <p className="file-name">📎 {file.filename}</p>
              <p className="file-size">{(file.size / 1024).toFixed(2)} KB</p>
              <button
                onClick={() => handleDownloadFile(file)}
                className="download-btn"
              >
                Download
              </button>
            </div>
          </div>
        ))}

        {isDecrypting && (
          <div className="message message-system">
            <p>Decrypting...</p>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input-area">
        {selectedFile && (
          <div className="file-preview">
            <span>📎 {selectedFile.name}</span>
            <button onClick={() => setSelectedFile(null)}>✕</button>
          </div>
        )}

        <form onSubmit={handleSendMessage} className="chat-form">
          <input
            type="file"
            id="file-input"
            onChange={handleFileSelect}
            style={{ display: 'none' }}
          />
          <label htmlFor="file-input" className="file-btn">
            📎
          </label>

          <input
            type="text"
            value={messageInput}
            onChange={(e) => setMessageInput(e.target.value)}
            placeholder="Type a message..."
            className="message-input"
            disabled={sending}
          />

          {selectedFile ? (
            <button
              type="button"
              onClick={handleSendFile}
              disabled={sending}
              className="send-btn"
            >
              {sending ? 'Sending...' : 'Send File'}
            </button>
          ) : (
            <button
              type="submit"
              disabled={sending || !messageInput.trim()}
              className="send-btn"
            >
              {sending ? 'Sending...' : 'Send'}
            </button>
          )}
        </form>
      </div>
    </div>
  );
}

