import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../context/AuthContext';
import './WebSocketTest.css';

/**
 * WebSocket test component
 * Connects to the secure WebSocket server with JWT authentication
 */
function WebSocketTest() {
  const { accessToken, isAuthenticated } = useAuth();
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');

  useEffect(() => {
    if (!isAuthenticated || !accessToken) {
      return;
    }

    // Initialize Socket.IO connection with JWT token
    const newSocket = io('https://localhost:8443', {
      transports: ['websocket'],
      rejectUnauthorized: false, // Allow self-signed certificates
      auth: {
        token: accessToken
      }
    });

    newSocket.on('connect', () => {
      console.log('WebSocket connected:', newSocket.id);
      setConnected(true);
    });

    newSocket.on('hello', (data) => {
      setMessages(prev => [...prev, { type: 'server', data }]);
      if (data.authenticated) {
        setAuthenticated(true);
      }
    });

    newSocket.on('auth:hello', (data) => {
      setMessages(prev => [...prev, { type: 'auth', data }]);
      if (data.success) {
        setAuthenticated(true);
      }
    });

    newSocket.on('message', (data) => {
      setMessages(prev => [...prev, { type: 'echo', data }]);
    });

    newSocket.on('error', (data) => {
      setMessages(prev => [...prev, { type: 'error', data }]);
    });

    newSocket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setConnected(false);
    });

    newSocket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      setConnected(false);
    });

    setSocket(newSocket);

    // Cleanup on unmount
    return () => {
      newSocket.close();
    };
  }, [isAuthenticated, accessToken]);

  const sendMessage = () => {
    if (socket && messageInput.trim()) {
      socket.emit('message', messageInput);
      setMessages(prev => [...prev, { type: 'client', data: messageInput }]);
      setMessageInput('');
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="websocket-test">
        <h3>WebSocket Connection Test</h3>
        <div className="ws-status disconnected">
          ✗ Authentication required
        </div>
        <p>Please log in to use WebSocket features.</p>
      </div>
    );
  }

  return (
    <div className="websocket-test">
      <h3>WebSocket Connection Test</h3>
      <div className={`ws-status ${connected ? 'connected' : 'disconnected'}`}>
        {connected ? '✓ Connected' : '✗ Disconnected'}
      </div>
      {connected && (
        <div className={`ws-status ${authenticated ? 'connected' : 'disconnected'}`}>
          {authenticated ? '✓ Authenticated' : '✗ Not Authenticated'}
        </div>
      )}
      
      <div className="messages-container">
        <h4>Messages:</h4>
        <div className="messages">
          {messages.length === 0 ? (
            <p className="no-messages">No messages yet...</p>
          ) : (
            messages.map((msg, idx) => (
              <div key={idx} className={`message ${msg.type}`}>
                <span className="message-type">{msg.type}:</span>
                <pre>{JSON.stringify(msg.data, null, 2)}</pre>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="message-input">
        <input
          type="text"
          value={messageInput}
          onChange={(e) => setMessageInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
          placeholder="Type a message..."
          disabled={!connected || !authenticated}
        />
        <button 
          onClick={sendMessage} 
          disabled={!connected || !authenticated || !messageInput.trim()}
        >
          Send
        </button>
        <button 
          onClick={() => socket?.emit('auth:hello')}
          disabled={!connected}
          style={{ marginLeft: '0.5rem' }}
        >
          Test Auth
        </button>
      </div>
    </div>
  );
}

export default WebSocketTest;

