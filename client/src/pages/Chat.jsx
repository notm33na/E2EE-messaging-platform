import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useChat } from '../hooks/useChat';
import { io } from 'socket.io-client';
import { ArrowLeft, Lock, Shield, Download } from 'lucide-react';
import { Button } from '../components/ui/button';
import { ChatBubble } from '../components/chat/ChatBubble';
import { MessageInput } from '../components/chat/MessageInput';
import { SecurityAlert } from '../components/shared/SecurityAlert';
import { FileCard } from '../components/shared/FileCard';
import { FileProgress } from '../components/chat/FileProgress';
import { ErrorMessage } from '../components/chat/ErrorMessage';
import { loadSession } from '../crypto/sessionManager.js';

export function Chat() {
  const { sessionId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const { user, accessToken } = useAuth();
  const [socket, setSocket] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  // Get peerId from route state, URL params, or session
  const [peerId, setPeerId] = useState(location.state?.peerId || null);

  const { 
    messages, 
    files, 
    isDecrypting, 
    sendMessage, 
    sendFile, 
    securityEvents,
    isEstablishingSession,
    sessionError,
    fileProgress,
    errors,
    clearError,
    isConnected,
    connectionError,
    reconnect
  } = useChat(
    sessionId,
    socket,
    peerId
  );

  // Load session to get peerId if not already set
  useEffect(() => {
    if (!sessionId || !user?.id || peerId) return;

    const loadSessionInfo = async () => {
      try {
        // Try to load session (may fail if password not cached, that's OK)
        try {
          const session = await loadSession(sessionId, user.id);
          if (session && session.peerId) {
            setPeerId(session.peerId);
          }
        } catch (loadError) {
          // Session doesn't exist or password not cached - will be established
          // peerId will need to be provided via route state or URL param
          console.log('Session not found, peerId needed for establishment');
        }
      } catch (error) {
        console.warn('Could not load session info:', error);
      }
    };

    loadSessionInfo();
  }, [sessionId, user?.id, peerId]);

  // Initialize WebSocket connection
  useEffect(() => {
    if (!accessToken || !sessionId) return;

    // In development, use Vite proxy to avoid mixed content issues
    const wsURL = import.meta.env.DEV 
      ? window.location.origin // Use same origin (Vite proxy will handle it)
      : 'https://localhost:8443';
    
    const newSocket = io(wsURL, {
      transports: ['polling', 'websocket'], // Try polling first in dev (works through proxy)
      rejectUnauthorized: false, // Allow self-signed certificates
      auth: {
        token: accessToken
      },
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: Infinity, // Always try to reconnect
      reconnectionDelayMax: 10000,
      timeout: 20000,
      forceNew: false // Reuse connection if possible
    });

    newSocket.on('connect', () => {
      console.log('Chat WebSocket connected');
      // Set up keep-alive ping to maintain connection
      const keepAliveInterval = setInterval(() => {
        if (newSocket.connected) {
          newSocket.emit('ping', { timestamp: Date.now() });
        } else {
          clearInterval(keepAliveInterval);
        }
      }, 30000); // Ping every 30 seconds
      
      // Store interval ID for cleanup
      newSocket._keepAliveInterval = keepAliveInterval;
    });

    newSocket.on('msg:sent', (data) => {
      console.log('Message sent confirmation:', data);
    });

    newSocket.on('error', (error) => {
      // Suppress repeated errors
      if (!newSocket._errorLogged) {
        console.warn('WebSocket error (this is expected in development):', error);
        newSocket._errorLogged = true;
      }
    });

    newSocket.on('connect_error', (error) => {
      // Suppress repeated connection errors
      if (!newSocket._connectErrorLogged) {
        console.warn('WebSocket connection error (this is expected in development):', error.message);
        newSocket._connectErrorLogged = true;
      }
    });

    setSocket(newSocket);

    return () => {
      // Clear keep-alive interval
      if (newSocket._keepAliveInterval) {
        clearInterval(newSocket._keepAliveInterval);
      }
      newSocket.close();
    };
  }, [accessToken, sessionId]);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, files]);

  const handleSendMessage = async (message) => {
    if (!message.trim() || sending) return;

    // Don't allow sending if session is being established
    if (isEstablishingSession) {
      alert('Please wait for the secure session to be established before sending messages.');
      return;
    }

    setSending(true);
    try {
      await sendMessage(message);
    } catch (error) {
      console.error('Failed to send message:', error);
      const errorMessage = error.message || 'Failed to send message. Please try again.';
      
      // Show user-friendly error
      if (errorMessage.includes('Session not found') || errorMessage.includes('Session is being established')) {
        alert('Please wait for the secure session to be established. This may take a few seconds.');
      } else {
        alert(errorMessage);
      }
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

  const handleAttach = () => {
    fileInputRef.current?.click();
  };

  const handleSendFile = async () => {
    if (!selectedFile || sending) return;

    setSending(true);
    try {
      await sendFile(selectedFile);
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
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

  if (!sessionId) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <p className="text-foreground">No session selected</p>
          <Button onClick={() => navigate('/dashboard')}>Go to Dashboard</Button>
        </div>
      </div>
    );
  }

  const sessionName = `Session ${sessionId.substring(0, 8)}`;
  const initials = sessionName.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="flex items-center justify-between h-16 px-4 bg-card/80 backdrop-blur-xl border-b border-border sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate('/dashboard')}>
            <ArrowLeft className="w-5 h-5" />
          </Button>
          
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary/80 to-accent flex items-center justify-center">
                <span className="text-sm font-semibold text-primary-foreground">{initials}</span>
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-semibold text-foreground">{sessionName}</span>
                <Lock className="w-3.5 h-3.5 text-success" />
              </div>
              <span className="text-xs text-muted-foreground">
                Encrypted session
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Encryption Banner */}
      <div className="flex items-center justify-center gap-2 py-2 bg-success/5 border-b border-success/10">
        <Shield className="w-3.5 h-3.5 text-success" />
        <span className="text-xs text-success">Messages are end-to-end encrypted</span>
      </div>

      {/* Session Establishment Status */}
      {isEstablishingSession && (
        <div className="flex items-center justify-center gap-2 py-3 bg-primary/5 border-b border-primary/10">
          <div className="w-4 h-4 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <span className="text-xs text-primary">Establishing secure connection...</span>
        </div>
      )}

      {sessionError && (
        <div className="px-4 pt-4">
          <SecurityAlert
            severity="high"
            title="Session Establishment Failed"
            description={sessionError}
            timestamp={new Date().toLocaleString()}
          />
        </div>
      )}

      {/* Security Events */}
      {securityEvents && securityEvents.length > 0 && (
        <div className="px-4 pt-4 space-y-2">
          <SecurityAlert
            severity={securityEvents[securityEvents.length - 1].type === 'replay' ? 'high' : 'medium'}
            title={securityEvents[securityEvents.length - 1].type === 'replay' ? 'Replay Attack Detected' : 'Integrity Check Failed'}
            description={
              securityEvents[securityEvents.length - 1].type === 'replay'
                ? 'Potential replay attack detected. The affected message was blocked and not shown.'
                : 'Message integrity verification failed. The affected message was blocked and not shown.'
            }
            timestamp={new Date(securityEvents[securityEvents.length - 1].timestamp).toLocaleString()}
          />
        </div>
      )}

      {/* Connection Status */}
      {!isConnected && (
        <div className="px-4 pt-4">
          <ErrorMessage
            title="Connection Lost"
            message={connectionError || "Disconnected from server. Attempting to reconnect..."}
            variant="warning"
            onRetry={reconnect}
          />
        </div>
      )}

      {/* Error Messages */}
      {errors && errors.length > 0 && (
        <div className="px-4 pt-4 space-y-2">
          {errors.map((error) => (
            <ErrorMessage
              key={error.id}
              title={error.title}
              message={error.message}
              variant={error.variant}
              onDismiss={() => clearError(error.id)}
            />
          ))}
        </div>
      )}

      {/* File Progress */}
      {fileProgress && (
        <div className="px-4 pt-4">
          <FileProgress
            filename={fileProgress.filename}
            progress={fileProgress.progress}
            speed={fileProgress.speed}
            timeRemaining={fileProgress.timeRemaining}
            type={fileProgress.type}
            onCancel={() => {
              // Cancel file operation (if needed)
              console.log('File operation cancelled');
            }}
          />
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-1 scrollbar-thin">
        {messages
          .sort((a, b) => (a.seq || 0) - (b.seq || 0)) // Ensure sorted by sequence
          .map((msg, i) => (
            <ChatBubble
              key={msg.id}
              message={msg.type === 'text' ? msg.content : '[File]'}
              timestamp={new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              isSender={msg.sender === user.id}
              isRead={true}
              isEncrypted={true}
              className="animate-fade-in"
              style={{ animationDelay: `${i * 50}ms` }}
            />
          ))}

        {files.map((file, i) => (
          <div key={file.id} className="flex w-full mb-3 animate-fade-in justify-start">
            <div className="max-w-[80%] sm:max-w-[70%] lg:max-w-[60%] rounded-2xl px-4 py-3 bg-secondary text-secondary-foreground">
              <div className="flex items-center gap-3 p-2.5 rounded-lg mb-2 bg-background/50">
                <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-primary/20">
                  <Download className="w-5 h-5 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{file.filename}</p>
                  <p className="text-xs text-muted-foreground">
                    {(file.size / 1024).toFixed(2)} KB
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => handleDownloadFile(file)}
                  className="flex-shrink-0"
                >
                  <Download className="w-4 h-4" />
                </Button>
              </div>
              <div className="flex items-center gap-1.5 mt-1.5 justify-start">
                <Lock className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground">
                  {new Date(file.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            </div>
          </div>
        ))}

        {isDecrypting && (
          <div className="flex w-full justify-center mb-3">
            <div className="px-4 py-2 rounded-xl bg-muted text-muted-foreground text-sm">
              Decrypting...
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* File Preview */}
      {selectedFile && (
        <div className="px-4 py-2 bg-card border-t border-border flex items-center justify-between">
          <span className="text-sm text-foreground">📎 {selectedFile.name}</span>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSelectedFile(null)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSendFile}
              disabled={sending}
            >
              {sending ? 'Sending...' : 'Send File'}
            </Button>
          </div>
        </div>
      )}

      {/* Message Input */}
      <div className="sticky bottom-0 pb-safe">
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />
        <MessageInput
          onSend={handleSendMessage}
          onAttach={handleAttach}
        />
      </div>
    </div>
  );
}
