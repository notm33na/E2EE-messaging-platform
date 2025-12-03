import { useState, useEffect, useCallback } from 'react';

/**
 * Hook to manage WebSocket connection state
 * Provides connection status and automatic reconnection
 */
export function useConnectionState(socket) {
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState(null);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);

  useEffect(() => {
    if (!socket) {
      setIsConnected(false);
      return;
    }

    const onConnect = () => {
      setIsConnected(true);
      setConnectionError(null);
      setReconnectAttempts(0);
      console.log('✓ WebSocket connected');
    };

    const onDisconnect = (reason) => {
      setIsConnected(false);
      // Always try to reconnect, regardless of reason
      if (reason === 'io server disconnect') {
        // Server disconnected, reconnect manually
        socket.connect();
      } else {
        // For other disconnects, socket.io will auto-reconnect
        // But we can also manually trigger if needed
        setTimeout(() => {
          if (!socket.connected) {
            socket.connect();
          }
        }, 1000);
      }
      console.log('WebSocket disconnected:', reason);
    };

    const onConnectError = (error) => {
      setIsConnected(false);
      setConnectionError(error.message || 'Connection failed');
      setReconnectAttempts(prev => prev + 1);
      console.warn('WebSocket connection error:', error);
    };

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onConnectError);

    // Check initial connection state
    setIsConnected(socket.connected);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onConnectError);
    };
  }, [socket]);

  const reconnect = useCallback(() => {
    if (socket && !socket.connected) {
      socket.connect();
    }
  }, [socket]);

  return {
    isConnected,
    connectionError,
    reconnectAttempts,
    reconnect
  };
}

