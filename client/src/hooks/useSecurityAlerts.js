import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { getUserSessions } from '../crypto/sessionManager';
import { getLogs } from '../utils/clientLogger';

/**
 * Hook to aggregate security alerts from all sessions
 * Includes replay attempts, MITM attacks, signature failures, and other security events
 */
export function useSecurityAlerts() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!user?.id) {
      setAlerts([]);
      setLoading(false);
      return;
    }

    const fetchAlerts = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Get security logs from IndexedDB
        const securityLogs = await getLogs({
          userId: user.id,
          limit: 200 // Get recent 200 security events
        });

        // Transform logs into alerts
        const alertsList = securityLogs.map(log => {
          const event = log.event;
          const metadata = log.metadata || {};
          
          // Determine severity based on event type
          let severity = 'medium';
          let title = 'Security Event';
          let message = metadata.reason || 'Security event detected';
          
          switch (event) {
            case 'replay_attempt':
              severity = 'high';
              title = 'Replay Attack Detected';
              message = `Replay attempt blocked: ${metadata.reason || 'Duplicate message detected'}`;
              if (metadata.seq) {
                message += ` (seq: ${metadata.seq})`;
              }
              break;
              
            case 'mitm_attack':
              severity = 'critical';
              title = 'MITM Attack Detected';
              message = metadata.reason || 'Man-in-the-middle attack detected';
              if (metadata.attackType) {
                message += ` (Type: ${metadata.attackType})`;
              }
              break;
              
            case 'mitm_demonstration':
              severity = metadata.attackSuccessful ? 'critical' : 'high';
              title = metadata.attackSuccessful 
                ? 'MITM Attack Successful (Demo)' 
                : 'MITM Attack Blocked (Demo)';
              message = metadata.reason || 
                (metadata.attackSuccessful 
                  ? 'MITM attack demonstration succeeded' 
                  : 'MITM attack blocked by signature verification');
              if (metadata.scenario) {
                message += ` (Scenario: ${metadata.scenario})`;
              }
              break;
              
            case 'invalid_signature':
              severity = 'critical';
              title = 'Invalid Signature Detected';
              message = `Signature verification failed: ${metadata.reason || 'Invalid signature'}`;
              if (metadata.messageType) {
                message += ` (Message: ${metadata.messageType})`;
              }
              break;
              
            case 'decryption_error':
              severity = 'high';
              title = 'Decryption Failed';
              message = `Message decryption failed: ${metadata.reason || 'Decryption error'}`;
              if (metadata.seq) {
                message += ` (seq: ${metadata.seq})`;
              }
              break;
              
            case 'kep_error':
              severity = 'high';
              title = 'Key Exchange Error';
              message = `Key exchange failed: ${metadata.reason || 'KEP error'}`;
              if (metadata.messageType) {
                message += ` (Type: ${metadata.messageType})`;
              }
              break;
              
            case 'timestamp_failure':
              severity = 'medium';
              title = 'Timestamp Validation Failed';
              message = `Message timestamp invalid: ${metadata.reason || 'Timestamp out of window'}`;
              if (metadata.seq) {
                message += ` (seq: ${metadata.seq})`;
              }
              break;
              
            case 'seq_mismatch':
              severity = 'high';
              title = 'Sequence Number Mismatch';
              message = metadata.reason || 'Sequence number validation failed';
              if (metadata.seq) {
                message += ` (seq: ${metadata.seq})`;
              }
              break;
              
            case 'message_dropped':
              severity = 'medium';
              title = 'Message Dropped';
              message = `Message dropped: ${metadata.reason || 'Message validation failed'}`;
              if (metadata.seq) {
                message += ` (seq: ${metadata.seq})`;
              }
              break;
              
            default:
              severity = 'medium';
              title = 'Security Event';
              message = metadata.reason || `Event: ${event}`;
          }
          
          return {
            id: log.id || `${event}-${log.timestamp}`,
            title,
            message,
            description: message,
            severity,
            timestamp: log.timestamp,
            sessionId: log.sessionId,
            eventType: event,
            metadata
          };
        });

        // Get all sessions to check for stale sessions
        const sessions = await getUserSessions(user.id);
        sessions.forEach(session => {
          const lastUpdate = new Date(session.updatedAt || session.createdAt).getTime();
          const daysSinceUpdate = (Date.now() - lastUpdate) / (1000 * 60 * 60 * 24);
          
          if (daysSinceUpdate > 90) {
            alertsList.push({
              id: `session-stale-${session.sessionId}`,
              title: 'Stale Session Detected',
              message: `Session ${session.sessionId.substring(0, 8)}... has been inactive for ${Math.floor(daysSinceUpdate)} days`,
              description: `Session ${session.sessionId.substring(0, 8)}... has been inactive for ${Math.floor(daysSinceUpdate)} days`,
              severity: 'low',
              timestamp: session.updatedAt || session.createdAt,
              sessionId: session.sessionId,
              eventType: 'stale_session'
            });
          }
        });

        // Sort by timestamp (most recent first)
        alertsList.sort((a, b) => {
          const timeA = new Date(a.timestamp).getTime();
          const timeB = new Date(b.timestamp).getTime();
          return timeB - timeA;
        });

        setAlerts(alertsList);
      } catch (err) {
        console.error('Failed to fetch security alerts:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();

    // Refresh alerts periodically
    const interval = setInterval(fetchAlerts, 60000); // Every minute
    return () => clearInterval(interval);
  }, [user?.id]);

  return { 
    alerts, 
    loading, 
    error,
    refetch: async () => {
      if (user?.id) {
        try {
          // Refetch security logs from IndexedDB
          const securityLogs = await getLogs({
            userId: user.id,
            limit: 200
          });

          const alertsList = securityLogs.map(log => {
            const event = log.event;
            const metadata = log.metadata || {};
            
            let severity = 'medium';
            let title = 'Security Event';
            let message = metadata.reason || 'Security event detected';
            
            switch (event) {
              case 'replay_attempt':
                severity = 'high';
                title = 'Replay Attack Detected';
                message = `Replay attempt blocked: ${metadata.reason || 'Duplicate message detected'}`;
                break;
              case 'mitm_attack':
                severity = 'critical';
                title = 'MITM Attack Detected';
                message = metadata.reason || 'Man-in-the-middle attack detected';
                break;
              case 'mitm_demonstration':
                severity = metadata.attackSuccessful ? 'critical' : 'high';
                title = metadata.attackSuccessful ? 'MITM Attack Successful (Demo)' : 'MITM Attack Blocked (Demo)';
                message = metadata.reason || (metadata.attackSuccessful ? 'MITM attack demonstration succeeded' : 'MITM attack blocked');
                break;
              case 'invalid_signature':
                severity = 'critical';
                title = 'Invalid Signature Detected';
                message = `Signature verification failed: ${metadata.reason || 'Invalid signature'}`;
                break;
              default:
                severity = 'medium';
                title = 'Security Event';
                message = metadata.reason || `Event: ${event}`;
            }
            
            return {
              id: log.id || `${event}-${log.timestamp}`,
              title,
              message,
              description: message,
              severity,
              timestamp: log.timestamp,
              sessionId: log.sessionId,
              eventType: event,
              metadata
            };
          });

          // Add stale session alerts
          const sessions = await getUserSessions(user.id);
          sessions.forEach(session => {
            const lastUpdate = new Date(session.updatedAt || session.createdAt).getTime();
            const daysSinceUpdate = (Date.now() - lastUpdate) / (1000 * 60 * 60 * 24);
            
            if (daysSinceUpdate > 90) {
              alertsList.push({
                id: `session-stale-${session.sessionId}`,
                title: 'Stale Session Detected',
                message: `Session ${session.sessionId.substring(0, 8)}... has been inactive for ${Math.floor(daysSinceUpdate)} days`,
                description: `Session ${session.sessionId.substring(0, 8)}... has been inactive for ${Math.floor(daysSinceUpdate)} days`,
                severity: 'low',
                timestamp: session.updatedAt || session.createdAt,
                sessionId: session.sessionId,
                eventType: 'stale_session'
              });
            }
          });

          alertsList.sort((a, b) => {
            const timeA = new Date(a.timestamp).getTime();
            const timeB = new Date(b.timestamp).getTime();
            return timeB - timeA;
          });

          setAlerts(alertsList);
        } catch (err) {
          console.error('Failed to refetch alerts:', err);
        }
      }
    }
  };
}

