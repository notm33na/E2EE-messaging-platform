import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { getUserSessions } from '../crypto/sessionManager';
import api from '../services/api';
import { getAccessToken } from '../utils/tokenStore';
import { getLogs } from '../utils/clientLogger';

/**
 * Hook to fetch audit logs from API
 */
export function useLogs() {
  const { user } = useAuth();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!user?.id) {
      setLogs([]);
      setLoading(false);
      return;
    }

    // Don't fetch if not authenticated
    const token = getAccessToken();
    if (!token) {
      setLogs([]);
      setLoading(false);
      return;
    }

    const fetchLogs = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const allLogs = [];
        
        // Get client-side security logs from IndexedDB
        // Try with userId first, then without if no results
        let clientLogs = await getLogs({
          userId: user.id,
          limit: 100
        });
        
        // If no logs found with userId filter, try without filter (in case userId wasn't set)
        if (clientLogs.length === 0) {
          console.log('[useLogs] No logs found with userId filter, trying without filter...');
          clientLogs = await getLogs({
            limit: 100
          });
        }
        
        console.log(`[useLogs] Found ${clientLogs.length} client logs`);
        
        // Transform client logs to log format
        clientLogs.forEach(log => {
          try {
            const event = log.event;
            const metadata = log.metadata || {};
            // Additional metadata is stored directly in metadata object (spread from metadata.additional)
            const additional = metadata.additional || {};
            
            // Determine log level based on event type
            let level = 'info';
            let title = event.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            let message = metadata.reason || `Event: ${event}`;
            
            switch (event) {
              case 'replay_attempt':
                level = 'warning';
                title = 'Replay Attempt';
                message = `Replay attempt detected: ${metadata.reason || 'Duplicate message'}`;
                if (metadata.seq) message += ` (seq: ${metadata.seq})`;
                break;
              case 'mitm_attack':
                level = 'error';
                title = 'MITM Attack';
                message = metadata.reason || 'Man-in-the-middle attack detected';
                if (metadata.attackType) message += ` (Type: ${metadata.attackType})`;
                else if (additional.attackType) message += ` (Type: ${additional.attackType})`;
                break;
            case 'mitm_demonstration':
              // Check both locations for attackSuccessful (it's spread into metadata from additional)
              const attackSuccessful = metadata.attackSuccessful !== undefined 
                ? metadata.attackSuccessful 
                : (additional.attackSuccessful !== undefined ? additional.attackSuccessful : false);
              level = attackSuccessful ? 'error' : 'warning';
              title = 'MITM Demonstration';
              message = metadata.reason || (attackSuccessful ? 'MITM attack succeeded' : 'MITM attack blocked');
              if (metadata.scenario) message += ` (Scenario: ${metadata.scenario})`;
              else if (additional.scenario) message += ` (Scenario: ${additional.scenario})`;
              break;
              case 'invalid_signature':
                level = 'error';
                title = 'Invalid Signature';
                message = `Signature verification failed: ${metadata.reason || 'Invalid signature'}`;
                if (metadata.messageType) message += ` (Message: ${metadata.messageType})`;
                break;
              case 'decryption_error':
                level = 'error';
                title = 'Decryption Error';
                message = `Decryption failed: ${metadata.reason || 'Decryption error'}`;
                if (metadata.seq) message += ` (seq: ${metadata.seq})`;
                break;
              case 'kep_error':
                level = 'error';
                title = 'Key Exchange Error';
                message = `Key exchange failed: ${metadata.reason || 'KEP error'}`;
                if (metadata.messageType) message += ` (Type: ${metadata.messageType})`;
                break;
              case 'timestamp_failure':
                level = 'warning';
                title = 'Timestamp Failure';
                message = `Timestamp validation failed: ${metadata.reason || 'Timestamp out of window'}`;
                if (metadata.seq) message += ` (seq: ${metadata.seq})`;
                break;
              case 'seq_mismatch':
                level = 'warning';
                title = 'Sequence Mismatch';
                message = metadata.reason || 'Sequence number validation failed';
                if (metadata.seq) message += ` (seq: ${metadata.seq})`;
                break;
              case 'message_dropped':
                level = 'warning';
                title = 'Message Dropped';
                message = `Message dropped: ${metadata.reason || 'Validation failed'}`;
                if (metadata.seq) message += ` (seq: ${metadata.seq})`;
                break;
              default:
                level = 'info';
                title = event.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                message = metadata.reason || `Event: ${event}`;
            }
            
            allLogs.push({
              id: log.id || `${event}-${log.timestamp}-${Math.random()}`,
              title,
              message,
              level,
              timestamp: log.timestamp,
              source: 'Client',
              sessionId: log.sessionId || null,
              eventType: event,
              metadata
            });
          } catch (err) {
            console.error('[useLogs] Error transforming log entry:', err, log);
            // Add a fallback log entry so we can see there was an error
            allLogs.push({
              id: log.id || `error-${Date.now()}-${Math.random()}`,
              title: 'Log Entry Error',
              message: `Failed to parse log entry: ${err.message}`,
              level: 'error',
              timestamp: log.timestamp || new Date().toISOString(),
              source: 'Client',
              sessionId: log.sessionId || null,
              eventType: log.event || 'unknown'
            });
          }
        });
        
        // Get all sessions to fetch audit trails from server
        const sessions = await getUserSessions(user.id);
        
        // Fetch audit trails for each session
        for (const session of sessions.slice(0, 10)) { // Limit to first 10 sessions
          try {
            const response = await api.get(`/audit/session/${session.sessionId}`);
            if (response.data.success && response.data.data.auditTrail) {
              const auditTrail = response.data.data.auditTrail;
              
              // Transform audit trail entries to log format
              auditTrail.forEach(entry => {
                allLogs.push({
                  id: `${entry.messageId}-${entry.timestamp}`,
                  title: entry.action,
                  message: `Action: ${entry.action} on message ${entry.messageId.substring(0, 8)}...`,
                  level: entry.action.includes('error') || entry.action.includes('failed') ? 'error' :
                         entry.action.includes('warning') ? 'warning' :
                         entry.action.includes('success') ? 'success' : 'info',
                  timestamp: entry.timestamp,
                  source: entry.changedBy || 'System',
                  sessionId: session.sessionId,
                  messageId: entry.messageId
                });
              });
            }
          } catch (sessionErr) {
            // Skip sessions that fail (might not have audit trail)
            console.warn(`Failed to fetch audit trail for session ${session.sessionId}:`, sessionErr);
          }
        }

        // Sort by timestamp (most recent first)
        allLogs.sort((a, b) => {
          const timeA = new Date(a.timestamp).getTime();
          const timeB = new Date(b.timestamp).getTime();
          return timeB - timeA;
        });

        // Limit to most recent 100 logs
        setLogs(allLogs.slice(0, 100));
      } catch (err) {
        console.error('Failed to fetch logs:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();

    // Refresh logs periodically
    const interval = setInterval(fetchLogs, 120000); // Every 2 minutes
    return () => clearInterval(interval);
  }, [user?.id]);

  return { 
    logs, 
    loading, 
    error,
    refetch: async () => {
      if (user?.id) {
        try {
          const allLogs = [];
          
          // Refetch client-side logs
          let clientLogs = await getLogs({
            userId: user.id,
            limit: 100
          });
          
          // If no logs found with userId filter, try without filter
          if (clientLogs.length === 0) {
            clientLogs = await getLogs({
              limit: 100
            });
          }
          
          clientLogs.forEach(log => {
            try {
              const event = log.event;
              const metadata = log.metadata || {};
              const additional = metadata.additional || {};
              
              let level = 'info';
              let title = event.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
              let message = metadata.reason || `Event: ${event}`;
              
              switch (event) {
                case 'replay_attempt':
                  level = 'warning';
                  title = 'Replay Attempt';
                  message = `Replay attempt detected: ${metadata.reason || 'Duplicate message'}`;
                  if (metadata.seq) message += ` (seq: ${metadata.seq})`;
                  break;
                case 'mitm_attack':
                  level = 'error';
                  title = 'MITM Attack';
                  message = metadata.reason || 'Man-in-the-middle attack detected';
                  if (additional.attackType) message += ` (Type: ${additional.attackType})`;
                  break;
                case 'mitm_demonstration':
                  const attackSuccessful = metadata.attackSuccessful !== undefined 
                    ? metadata.attackSuccessful 
                    : (additional.attackSuccessful !== undefined ? additional.attackSuccessful : false);
                  level = attackSuccessful ? 'error' : 'warning';
                  title = 'MITM Demonstration';
                  message = metadata.reason || (attackSuccessful ? 'MITM attack succeeded' : 'MITM attack blocked');
                  if (metadata.scenario) message += ` (Scenario: ${metadata.scenario})`;
                  else if (additional.scenario) message += ` (Scenario: ${additional.scenario})`;
                  break;
                case 'invalid_signature':
                  level = 'error';
                  title = 'Invalid Signature';
                  message = `Signature verification failed: ${metadata.reason || 'Invalid signature'}`;
                  break;
                case 'decryption_error':
                  level = 'error';
                  title = 'Decryption Error';
                  message = `Decryption failed: ${metadata.reason || 'Decryption error'}`;
                  break;
                case 'kep_error':
                  level = 'error';
                  title = 'Key Exchange Error';
                  message = `Key exchange failed: ${metadata.reason || 'KEP error'}`;
                  break;
                case 'timestamp_failure':
                  level = 'warning';
                  title = 'Timestamp Failure';
                  message = `Timestamp validation failed: ${metadata.reason || 'Timestamp out of window'}`;
                  break;
                case 'seq_mismatch':
                  level = 'warning';
                  title = 'Sequence Mismatch';
                  message = metadata.reason || 'Sequence number validation failed';
                  break;
                case 'message_dropped':
                  level = 'warning';
                  title = 'Message Dropped';
                  message = `Message dropped: ${metadata.reason || 'Validation failed'}`;
                  break;
                default:
                  level = 'info';
                  title = event.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                  message = metadata.reason || `Event: ${event}`;
              }
              
              allLogs.push({
                id: log.id || `${event}-${log.timestamp}-${Date.now()}`,
                title,
                message,
                level,
                timestamp: log.timestamp,
                source: 'Client',
                sessionId: log.sessionId || null,
                eventType: event
              });
            } catch (err) {
              console.error('Error transforming log entry in refetch:', err, log);
            }
          });
          
          // Refetch server audit trails
          const sessions = await getUserSessions(user.id);
          for (const session of sessions.slice(0, 10)) {
            try {
              const response = await api.get(`/audit/session/${session.sessionId}`);
              if (response.data.success && response.data.data.auditTrail) {
                const auditTrail = response.data.data.auditTrail;
                auditTrail.forEach(entry => {
                  allLogs.push({
                    id: `${entry.messageId}-${entry.timestamp}`,
                    title: entry.action,
                    message: `Action: ${entry.action} on message ${entry.messageId.substring(0, 8)}...`,
                    level: entry.action.includes('error') || entry.action.includes('failed') ? 'error' :
                           entry.action.includes('warning') ? 'warning' :
                           entry.action.includes('success') ? 'success' : 'info',
                    timestamp: entry.timestamp,
                    source: entry.changedBy || 'System',
                    sessionId: session.sessionId,
                    messageId: entry.messageId
                  });
                });
              }
            } catch (sessionErr) {
              console.warn(`Failed to fetch audit trail for session ${session.sessionId}:`, sessionErr);
            }
          }

          allLogs.sort((a, b) => {
            const timeA = new Date(a.timestamp).getTime();
            const timeB = new Date(b.timestamp).getTime();
            return timeB - timeA;
          });

          setLogs(allLogs.slice(0, 100));
        } catch (err) {
          console.error('Failed to refetch logs:', err);
        }
      }
    }
  };
}

