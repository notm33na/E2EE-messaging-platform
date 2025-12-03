import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useChatSessions } from './useChatSessions';
import { useFiles } from './useFiles';
import { useKeys } from './useKeys';
import { useSecurityAlerts } from './useSecurityAlerts';
import api from '../services/api';
import { getAccessToken } from '../utils/tokenStore';

/**
 * Hook to fetch dashboard statistics
 */
export function useDashboardStats() {
  const { user } = useAuth();
  const { sessions } = useChatSessions();
  const { files } = useFiles();
  const { keys } = useKeys();
  const { alerts } = useSecurityAlerts();
  const [stats, setStats] = useState({
    messages: 0,
    contacts: 0,
    filesShared: 0,
    activeKeys: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!user?.id) {
      setLoading(false);
      return;
    }

    // Don't fetch if not authenticated
    const token = getAccessToken();
    if (!token) {
      setLoading(false);
      return;
    }

    const fetchStats = async () => {
      try {
        setLoading(true);
        setError(null);

        // Get message count from pending messages
        let messageCount = 0;
        try {
          const response = await api.get(`/messages/pending/${user.id}`);
          if (response.data.success) {
            messageCount = response.data.data.messages?.length || 0;
          }
        } catch (err) {
          // Handle 403 Forbidden gracefully - don't show error, just use 0 count
          if (err.response?.status === 403) {
            console.warn('Access denied to pending messages. Using 0 message count.');
          } else {
            console.warn('Failed to fetch message count:', err);
          }
        }

        // Calculate stats from hooks data
        const contacts = new Set(sessions.map(s => s.peerId || s.userId)).size;
        const filesShared = files.length;
        const activeKeys = keys.filter(k => k.status === 'active').length;

        setStats({
          messages: messageCount,
          contacts: contacts,
          filesShared: filesShared,
          activeKeys: activeKeys || 1, // At least 1 if user is logged in
        });
      } catch (err) {
        console.error('Failed to fetch dashboard stats:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, [user?.id, sessions, files, keys]);

  return { stats, loading, error, alerts: alerts.slice(0, 3) };
}

