import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { formatFileTimestamp } from '../utils/formatTime';
import { getAccessToken } from '../utils/tokenStore';

/**
 * Hook to fetch file metadata from messages
 */
export function useFiles() {
  const { user } = useAuth();
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!user?.id) {
      setFiles([]);
      setLoading(false);
      return;
    }

    // Don't fetch if not authenticated
    const token = getAccessToken();
    if (!token) {
      setFiles([]);
      setLoading(false);
      return;
    }

    const fetchFiles = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Fetch pending messages which may include file metadata
        let response;
        try {
          response = await api.get(`/messages/pending/${user.id}`);
        } catch (err) {
          // Handle 403 Forbidden - user might not have access or token issue
          if (err.response?.status === 403) {
            console.warn('Access denied to pending messages. User may need to re-authenticate.');
            setError('Access denied. Please refresh the page.');
            setFiles([]);
            setLoading(false);
            return;
          }
          throw err;
        }
        
        if (response.data.success) {
          const messages = response.data.data.messages || [];
          
          // Filter for FILE_META type messages
          const fileMessages = messages.filter(msg => msg.type === 'FILE_META');
          
          // Transform to file format
          const formattedFiles = fileMessages.map(msg => ({
            id: msg.messageId,
            name: msg.meta?.filename || 'Unknown file',
            size: msg.meta?.size || 0,
            type: msg.meta?.mimetype || 'application/octet-stream',
            encrypted: true,
            uploadedAt: formatFileTimestamp(msg.createdAt || msg.timestamp),
            uploadedAtRaw: msg.createdAt || msg.timestamp,
            sessionId: msg.sessionId,
            messageId: msg.messageId
          }));

          // Sort by most recent
          formattedFiles.sort((a, b) => {
            const timeA = new Date(a.uploadedAtRaw).getTime();
            const timeB = new Date(b.uploadedAtRaw).getTime();
            return timeB - timeA;
          });

          setFiles(formattedFiles);
        }
      } catch (err) {
        console.error('Failed to fetch files:', err);
        setError(err.message);
        // Don't set error state if it's just no files found
        if (err.response?.status !== 404) {
          setError(err.message);
        }
      } finally {
        setLoading(false);
      }
    };

    fetchFiles();

    // Refresh files periodically
    const interval = setInterval(fetchFiles, 60000); // Every minute
    return () => clearInterval(interval);
  }, [user?.id]);

  // Calculate total storage used
  const totalSize = files.reduce((sum, file) => sum + (file.size || 0), 0);
  const totalSizeGB = totalSize / (1024 * 1024 * 1024); // Convert to GB
  const maxStorageGB = 10; // 10 GB limit

  return { 
    files, 
    loading, 
    error, 
    totalSize,
    totalSizeGB,
    maxStorageGB,
    storageUsed: (totalSizeGB / maxStorageGB) * 100,
    refetch: async () => {
      if (user?.id) {
        try {
          const response = await api.get(`/messages/pending/${user.id}`);
          if (response.data.success) {
            const messages = response.data.data.messages || [];
            const fileMessages = messages.filter(msg => msg.type === 'FILE_META');
            const formattedFiles = fileMessages.map(msg => ({
              id: msg.messageId,
              name: msg.meta?.filename || 'Unknown file',
              size: msg.meta?.size || 0,
            type: msg.meta?.mimetype || 'application/octet-stream',
            encrypted: true,
            uploadedAt: formatFileTimestamp(msg.createdAt || msg.timestamp),
            uploadedAtRaw: msg.createdAt || msg.timestamp,
            sessionId: msg.sessionId,
            messageId: msg.messageId
            }));
            formattedFiles.sort((a, b) => {
              const timeA = new Date(a.uploadedAtRaw).getTime();
              const timeB = new Date(b.uploadedAtRaw).getTime();
              return timeB - timeA;
            });
            setFiles(formattedFiles);
          }
        } catch (err) {
          console.error('Failed to refetch files:', err);
        }
      }
    }
  };
}

