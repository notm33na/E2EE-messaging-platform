import { useCallback } from 'react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

/**
 * Custom hook for token refresh
 * Handles automatic token refresh logic
 */
export function useRefreshToken() {
  const { updateAccessToken } = useAuth();

  const refreshToken = useCallback(async () => {
    try {
      const response = await api.post('/auth/refresh');
      if (response.data.success) {
        const newToken = response.data.data.accessToken;
        updateAccessToken(newToken);
        return newToken;
      }
      return null;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return null;
    }
  }, [updateAccessToken]);

  return { refreshToken };
}

