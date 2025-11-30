import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api from '../services/api';
import { setAccessToken as setTokenStore, clearAccessToken, setTokenUpdateCallback } from '../utils/tokenStore';
import { generateIdentityKeyPair, storePrivateKeyEncrypted, exportPublicKey } from '../crypto/identityKeys.js';

const AuthContext = createContext(null);

/**
 * AuthProvider component
 * Manages authentication state and provides auth methods
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  /**
   * Attempts to refresh the access token using refresh token cookie
   */
  const refreshAccessToken = useCallback(async () => {
    try {
      const response = await api.post('/auth/refresh');
      if (response.data.success) {
        const newToken = response.data.data.accessToken;
        setAccessToken(newToken);
        setTokenStore(newToken); // Also update token store
        return newToken;
      }
      return null;
    } catch (error) {
      console.error('Token refresh failed:', error);
      setAccessToken(null);
      setUser(null);
      return null;
    }
  }, []);

  /**
   * Fetches current user information
   */
  const fetchUser = useCallback(async (token) => {
    try {
      const response = await api.get('/auth/me', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (response.data.success) {
        setUser(response.data.data.user);
        return response.data.data.user;
      }
      return null;
    } catch (error) {
      console.error('Failed to fetch user:', error);
      return null;
    }
  }, []);

  /**
   * Initializes auth state on mount
   */
  useEffect(() => {
    // Set up token update callback
    setTokenUpdateCallback((token) => {
      setAccessToken(token);
    });

    const initializeAuth = async () => {
      try {
        // Try to refresh token first
        const token = await refreshAccessToken();
        if (token) {
          setTokenStore(token); // Update token store
          // Fetch user info
          await fetchUser(token);
        }
      } catch (error) {
        console.error('Auth initialization failed:', error);
      } finally {
        setLoading(false);
      }
    };

    initializeAuth();
  }, [refreshAccessToken, fetchUser]);

  /**
   * Login function
   */
  const login = async (email, password) => {
    try {
      setError(null);
      const response = await api.post('/auth/login', { email, password });
      
      if (response.data.success) {
        const { user, accessToken: token } = response.data.data;
        setUser(user);
        setAccessToken(token);
        return { success: true, user };
      }
      
      throw new Error(response.data.message || 'Login failed');
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.message || 'Login failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  /**
   * Register function
   * Also generates and stores identity key pair
   */
  const register = async (email, password) => {
    try {
      setError(null);
      
      // Generate identity key pair
      console.log('Generating identity key pair...');
      const { privateKey, publicKey } = await generateIdentityKeyPair();
      
      // Export public key for upload
      const publicKeyJWK = await exportPublicKey(publicKey);
      
      // Register user
      const response = await api.post('/auth/register', { email, password });
      
      if (response.data.success) {
        const { user, accessToken: token } = response.data.data;
        setUser(user);
        setAccessToken(token);
        setTokenStore(token);
        
        // Store private key encrypted with password
        await storePrivateKeyEncrypted(user.id, privateKey, password);
        console.log('✓ Identity private key stored securely');
        
        // Upload public key to server
        try {
          await api.post('/keys/upload', { publicIdentityKeyJWK: publicKeyJWK });
          console.log('✓ Identity public key uploaded to server');
        } catch (keyError) {
          console.error('Failed to upload public key:', keyError);
          // Non-fatal - user can upload later
        }
        
        return { success: true, user };
      }
      
      throw new Error(response.data.message || 'Registration failed');
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.message || 'Registration failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  /**
   * Logout function
   */
  const logout = async () => {
    try {
      if (accessToken) {
        await api.post('/auth/logout', {}, {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setUser(null);
      setAccessToken(null);
      clearAccessToken(); // Clear token store
      setError(null);
    }
  };

  /**
   * Updates access token (used by interceptors)
   */
  const updateAccessToken = useCallback((token) => {
    setAccessToken(token);
    setTokenStore(token); // Also update token store
  }, []);

  const value = {
    user,
    accessToken,
    loading,
    error,
    isAuthenticated: !!user && !!accessToken,
    login,
    register,
    logout,
    refreshAccessToken,
    updateAccessToken,
    clearError: () => setError(null)
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * useAuth hook
 * Provides access to auth context
 */
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

