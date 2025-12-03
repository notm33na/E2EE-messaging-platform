import axios from 'axios';
import { getAccessToken, notifyTokenUpdate } from '../utils/tokenStore.js';

/**
 * Axios instance configured for the secure backend API
 * Uses Vite proxy in development to handle self-signed certificates
 * In production, use the full HTTPS URL
 */
const baseURL = import.meta.env.DEV 
  ? '/api'  // Use Vite proxy in development
  : 'https://localhost:8443/api';  // Direct connection in production

const api = axios.create({
  baseURL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true, // Include cookies (for refresh token)
  validateStatus: (status) => status < 500 // Don't throw on 4xx errors
});

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  
  failedQueue = [];
};

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add access token from memory store
    const token = getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor with auto-refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 Unauthorized - token expired or invalid
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // If already refreshing, queue this request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(token => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch(err => {
            return Promise.reject(err);
          });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Attempt to refresh token
        const response = await axios.post(`${baseURL}/auth/refresh`, {}, {
          withCredentials: true,
          timeout: 5000
        });

        if (response.data && response.data.success) {
          const newToken = response.data.data.accessToken;
          notifyTokenUpdate(newToken);
          processQueue(null, newToken);
          
          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
          // Remove the retry flag so we can retry
          delete originalRequest._retry;
          return api(originalRequest);
        } else {
          throw new Error('Token refresh failed: Invalid response');
        }
      } catch (refreshError) {
        processQueue(refreshError, null);
        // Clear token
        notifyTokenUpdate(null);
        
        // Mark that we tried to refresh (so components know refresh failed)
        originalRequest._retry = true;
        
        // If refresh failed with 401, the refresh token is also expired
        if (refreshError.response?.status === 401) {
          console.warn('Token refresh failed: Refresh token expired. User needs to log in again.');
        } else if (refreshError.code === 'ECONNREFUSED' || refreshError.message?.includes('Network Error')) {
          console.error('Token refresh failed: Cannot connect to server.');
        } else {
          console.error('Token refresh failed:', refreshError.message);
        }
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // Handle other errors
    if (error.response) {
      // Server responded with error status
      console.error('API Error:', error.response.data);
    } else if (error.request) {
      // Request made but no response received
      // Check if it's a connection refused error
      if (error.code === 'ECONNREFUSED' || error.message.includes('Network Error')) {
        console.error('Network Error: Backend server is not running or not accessible.');
        console.error('Please ensure the backend server is running on https://localhost:8443');
        // Don't spam console with network errors - only log once
        if (!window.__backendConnectionErrorLogged) {
          console.error('To start the backend server, run: cd server && npm run dev');
          window.__backendConnectionErrorLogged = true;
        }
      } else {
        console.error('Network Error:', error.message);
      }
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }
    
    return Promise.reject(error);
  }
);

export default api;

