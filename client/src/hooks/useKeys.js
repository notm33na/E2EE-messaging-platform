import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { hasIdentityKey } from '../crypto/identityKeys';
import { getUserSessions } from '../crypto/sessionManager';
import api from '../services/api';
import { getAccessToken } from '../utils/tokenStore';

/**
 * Generate a fingerprint from key data (ArrayBuffer or string)
 */
function generateKeyFingerprint(keyData) {
  try {
    let dataString;
    if (keyData instanceof ArrayBuffer) {
      // Convert ArrayBuffer to hex string
      const bytes = new Uint8Array(keyData);
      dataString = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    } else if (typeof keyData === 'string') {
      dataString = keyData;
    } else {
      return 'Unknown';
    }
    
    // Simple hash for display
    const hash = dataString.split('').reduce((acc, char) => {
      return ((acc << 5) - acc) + char.charCodeAt(0) | 0;
    }, 0).toString(16).substring(0, 20);
    
    return hash.match(/.{1,4}/g)?.join(' ') || hash;
  } catch (err) {
    console.warn('Failed to generate fingerprint:', err);
    return 'Unknown';
  }
}

/**
 * Hook to fetch and manage encryption keys
 */
export function useKeys() {
  const { user } = useAuth();
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAllKeys = async () => {
    if (!user?.id) {
      setKeys([]);
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      const keysList = [];

      // 1. Fetch Identity Keys (from local IndexedDB - doesn't require server)
      try {
        const hasKey = await hasIdentityKey(user.id);
        console.log('[useKeys] Identity key exists:', hasKey);
        
        if (hasKey) {
          // Try to fetch public key from server (optional - for additional metadata)
          let publicKeyInfo = null;
          const token = getAccessToken();
          if (token) {
            try {
              const response = await api.get('/keys/me');
              if (response.data.success && response.data.data) {
                publicKeyInfo = response.data.data;
              }
            } catch (keyErr) {
              // Server fetch failed, but we can still show the key from IndexedDB
              console.warn('[useKeys] Failed to fetch public key from server (will show local key):', keyErr.message);
            }
          }

          // Generate fingerprint - use a default if we don't have public key info
          let fingerprint = 'Local key (fingerprint unavailable)';
          if (publicKeyInfo?.publicIdentityKeyJWK) {
            try {
              // Create a simple fingerprint from JWK
              const jwk = publicKeyInfo.publicIdentityKeyJWK;
              const keyData = `${jwk.kty}-${jwk.crv}-${jwk.x?.substring(0, 8)}-${jwk.y?.substring(0, 8)}`;
              // Simple hash for display
              fingerprint = keyData.split('').reduce((acc, char) => {
                return ((acc << 5) - acc) + char.charCodeAt(0) | 0;
              }, 0).toString(16).substring(0, 20).match(/.{1,4}/g)?.join(' ') || 'Unknown';
            } catch (err) {
              console.warn('[useKeys] Failed to generate fingerprint:', err);
            }
          }

          keysList.push({
            id: 'identity-key',
            name: 'Identity Key (ECC P-256)',
            type: 'Identity Key',
            keyType: 'ECC P-256',
            category: 'identity',
            status: 'active',
            fingerprint: fingerprint,
            createdAt: publicKeyInfo?.createdAt || publicKeyInfo?.updatedAt || new Date().toISOString(),
            expiresAt: 'Never',
            publicKeyJWK: publicKeyInfo?.publicIdentityKeyJWK
          });
        }
      } catch (identityErr) {
        console.error('[useKeys] Failed to check identity key:', identityErr);
        // Don't fail completely - continue to check session keys
      }

      // 2. Fetch Session Keys (from local IndexedDB - doesn't require server)
      try {
        console.log('[useKeys] Fetching session keys for user:', user.id);
        const sessions = await getUserSessions(user.id);
        console.log('[useKeys] Found sessions:', sessions.length);
        
        for (const session of sessions) {
          const sessionId = session.sessionId;
          const peerId = session.userId === user.id ? session.peerId : session.userId;
          
          // Root Key
          if (session.rootKey) {
            keysList.push({
              id: `session-${sessionId}-root`,
              name: `Root Key (Session: ${sessionId.substring(0, 8)}...)`,
              type: 'Session Key',
              keyType: 'HKDF-SHA256 (256 bits)',
              category: 'session',
              status: 'active',
              fingerprint: generateKeyFingerprint(session.rootKey),
              createdAt: session.createdAt || new Date().toISOString(),
              expiresAt: 'Session lifetime',
              sessionId: sessionId,
              peerId: peerId,
              keyPurpose: 'Base key for deriving send/recv keys'
            });
          }

          // Send Key
          if (session.sendKey) {
            keysList.push({
              id: `session-${sessionId}-send`,
              name: `Send Key (Session: ${sessionId.substring(0, 8)}...)`,
              type: 'Session Key',
              keyType: 'HKDF-SHA256 (256 bits)',
              category: 'session',
              status: 'active',
              fingerprint: generateKeyFingerprint(session.sendKey),
              createdAt: session.createdAt || new Date().toISOString(),
              expiresAt: 'Session lifetime',
              sessionId: sessionId,
              peerId: peerId,
              keyPurpose: 'Encrypts outgoing messages (AES-256-GCM)'
            });
          }

          // Receive Key
          if (session.recvKey) {
            keysList.push({
              id: `session-${sessionId}-recv`,
              name: `Receive Key (Session: ${sessionId.substring(0, 8)}...)`,
              type: 'Session Key',
              keyType: 'HKDF-SHA256 (256 bits)',
              category: 'session',
              status: 'active',
              fingerprint: generateKeyFingerprint(session.recvKey),
              createdAt: session.createdAt || new Date().toISOString(),
              expiresAt: 'Session lifetime',
              sessionId: sessionId,
              peerId: peerId,
              keyPurpose: 'Decrypts incoming messages (AES-256-GCM)'
            });
          }
        }
      } catch (sessionErr) {
        console.warn('[useKeys] Failed to fetch session keys:', sessionErr);
        // Don't fail completely if session keys can't be loaded
      }

      console.log('[useKeys] Total keys found:', keysList.length);
      setKeys(keysList);
    } catch (err) {
      console.error('[useKeys] Failed to fetch keys:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllKeys();
  }, [user?.id]);

  return { 
    keys, 
    loading, 
    error,
    refetch: fetchAllKeys
  };
}

