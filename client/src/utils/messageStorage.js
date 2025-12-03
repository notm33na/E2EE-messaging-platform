/**
 * Message Storage Utilities
 * 
 * Handles persistence of messages in IndexedDB for offline access
 * and message history across page reloads.
 */

const DB_NAME = 'InfosecCryptoDB';
const DB_VERSION = 7; // Database version (must match highest version used by any module)
const MESSAGES_STORE = 'messages';

/**
 * Opens IndexedDB database
 * @returns {Promise<IDBDatabase>}
 */
async function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      const transaction = event.target.transaction;
      
      // Create messages store if it doesn't exist
      if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
        const store = db.createObjectStore(MESSAGES_STORE, { keyPath: 'id' });
        // Index by sessionId for fast lookup
        store.createIndex('sessionId', 'sessionId', { unique: false });
        // Index by timestamp for sorting
        store.createIndex('timestamp', 'timestamp', { unique: false });
        // Index by sequence for ordering
        store.createIndex('seq', 'seq', { unique: false });
      } else {
        // Store exists, but check if indexes exist
        const store = transaction.objectStore(MESSAGES_STORE);
        
        // Check and create indexes if they don't exist
        if (!store.indexNames.contains('sessionId')) {
          store.createIndex('sessionId', 'sessionId', { unique: false });
        }
        if (!store.indexNames.contains('timestamp')) {
          store.createIndex('timestamp', 'timestamp', { unique: false });
        }
        if (!store.indexNames.contains('seq')) {
          store.createIndex('seq', 'seq', { unique: false });
        }
      }
      
      // Ensure all other required stores exist
      if (!db.objectStoreNames.contains('messageQueue')) {
        const queueStore = db.createObjectStore('messageQueue', { keyPath: 'id', autoIncrement: true });
        queueStore.createIndex('sessionId', 'sessionId', { unique: false });
        queueStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions', { keyPath: 'sessionId' });
      }
      if (!db.objectStoreNames.contains('sessionEncryptionKeys')) {
        db.createObjectStore('sessionEncryptionKeys', { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains('identityKeys')) {
        db.createObjectStore('identityKeys', { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains('clientLogs')) {
        const logStore = db.createObjectStore('clientLogs', { 
          keyPath: 'id', 
          autoIncrement: true 
        });
        logStore.createIndex('timestamp', 'timestamp', { unique: false });
        logStore.createIndex('userId', 'userId', { unique: false });
        logStore.createIndex('sessionId', 'sessionId', { unique: false });
        logStore.createIndex('event', 'event', { unique: false });
        logStore.createIndex('synced', 'synced', { unique: false });
      }
    };
  });
}

/**
 * Stores a message in IndexedDB
 * @param {string} sessionId - Session identifier
 * @param {Object} message - Message object with id, type, content, sender, timestamp, seq
 * @returns {Promise<void>}
 */
export async function storeMessage(sessionId, message) {
  try {
    const db = await openDB();
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
      console.warn('messages store does not exist, cannot store message');
      return;
    }
    
    const transaction = db.transaction([MESSAGES_STORE], 'readwrite');
    const store = transaction.objectStore(MESSAGES_STORE);

    const messageToStore = {
      id: message.id || `${sessionId}-${message.seq}`,
      sessionId,
      type: message.type || 'text',
      content: message.content,
      sender: message.sender,
      timestamp: message.timestamp || Date.now(),
      seq: message.seq || 0,
      sent: message.sent || false,
      createdAt: new Date().toISOString()
    };

    await new Promise((resolve, reject) => {
      const request = store.put(messageToStore);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('Failed to store message:', error);
    // Don't throw - message storage failure shouldn't break messaging
  }
}

/**
 * Loads messages for a session from IndexedDB
 * @param {string} sessionId - Session identifier
 * @param {number} limit - Maximum number of messages to load (default: 100)
 * @returns {Promise<Array>} Array of messages sorted by sequence number
 */
export async function loadMessages(sessionId, limit = 100) {
  try {
    const db = await openDB();
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
      console.warn('messages store does not exist, returning empty array');
      return [];
    }
    
    const transaction = db.transaction([MESSAGES_STORE], 'readonly');
    const store = transaction.objectStore(MESSAGES_STORE);
    
    // Check if index exists
    let index;
    try {
      index = store.index('sessionId');
    } catch (e) {
      // Index doesn't exist, use getAll and filter
      const allMessages = await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
      });
      
      const filtered = allMessages.filter(msg => msg.sessionId === sessionId);
      filtered.sort((a, b) => (a.seq || 0) - (b.seq || 0));
      return filtered.slice(-limit);
    }

    const messages = await new Promise((resolve, reject) => {
      const request = index.getAll(sessionId);
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    // Sort by sequence number (ascending)
    messages.sort((a, b) => (a.seq || 0) - (b.seq || 0));

    // Return most recent messages (last N)
    return messages.slice(-limit);
  } catch (error) {
    console.error('Failed to load messages:', error);
    return [];
  }
}

/**
 * Clears all messages for a session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<void>}
 */
export async function clearMessages(sessionId) {
  try {
    const db = await openDB();
    const transaction = db.transaction([MESSAGES_STORE], 'readwrite');
    const store = transaction.objectStore(MESSAGES_STORE);
    const index = store.index('sessionId');

    const messages = await new Promise((resolve, reject) => {
      const request = index.getAll(sessionId);
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    // Delete all messages for this session
    await Promise.all(
      messages.map(msg => 
        new Promise((resolve, reject) => {
          const deleteRequest = store.delete(msg.id);
          deleteRequest.onsuccess = () => resolve();
          deleteRequest.onerror = () => reject(deleteRequest.error);
        })
      )
    );
  } catch (error) {
    console.error('Failed to clear messages:', error);
  }
}

/**
 * Clears all messages for a user (on logout)
 * @param {string} userId - User ID
 * @returns {Promise<void>}
 */
export async function clearAllUserMessages(userId) {
  try {
    // Get all sessions for user and clear their messages
    const { getUserSessions } = await import('../crypto/sessionManager.js');
    const sessions = await getUserSessions(userId);
    
    await Promise.all(
      sessions.map(session => clearMessages(session.sessionId))
    );
  } catch (error) {
    console.error('Failed to clear user messages:', error);
  }
}

/**
 * Syncs messages with server (fetches missed messages)
 * @param {string} sessionId - Session identifier
 * @returns {Promise<Array>} Array of new messages from server
 */
export async function syncMessages(sessionId) {
  try {
    const api = (await import('../services/api.js')).default;
    const response = await api.get(`/messages/pending/${sessionId}`);
    
    if (response.data.success && response.data.data) {
      const pendingMessages = response.data.data;
      // Process and store pending messages
      const messages = [];
      for (const msg of pendingMessages) {
        // Messages should be decrypted and processed via handleIncomingMessage
        // This function just returns the raw messages for processing
        messages.push(msg);
      }
      return messages;
    }
    return [];
  } catch (error) {
    console.error('Failed to sync messages:', error);
    return [];
  }
}

