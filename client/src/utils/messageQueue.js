/**
 * Message Queue
 * 
 * Queues messages when offline and sends them when connection is restored
 */

const QUEUE_STORE = 'messageQueue';
const DB_NAME = 'InfosecCryptoDB';
const DB_VERSION = 7;

/**
 * Opens IndexedDB database
 */
async function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      // Store existence is checked in individual functions
      // If stores don't exist, functions will handle it gracefully
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      const transaction = event.target.transaction;
      ensureAllStores(db, transaction);
    };
    
    // Handle version conflict - if database is blocked, wait and retry
    request.onblocked = () => {
      console.warn('IndexedDB upgrade blocked - waiting for other connections to close');
      // The upgrade will proceed once other connections close
    };
  });
}

/**
 * Ensures all required object stores exist
 */
function ensureAllStores(db, transaction) {
  // Create messageQueue store if it doesn't exist
  if (!db.objectStoreNames.contains(QUEUE_STORE)) {
    const store = db.createObjectStore(QUEUE_STORE, { keyPath: 'id', autoIncrement: true });
    store.createIndex('sessionId', 'sessionId', { unique: false });
    store.createIndex('timestamp', 'timestamp', { unique: false });
  } else if (transaction) {
    // Store exists, but check if indexes exist
    try {
      const store = transaction.objectStore(QUEUE_STORE);
      if (!store.indexNames.contains('sessionId')) {
        store.createIndex('sessionId', 'sessionId', { unique: false });
      }
      if (!store.indexNames.contains('timestamp')) {
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    } catch (e) {
      // Index check failed, but store exists - that's OK
    }
  }
  
  // Ensure all other required stores exist
  if (!db.objectStoreNames.contains('messages')) {
    const msgStore = db.createObjectStore('messages', { keyPath: 'id' });
    msgStore.createIndex('sessionId', 'sessionId', { unique: false });
    msgStore.createIndex('timestamp', 'timestamp', { unique: false });
    msgStore.createIndex('seq', 'seq', { unique: false });
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
}

/**
 * Queues a message for later sending
 * @param {string} sessionId - Session identifier
 * @param {Object} envelope - Message envelope
 * @param {string} type - Message type ('text' | 'file')
 * @returns {Promise<string>} Queue ID
 */
export async function queueMessage(sessionId, envelope, type = 'text') {
  try {
    const db = await openDB();
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(QUEUE_STORE)) {
      throw new Error('messageQueue store does not exist');
    }
    
    const transaction = db.transaction([QUEUE_STORE], 'readwrite');
    const store = transaction.objectStore(QUEUE_STORE);

    const queuedMessage = {
      sessionId,
      envelope,
      type,
      timestamp: Date.now(),
      attempts: 0
    };

    const id = await new Promise((resolve, reject) => {
      const request = store.add(queuedMessage);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    return id;
  } catch (error) {
    console.error('Failed to queue message:', error);
    throw error;
  }
}

/**
 * Gets all queued messages for a session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<Array>} Array of queued messages
 */
export async function getQueuedMessages(sessionId) {
  try {
    const db = await openDB();
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(QUEUE_STORE)) {
      console.warn('messageQueue store does not exist, returning empty array');
      return [];
    }
    
    const transaction = db.transaction([QUEUE_STORE], 'readonly');
    const store = transaction.objectStore(QUEUE_STORE);
    
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
      filtered.sort((a, b) => a.timestamp - b.timestamp);
      return filtered;
    }

    const messages = await new Promise((resolve, reject) => {
      const request = index.getAll(sessionId);
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    // Sort by timestamp (oldest first)
    messages.sort((a, b) => a.timestamp - b.timestamp);
    return messages;
  } catch (error) {
    console.error('Failed to get queued messages:', error);
    return [];
  }
}

/**
 * Removes a message from the queue
 * @param {number} queueId - Queue message ID
 * @returns {Promise<void>}
 */
export async function removeQueuedMessage(queueId) {
  try {
    const db = await openDB();
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(QUEUE_STORE)) {
      console.warn('messageQueue store does not exist, cannot remove message');
      return;
    }
    
    const transaction = db.transaction([QUEUE_STORE], 'readwrite');
    const store = transaction.objectStore(QUEUE_STORE);

    await new Promise((resolve, reject) => {
      const request = store.delete(queueId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('Failed to remove queued message:', error);
  }
}

/**
 * Increments the attempt count for a queued message
 * @param {number} queueId - Queue message ID
 * @returns {Promise<void>}
 */
export async function incrementQueueAttempt(queueId) {
  try {
    const db = await openDB();
    
    // Verify store exists before attempting transaction
    if (!db.objectStoreNames.contains(QUEUE_STORE)) {
      console.warn('messageQueue store does not exist, cannot increment attempt');
      return;
    }
    
    const transaction = db.transaction([QUEUE_STORE], 'readwrite');
    const store = transaction.objectStore(QUEUE_STORE);

    const message = await new Promise((resolve, reject) => {
      const request = store.get(queueId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    if (message) {
      message.attempts = (message.attempts || 0) + 1;
      await new Promise((resolve, reject) => {
        const request = store.put(message);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    }
  } catch (error) {
    console.error('Failed to increment queue attempt:', error);
  }
}

/**
 * Clears all queued messages for a session
 * @param {string} sessionId - Session identifier
 * @returns {Promise<void>}
 */
export async function clearQueue(sessionId) {
  try {
    const messages = await getQueuedMessages(sessionId);
    await Promise.all(messages.map(msg => removeQueuedMessage(msg.id)));
  } catch (error) {
    console.error('Failed to clear queue:', error);
  }
}

