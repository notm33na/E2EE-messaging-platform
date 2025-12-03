/**
 * Client-Side Security Logging
 * 
 * Provides persistent client-side logging for security events.
 * Logs are stored in IndexedDB and can be synced to server for centralized audit.
 * 
 * SECURITY CONSIDERATIONS:
 * - Logs never contain plaintext or private keys
 * - Only metadata and security event indicators are logged
 * - Logs are stored locally for audit and can be synced to server
 */

const DB_NAME = 'InfosecCryptoDB';
const DB_VERSION = 7; // Must match the highest version used by any module
const CLIENT_LOGS_STORE = 'clientLogs';

/**
 * Ensures the clientLogs store exists in the database
 * @param {IDBDatabase} db - Database instance
 * @returns {Promise<IDBDatabase>} Database with store ensured
 */
async function ensureStoreExists(db) {
  if (db.objectStoreNames.contains(CLIENT_LOGS_STORE)) {
    return db;
  }
  
  // Store doesn't exist, need to upgrade
  // Use DB_VERSION to ensure consistency
  db.close();
  
  return new Promise((resolve, reject) => {
    const upgradeRequest = indexedDB.open(DB_NAME, DB_VERSION);
    upgradeRequest.onerror = () => reject(upgradeRequest.error);
    upgradeRequest.onsuccess = () => resolve(upgradeRequest.result);
    upgradeRequest.onupgradeneeded = (event) => {
      const upgradeDb = event.target.result;
      if (!upgradeDb.objectStoreNames.contains(CLIENT_LOGS_STORE)) {
        const store = upgradeDb.createObjectStore(CLIENT_LOGS_STORE, { 
          keyPath: 'id', 
          autoIncrement: true 
        });
        store.createIndex('timestamp', 'timestamp', { unique: false });
        store.createIndex('userId', 'userId', { unique: false });
        store.createIndex('sessionId', 'sessionId', { unique: false });
        store.createIndex('event', 'event', { unique: false });
        store.createIndex('synced', 'synced', { unique: false });
      }
    };
  });
}

/**
 * Opens IndexedDB database
 * @returns {Promise<IDBDatabase>}
 */
async function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = async () => {
      const db = request.result;
      // Ensure store exists
      try {
        const dbWithStore = await ensureStoreExists(db);
        resolve(dbWithStore);
      } catch (error) {
        // If ensureStoreExists fails, just return the original db
        // The error will be caught when trying to use the store
        resolve(db);
      }
    };

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      const transaction = event.target.transaction;
      
      // Create clientLogs store if it doesn't exist
      if (!db.objectStoreNames.contains(CLIENT_LOGS_STORE)) {
        const store = db.createObjectStore(CLIENT_LOGS_STORE, { 
          keyPath: 'id', 
          autoIncrement: true 
        });
        
        // Create indexes for efficient queries
        store.createIndex('timestamp', 'timestamp', { unique: false });
        store.createIndex('userId', 'userId', { unique: false });
        store.createIndex('sessionId', 'sessionId', { unique: false });
        store.createIndex('event', 'event', { unique: false });
        store.createIndex('synced', 'synced', { unique: false });
      } else {
        // Store exists, but check if indexes exist
        const store = transaction.objectStore(CLIENT_LOGS_STORE);
        if (!store.indexNames.contains('timestamp')) {
          store.createIndex('timestamp', 'timestamp', { unique: false });
        }
        if (!store.indexNames.contains('userId')) {
          store.createIndex('userId', 'userId', { unique: false });
        }
        if (!store.indexNames.contains('sessionId')) {
          store.createIndex('sessionId', 'sessionId', { unique: false });
        }
        if (!store.indexNames.contains('event')) {
          store.createIndex('event', 'event', { unique: false });
        }
        if (!store.indexNames.contains('synced')) {
          store.createIndex('synced', 'synced', { unique: false });
        }
      }
      
      // Ensure all other required stores exist
      if (!db.objectStoreNames.contains('identityKeys')) {
        db.createObjectStore('identityKeys', { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions', { keyPath: 'sessionId' });
      }
      if (!db.objectStoreNames.contains('sessionEncryptionKeys')) {
        db.createObjectStore('sessionEncryptionKeys', { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains('messages')) {
        const msgStore = db.createObjectStore('messages', { keyPath: 'id' });
        msgStore.createIndex('sessionId', 'sessionId', { unique: false });
        msgStore.createIndex('timestamp', 'timestamp', { unique: false });
        msgStore.createIndex('seq', 'seq', { unique: false });
      }
      if (!db.objectStoreNames.contains('messageQueue')) {
        const queueStore = db.createObjectStore('messageQueue', { keyPath: 'id', autoIncrement: true });
        queueStore.createIndex('sessionId', 'sessionId', { unique: false });
        queueStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
  });
}

/**
 * Logs a security event to IndexedDB
 * @param {string} event - Event type (e.g., 'replay_attempt', 'invalid_signature', 'decryption_error', 'kep_error', 'timestamp_failure', 'seq_mismatch', 'message_dropped')
 * @param {Object} metadata - Event metadata
 * @param {string} [metadata.userId] - User ID
 * @param {string} [metadata.sessionId] - Session ID
 * @param {number} [metadata.seq] - Sequence number
 * @param {number} [metadata.timestamp] - Message timestamp
 * @param {string} [metadata.reason] - Failure reason
 * @param {string} [metadata.messageType] - Message type
 * @param {Object} [metadata.additional] - Additional metadata
 * @returns {Promise<number>} Log entry ID
 */
export async function logSecurityEvent(event, metadata = {}) {
  try {
    const logEntry = {
      timestamp: new Date().toISOString(),
      userId: metadata.userId || null,
      sessionId: metadata.sessionId || null,
      event,
      metadata: {
        seq: metadata.seq || null,
        messageTimestamp: metadata.timestamp || null,
        reason: metadata.reason || null,
        messageType: metadata.messageType || null,
        ...metadata.additional
      },
      synced: false // Track if synced to server
    };

    let db = await openDB();
    
    // Ensure store exists before using
    if (!db.objectStoreNames.contains(CLIENT_LOGS_STORE)) {
      // In test environment, just log to console and return
      if (process.env.NODE_ENV === 'test') {
        console.warn(`[ClientLogger] Event: ${event}`, metadata);
        return null;
      }
      // Try to ensure store exists
      try {
        db = await ensureStoreExists(db);
      } catch (error) {
        // If we can't create the store, just log to console
        console.warn(`[ClientLogger] Event: ${event}`, metadata);
        return null;
      }
    }
    
    const transaction = db.transaction([CLIENT_LOGS_STORE], 'readwrite');
    const store = transaction.objectStore(CLIENT_LOGS_STORE);

    return new Promise((resolve, reject) => {
      const request = store.add(logEntry);
      request.onsuccess = () => {
        const id = request.result;
        console.log(`[ClientLogger] Logged ${event}:`, logEntry);
        resolve(id);
      };
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    // In test environment, just log to console and don't throw
    if (process.env.NODE_ENV === 'test') {
      console.warn(`[ClientLogger] Event: ${event}`, metadata);
      return null;
    }
    // In production, log error but don't break the application
    console.error('[ClientLogger] Failed to log security event:', error);
    console.warn(`[ClientLogger] Event: ${event}`, metadata);
    // Return null instead of throwing to prevent breaking the app
    return null;
  }
}

/**
 * Retrieves logs from IndexedDB
 * @param {Object} [options] - Query options
 * @param {string} [options.userId] - Filter by user ID
 * @param {string} [options.sessionId] - Filter by session ID
 * @param {string} [options.event] - Filter by event type
 * @param {Date} [options.startDate] - Start date filter
 * @param {Date} [options.endDate] - End date filter
 * @param {number} [options.limit] - Maximum number of entries to return
 * @returns {Promise<Array>} Array of log entries
 */
export async function getLogs(options = {}) {
  try {
    const db = await openDB();
    const transaction = db.transaction([CLIENT_LOGS_STORE], 'readonly');
    const store = transaction.objectStore(CLIENT_LOGS_STORE);
    const index = store.index('timestamp');

    // Get all entries (or filtered by date range)
    let range = null;
    if (options.startDate || options.endDate) {
      range = IDBKeyRange.bound(
        options.startDate?.toISOString() || '',
        options.endDate?.toISOString() || '\uffff'
      );
    }

    const request = range ? index.getAll(range) : store.getAll();
    
    return new Promise((resolve, reject) => {
      request.onsuccess = () => {
        let logs = request.result || [];

        // Apply filters
        if (options.userId) {
          logs = logs.filter(log => log.userId === options.userId);
        }
        if (options.sessionId) {
          logs = logs.filter(log => log.sessionId === options.sessionId);
        }
        if (options.event) {
          logs = logs.filter(log => log.event === options.event);
        }

        // Sort by timestamp (newest first)
        logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Apply limit
        if (options.limit) {
          logs = logs.slice(0, options.limit);
        }

        resolve(logs);
      };
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('[ClientLogger] Failed to retrieve logs:', error);
    return [];
  }
}

/**
 * Clears logs from IndexedDB
 * @param {Object} [options] - Clear options
 * @param {string} [options.userId] - Clear logs for specific user
 * @param {string} [options.sessionId] - Clear logs for specific session
 * @param {Date} [options.beforeDate] - Clear logs before this date
 * @returns {Promise<number>} Number of entries cleared
 */
export async function clearLogs(options = {}) {
  try {
    const db = await openDB();
    const transaction = db.transaction([CLIENT_LOGS_STORE], 'readwrite');
    const store = transaction.objectStore(CLIENT_LOGS_STORE);

    // Get all entries to filter
    const allLogs = await new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    // Filter logs to delete
    let logsToDelete = allLogs;
    if (options.userId) {
      logsToDelete = logsToDelete.filter(log => log.userId === options.userId);
    }
    if (options.sessionId) {
      logsToDelete = logsToDelete.filter(log => log.sessionId === options.sessionId);
    }
    if (options.beforeDate) {
      logsToDelete = logsToDelete.filter(log => new Date(log.timestamp) < options.beforeDate);
    }

    // Delete filtered logs
    let deletedCount = 0;
    for (const log of logsToDelete) {
      await new Promise((resolve, reject) => {
        const request = store.delete(log.id);
        request.onsuccess = () => {
          deletedCount++;
          resolve();
        };
        request.onerror = () => reject(request.error);
      });
    }

    console.log(`[ClientLogger] Cleared ${deletedCount} log entries`);
    return deletedCount;
  } catch (error) {
    console.error('[ClientLogger] Failed to clear logs:', error);
    throw error;
  }
}

/**
 * Syncs critical security events to server
 * Only syncs events that haven't been synced yet
 * @param {Function} apiCall - Function to make API call to server (should accept array of log entries)
 * @returns {Promise<number>} Number of events synced
 */
export async function syncCriticalEventsToServer(apiCall) {
  try {
    // Get all unsynced logs
    const db = await openDB();
    const transaction = db.transaction([CLIENT_LOGS_STORE], 'readwrite');
    const store = transaction.objectStore(CLIENT_LOGS_STORE);
    const index = store.index('synced');

    const unsyncedLogs = await new Promise((resolve, reject) => {
      const request = index.getAll(false); // Get all where synced === false
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    if (unsyncedLogs.length === 0) {
      return 0;
    }

    // Prepare logs for server (remove IndexedDB-specific fields)
    const logsToSync = unsyncedLogs.map(log => ({
      timestamp: log.timestamp,
      userId: log.userId,
      sessionId: log.sessionId,
      event: log.event,
      metadata: log.metadata
    }));

    // Send to server
    try {
      await apiCall(logsToSync);

      // Mark as synced
      for (const log of unsyncedLogs) {
        log.synced = true;
        await new Promise((resolve, reject) => {
          const request = store.put(log);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        });
      }

      console.log(`[ClientLogger] Synced ${logsToSync.length} events to server`);
      return logsToSync.length;
    } catch (error) {
      console.error('[ClientLogger] Failed to sync events to server:', error);
      // Don't mark as synced if sync failed
      throw error;
    }
  } catch (error) {
    console.error('[ClientLogger] Failed to sync critical events:', error);
    throw error;
  }
}

/**
 * Convenience functions for specific event types
 */

export async function logReplayAttempt(sessionId, seq, timestamp, reason, userId = null) {
  return logSecurityEvent('replay_attempt', {
    userId,
    sessionId,
    seq,
    timestamp,
    reason
  });
}

export async function logInvalidSignature(sessionId, reason, userId = null, messageType = null) {
  return logSecurityEvent('invalid_signature', {
    userId,
    sessionId,
    reason,
    messageType
  });
}

export async function logDecryptionError(sessionId, seq, reason, userId = null) {
  return logSecurityEvent('decryption_error', {
    userId,
    sessionId,
    seq,
    reason
  });
}

export async function logKEPError(sessionId, reason, userId = null, messageType = null) {
  return logSecurityEvent('kep_error', {
    userId,
    sessionId,
    reason,
    messageType
  });
}

export async function logTimestampFailure(sessionId, seq, timestamp, reason, userId = null) {
  return logSecurityEvent('timestamp_failure', {
    userId,
    sessionId,
    seq,
    timestamp,
    reason
  });
}

export async function logSeqMismatch(sessionId, seq, expectedSeq, userId = null) {
  return logSecurityEvent('seq_mismatch', {
    userId,
    sessionId,
    seq,
    reason: `Expected seq > ${expectedSeq}, got ${seq}`,
    additional: { expectedSeq }
  });
}

export async function logMessageDropped(sessionId, seq, reason, userId = null) {
  return logSecurityEvent('message_dropped', {
    userId,
    sessionId,
    seq,
    reason
  });
}

/**
 * Logs MITM attack detection
 * @param {string} sessionId - Session ID
 * @param {string} attackType - Type of attack ('unsigned_dh', 'signature_blocked', etc.)
 * @param {string} description - Attack description
 * @param {Object} metadata - Additional metadata
 * @param {string} [userId] - User ID
 */
export async function logMITMAttack(sessionId, attackType, description, metadata = {}, userId = null) {
  return logSecurityEvent('mitm_attack', {
    userId,
    sessionId,
    reason: description,
    additional: {
      attackType,
      ...metadata
    }
  });
}

/**
 * Logs MITM attack demonstration event
 * @param {string} sessionId - Session ID
 * @param {string} scenario - Attack scenario ('unsigned_dh', 'signed_dh')
 * @param {boolean} attackSuccessful - Whether attack succeeded
 * @param {string} reason - Reason for success/failure
 * @param {Object} metadata - Additional metadata
 * @param {string} [userId] - User ID
 */
export async function logMITMDemonstration(sessionId, scenario, attackSuccessful, reason, metadata = {}, userId = null) {
  return logSecurityEvent('mitm_demonstration', {
    userId,
    sessionId,
    reason,
    additional: {
      scenario,
      attackSuccessful,
      ...metadata
    }
  });
}

