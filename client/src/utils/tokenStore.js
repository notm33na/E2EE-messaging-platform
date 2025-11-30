/**
 * Token Store
 * Stores access token in memory only (not localStorage)
 * This provides a way for axios interceptors to access the token
 */

let accessToken = null;
let tokenUpdateCallback = null;

/**
 * Sets the access token
 * @param {string} token - Access token
 */
export function setAccessToken(token) {
  accessToken = token;
}

/**
 * Gets the access token
 * @returns {string|null} Access token or null
 */
export function getAccessToken() {
  return accessToken;
}

/**
 * Clears the access token
 */
export function clearAccessToken() {
  accessToken = null;
}

/**
 * Sets a callback to be called when token is updated
 * @param {Function} callback - Callback function
 */
export function setTokenUpdateCallback(callback) {
  tokenUpdateCallback = callback;
}

/**
 * Notifies that token was updated
 * @param {string} token - New access token
 */
export function notifyTokenUpdate(token) {
  accessToken = token;
  if (tokenUpdateCallback) {
    tokenUpdateCallback(token);
  }
}

