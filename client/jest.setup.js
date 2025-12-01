// Jest setup for client E2EE tests

// Ensure Web Crypto API is available FIRST before anything else
// Use @peculiar/webcrypto for a spec-compliant Web Crypto implementation
// in Node test environment (no mocking of operations, just API polyfill).
const { Crypto } = require('@peculiar/webcrypto');

// Create a Web Crypto implementation and expose it globally so that
// application code using `crypto.subtle` and `crypto.getRandomValues`
// sees a spec-compliant implementation.
const webcrypto = new Crypto();

// Set up crypto BEFORE fake-indexeddb (which might also try to use crypto)
// Set it on all possible global objects to ensure ES modules can access it
global.crypto = webcrypto;
globalThis.crypto = webcrypto;

// Make sure window/self share the same crypto (jsdom environment)
if (typeof window !== 'undefined') {
  window.crypto = webcrypto;
}
if (typeof self !== 'undefined') {
  self.crypto = webcrypto;
}

// For ES modules, ensure crypto is available everywhere
// ES modules in Node.js don't have implicit globals, so we need to be explicit
if (typeof globalThis !== 'undefined') {
  globalThis.crypto = webcrypto;
}

// Also ensure crypto is available on the global object for module access
// Some modules might access crypto directly without going through global/window
if (typeof global !== 'undefined') {
  // Ensure it's also available as a direct property
  Object.defineProperty(global, 'crypto', {
    value: webcrypto,
    writable: true,
    configurable: true,
    enumerable: true
  });
}

// Verify crypto.subtle is available
if (!webcrypto.subtle) {
  throw new Error('Web Crypto API setup failed: crypto.subtle is not available');
}

// Use fake IndexedDB so we exercise the real IndexedDB API in tests
// (crypto operations still use the real Web Crypto API).
require('fake-indexeddb/auto');

// jsdom already provides TextEncoder/TextDecoder in modern Jest, but
// add a fallback for older environments.
if (typeof global.TextEncoder === 'undefined') {
  const { TextEncoder, TextDecoder } = require('util');
  global.TextEncoder = TextEncoder;
  global.TextDecoder = TextDecoder;
}

// Polyfill structuredClone for environments that lack it.
if (typeof global.structuredClone === 'undefined') {
  global.structuredClone = (value) => JSON.parse(JSON.stringify(value));
}

// Polyfill File.arrayBuffer for jsdom versions where it's missing.
if (typeof File !== 'undefined' && !File.prototype.arrayBuffer) {
  File.prototype.arrayBuffer = function () {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(this);
    });
  };
}

// Testing Library matchers (used mainly in UI-focused tests)
require('@testing-library/jest-dom');
