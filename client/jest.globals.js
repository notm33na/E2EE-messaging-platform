// This file runs BEFORE any modules are loaded
// It sets up crypto in a way that ES modules can access it

const { Crypto } = require('@peculiar/webcrypto');
const webcrypto = new Crypto();

// Set up crypto on all global objects
global.crypto = webcrypto;
globalThis.crypto = webcrypto;

if (typeof window !== 'undefined') {
  window.crypto = webcrypto;
}
if (typeof self !== 'undefined') {
  self.crypto = webcrypto;
}

// For ES modules, we need to make crypto available as a bare identifier
// This is done by setting it on the global object in a way that works with ES modules
Object.defineProperty(global, 'crypto', {
  value: webcrypto,
  writable: true,
  configurable: true,
  enumerable: true
});

