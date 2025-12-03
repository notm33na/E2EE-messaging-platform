import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import selfsigned from 'selfsigned';
import os from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Gets the local network IP address
 */
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal (loopback) and non-IPv4 addresses
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

/**
 * Generates a self-signed certificate for Vite HTTPS development
 */
function generateViteCert() {
  const certDir = path.join(__dirname, '.vite');
  const certPath = path.join(certDir, 'vite.crt');
  const keyPath = path.join(certDir, 'vite.key');
  
  // Get local network IP
  const localIP = getLocalIP();
  console.log(`Detected local IP: ${localIP}`);
  
  // Check if cert already exists
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const key = fs.readFileSync(keyPath, 'utf8');
      const cert = fs.readFileSync(certPath, 'utf8');
      if (key && typeof key === 'string' && key.trim().length > 0 &&
          cert && typeof cert === 'string' && cert.trim().length > 0) {
        console.log('✓ Using existing Vite certificate');
        return { key, cert };
      } else {
        console.warn('⚠️  Existing certificate files are empty or invalid, regenerating...');
        // Delete corrupted files
        fs.unlinkSync(keyPath);
        fs.unlinkSync(certPath);
      }
    } catch (error) {
      console.warn(`⚠️  Failed to read existing certificate (${error.message}), regenerating...`);
      // Try to delete corrupted files
      try {
        if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
        if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
      } catch {}
      // Continue to generate new certificate
    }
  }

  console.log('Generating self-signed certificate for Vite HTTPS...');
  
  // Generate self-signed certificate with proper SAN (Subject Alternative Names)
  // Include localhost, 127.0.0.1, and the local IP address
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  
  // Build altNames array - include localhost, 127.0.0.1, and the detected IP
  const altNames = [
    { type: 2, value: 'localhost' },
    { type: 2, value: '127.0.0.1' },
    { type: 7, ip: '127.0.0.1' }
  ];
  
  // Add the local IP if it's different from localhost
  if (localIP && localIP !== 'localhost' && localIP !== '127.0.0.1') {
    altNames.push({ type: 2, value: localIP });
    altNames.push({ type: 7, ip: localIP });
  }
  
  let pems;
  try {
    pems = selfsigned.generate(attrs, {
      keySize: 2048,
      days: 365,
      algorithm: 'sha256',
      extensions: [
        {
          name: 'basicConstraints',
          cA: false
        },
        {
          name: 'keyUsage',
          keyCertSign: false,
          digitalSignature: true,
          nonRepudiation: false,
          keyEncipherment: true,
          dataEncipherment: false
        },
        {
          name: 'subjectAltName',
          altNames: altNames
        }
      ]
    });
  } catch (error) {
    console.error('Error generating certificate:', error);
    throw new Error(`Failed to generate certificate: ${error.message}`);
  }

  // Debug: log what we got
  console.log('Certificate generation result keys:', Object.keys(pems || {}));
  
  if (!pems || typeof pems !== 'object') {
    throw new Error(`selfsigned.generate returned invalid result: ${typeof pems}`);
  }

  // selfsigned returns { private, cert, public }
  const privateKey = pems.private;
  const certificate = pems.cert;
  
  if (!privateKey || typeof privateKey !== 'string') {
    throw new Error(`Invalid private key. Got type: ${typeof privateKey}, keys in result: ${Object.keys(pems).join(', ')}`);
  }
  
  if (!certificate || typeof certificate !== 'string') {
    throw new Error(`Invalid certificate. Got type: ${typeof certificate}, keys in result: ${Object.keys(pems).join(', ')}`);
  }

  // Save certificate and key
  if (!fs.existsSync(certDir)) {
    fs.mkdirSync(certDir, { recursive: true });
  }
  
  try {
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(certPath, certificate, { mode: 0o644 });
  } catch (error) {
    throw new Error(`Failed to save certificate files: ${error.message}`);
  }

  console.log('✓ Vite certificate generated');
  console.log(`✓ Certificate includes: localhost, 127.0.0.1, ${localIP}`);
  console.log('⚠️  This is a development certificate. Use a trusted CA certificate in production.');

  return {
    key: privateKey,
    cert: certificate
  };
}

// Generate certificate if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  generateViteCert();
}

export { generateViteCert };

