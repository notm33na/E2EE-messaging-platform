import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import selfsigned from 'selfsigned';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Generates a self-signed certificate for HTTPS development
 * In production, use certificates from a trusted CA (e.g., Let's Encrypt)
 * @returns {Object} Object containing key and cert as strings
 */
export function generateSelfSignedCert() {
  const keysDir = path.join(__dirname, '../../../keys');
  
  // Check if cert already exists
  const certPath = path.join(keysDir, 'server.crt');
  const keyPath = path.join(keysDir, 'server.key');
  
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    console.log('✓ Using existing self-signed certificate');
    return {
      key: fs.readFileSync(keyPath, 'utf8'),
      cert: fs.readFileSync(certPath, 'utf8')
    };
  }

  console.log('Generating self-signed certificate for HTTPS...');
  
  // Generate self-signed certificate with proper SAN (Subject Alternative Names)
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  const pems = selfsigned.generate(attrs, {
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
        altNames: [
          { type: 2, value: 'localhost' },
          { type: 2, value: '127.0.0.1' },
          { type: 7, ip: '127.0.0.1' },
          { type: 7, ip: '::1' }
        ]
      }
    ]
  });

  // Save certificate and key
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }
  
  fs.writeFileSync(keyPath, pems.private, { mode: 0o600 });
  fs.writeFileSync(certPath, pems.cert, { mode: 0o644 });

  console.log('✓ Self-signed certificate generated');
  console.log('⚠️  This is a development certificate. Use a trusted CA certificate in production.');

  return {
    key: pems.private,
    cert: pems.cert
  };
}

