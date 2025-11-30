import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const keysDir = path.join(__dirname, '../../keys');

// Ensure keys directory exists
if (!fs.existsSync(keysDir)) {
  fs.mkdirSync(keysDir, { recursive: true });
}

// Generate ECC keypair using P-256 curve (ES256)
console.log('Generating ECC keypair (P-256, ES256)...');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1', // P-256 curve
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Write keys to files
const privateKeyPath = path.join(keysDir, 'private_key.pem');
const publicKeyPath = path.join(keysDir, 'public_key.pem');

fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });

console.log('✓ ECC keys generated successfully!');
console.log(`  Private key: ${privateKeyPath}`);
console.log(`  Public key: ${publicKeyPath}`);
console.log('\n⚠️  Keep the private key secure and never commit it to version control!');

