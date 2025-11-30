import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Loads ECC keys securely from the keys directory
 * @returns {Object} Object containing privateKey and publicKey as PEM strings
 */
export function loadKeys() {
  const keysDir = path.join(__dirname, '../../../keys');
  const privateKeyPath = path.join(keysDir, 'private_key.pem');
  const publicKeyPath = path.join(keysDir, 'public_key.pem');

  if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
    throw new Error(
      'ECC keys not found. Please run: npm run generate-keys'
    );
  }

  const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  const publicKey = fs.readFileSync(publicKeyPath, 'utf8');

  return { privateKey, publicKey };
}

