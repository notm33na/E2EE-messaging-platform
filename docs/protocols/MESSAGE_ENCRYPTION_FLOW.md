# Message Encryption Flow

## Overview

All messages are encrypted using AES-256-GCM before transmission. The server never sees plaintext content.

## Encryption Process

### Step 1: Load Session Keys

**Sender** loads session keys from IndexedDB:

```javascript
const sendKey = await getSendKey(sessionId);
const session = await loadSession(sessionId);
```

### Step 2: Generate IV

Generate a unique 96-bit initialization vector:

```javascript
const iv = crypto.getRandomValues(new Uint8Array(12));
```

**Requirements**:
- 96 bits (12 bytes)
- Cryptographically random
- Unique per message

### Step 3: Encrypt Plaintext

Encrypt using AES-256-GCM:

```javascript
const cryptoKey = await crypto.subtle.importKey(
  'raw',
  sendKey,
  { name: 'AES-GCM' },
  false,
  ['encrypt']
);

const encrypted = await crypto.subtle.encrypt(
  {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 128
  },
  cryptoKey,
  plaintextBuffer
);

// Extract ciphertext and auth tag
const ciphertext = encrypted.slice(0, -16);
const authTag = encrypted.slice(-16);
```

### Step 4: Build Envelope

Create message envelope:

```json
{
  "type": "MSG",
  "sessionId": "session-123",
  "sender": "aliceId",
  "receiver": "bobId",
  "ciphertext": "base64-encoded",
  "iv": "base64-encoded",
  "authTag": "base64-encoded",
  "timestamp": 1234567890,
  "seq": 1,
  "nonce": "base64-encoded"
}
```

### Step 5: Send via WebSocket

```javascript
socket.emit('msg:send', envelope);
```

## Decryption Process

### Step 1: Receive Envelope

**Receiver** receives envelope via WebSocket:

```javascript
socket.on('msg:receive', async (envelope) => {
  // Process envelope
});
```

### Step 2: Validate Envelope

Check structure and replay protection:

1. **Structure Validation**:
   - Required fields present
   - Type valid
   - Base64 format correct

2. **Timestamp Freshness**:
   ```javascript
   const age = Date.now() - envelope.timestamp;
   if (Math.abs(age) > 120000) {
     // Reject: stale message
   }
   ```

3. **Sequence Number**:
   ```javascript
   if (envelope.seq <= lastSeq) {
     // Reject: replay attempt
   }
   ```

### Step 3: Load Receive Key

```javascript
const recvKey = await getRecvKey(sessionId);
```

### Step 4: Decrypt

```javascript
const cryptoKey = await crypto.subtle.importKey(
  'raw',
  recvKey,
  { name: 'AES-GCM' },
  false,
  ['decrypt']
);

// Combine ciphertext and auth tag
const encrypted = new Uint8Array(ciphertext.length + authTag.length);
encrypted.set(ciphertext, 0);
encrypted.set(authTag, ciphertext.length);

const decrypted = await crypto.subtle.decrypt(
  {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 128
  },
  cryptoKey,
  encrypted
);
```

**Note**: If auth tag is invalid, decryption throws `OperationError`.

### Step 5: Update Session

```javascript
await updateSessionSeq(sessionId, envelope.seq);
```

## File Encryption Flow

### Step 1: Read File

```javascript
const fileBuffer = await file.arrayBuffer();
```

### Step 2: Chunk File

Split into 256KB chunks:

```javascript
const chunkSize = 256 * 1024; // 256KB
const chunks = [];
for (let i = 0; i < fileBuffer.byteLength; i += chunkSize) {
  chunks.push(fileBuffer.slice(i, i + chunkSize));
}
```

### Step 3: Encrypt Metadata

Encrypt file metadata (filename, size, mimetype):

```javascript
const metadata = {
  filename: file.name,
  size: file.size,
  totalChunks: chunks.length,
  mimetype: file.type
};

const metaEnvelope = buildFileMetaEnvelope(
  sessionId,
  sender,
  receiver,
  encryptedMetadata,
  iv,
  authTag,
  metadata
);
```

### Step 4: Encrypt Chunks

Encrypt each chunk:

```javascript
for (let i = 0; i < chunks.length; i++) {
  const { ciphertext, iv, authTag } = await encryptAESGCM(
    sendKey,
    chunks[i]
  );
  
  const chunkEnvelope = buildFileChunkEnvelope(
    sessionId,
    sender,
    receiver,
    ciphertext,
    iv,
    authTag,
    { chunkIndex: i, totalChunks: chunks.length }
  );
  
  chunkEnvelopes.push(chunkEnvelope);
}
```

### Step 5: Send Envelopes

Send FILE_META first, then FILE_CHUNK envelopes:

```javascript
socket.emit('msg:send', metaEnvelope);
for (const chunkEnvelope of chunkEnvelopes) {
  socket.emit('msg:send', chunkEnvelope);
}
```

## File Decryption Flow

### Step 1: Receive FILE_META

Decrypt metadata:

```javascript
const metadata = await decryptAESGCM(
  recvKey,
  metaIV,
  metaCiphertext,
  metaAuthTag
);
const { filename, size, totalChunks, mimetype } = JSON.parse(metadata);
```

### Step 2: Receive FILE_CHUNK Messages

Collect and sort chunks:

```javascript
const chunks = [];
for (const chunkEnvelope of chunkEnvelopes) {
  const decrypted = await decryptAESGCM(
    recvKey,
    chunkIV,
    chunkCiphertext,
    chunkAuthTag
  );
  chunks.push(decrypted);
}

// Sort by chunkIndex
chunks.sort((a, b) => a.meta.chunkIndex - b.meta.chunkIndex);
```

### Step 3: Reconstruct File

Combine chunks:

```javascript
const totalSize = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
const combined = new Uint8Array(totalSize);
let offset = 0;

for (const chunk of chunks) {
  combined.set(new Uint8Array(chunk), offset);
  offset += chunk.byteLength;
}

const blob = new Blob([combined], { type: mimetype });
```

## Security Properties

### Confidentiality

- **AES-256-GCM**: Strong encryption algorithm
- **Unique IVs**: Each message uses fresh IV
- **256-bit Keys**: Cryptographically strong keys

### Integrity

- **Auth Tags**: 128-bit authentication tags
- **Tag Verification**: Prevents tampering
- **Decryption Failure**: Invalid tags cause decryption to fail

### Replay Protection

- **Timestamps**: Freshness check (±2 minutes)
- **Sequence Numbers**: Strictly increasing
- **Message IDs**: Database uniqueness constraint

## Server Role

The server:
- ✅ Relays encrypted envelopes
- ✅ Stores metadata only (sender, receiver, timestamp, seq, type)
- ✅ Validates timestamps for replay protection
- ❌ Never sees plaintext
- ❌ Never decrypts messages
- ❌ Never stores ciphertext

## Performance

Typical performance (measured):
- **Message Encryption**: < 10ms
- **Message Decryption**: < 10ms
- **File Encryption (1MB)**: < 100ms
- **File Decryption (1MB)**: < 100ms

