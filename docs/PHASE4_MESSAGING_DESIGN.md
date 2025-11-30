# Phase 4: End-to-End Encrypted Messaging Design Document

**Generated:** 2025-11-30  
**Version:** 1.0  
**Status:** Implementation Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Message Format](#message-format)
3. [AES-GCM Encryption Diagrams](#aes-gcm-encryption-diagrams)
4. [File Encryption Workflow](#file-encryption-workflow)
5. [UI → Crypto → WebSocket → Server → Receiver Flow](#ui--crypto--websocket--server--receiver-flow)
6. [Replay Protection Logic](#replay-protection-logic)
7. [Storage Rules for Metadata](#storage-rules-for-metadata)
8. [Security Considerations & Pitfalls](#security-considerations--pitfalls)

---

## Overview

Phase 4 implements full **End-to-End Encrypted (E2EE) messaging** using AES-256-GCM encryption. The system provides:

- **Text Message Encryption**: All text messages encrypted with AES-256-GCM
- **File Encryption**: Files encrypted in 256 KB chunks
- **Secure Message Envelopes**: Standardized message format with integrity protection
- **WebSocket Delivery**: Real-time encrypted message delivery
- **Metadata-Only Storage**: Server stores only metadata, never plaintext
- **Replay Protection**: Timestamp, sequence number, and nonce validation
- **Client-Side Decryption**: All decryption happens in browser

**No plaintext content ever appears on the server** - all encryption/decryption is client-side using Web Crypto API.

---

## Message Format

### JSON Schema

All encrypted messages follow this envelope structure:

```json
{
  "type": "MSG" | "FILE_META" | "FILE_CHUNK",
  "sessionId": "string",
  "sender": "string (userId)",
  "receiver": "string (userId)",
  "ciphertext": "base64 string",
  "iv": "base64 string (96 bits)",
  "authTag": "base64 string (128 bits)",
  "timestamp": "number (milliseconds)",
  "seq": "number",
  "nonce": "base64 string",
  "meta": {
    // For FILE_META:
    "filename": "string",
    "size": "number",
    "totalChunks": "number",
    "mimetype": "string",
    
    // For FILE_CHUNK:
    "chunkIndex": "number",
    "totalChunks": "number"
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Message type: `MSG` (text), `FILE_META` (file metadata), `FILE_CHUNK` (file chunk) |
| `sessionId` | string | Session identifier from Phase 3 key exchange |
| `sender` | string | Sender user ID |
| `receiver` | string | Receiver user ID |
| `ciphertext` | base64 | Encrypted message content (AES-256-GCM) |
| `iv` | base64 | Initialization vector (96 bits, 12 bytes) |
| `authTag` | base64 | Authentication tag (128 bits, 16 bytes) |
| `timestamp` | number | Message timestamp (milliseconds since epoch) |
| `seq` | number | Sequence number (strictly increasing per session) |
| `nonce` | base64 | Random nonce for replay protection |
| `meta` | object | Optional metadata (required for file messages) |

### Message Types

#### MSG (Text Message)
```json
{
  "type": "MSG",
  "sessionId": "session-123",
  "sender": "user-1",
  "receiver": "user-2",
  "ciphertext": "base64...",
  "iv": "base64...",
  "authTag": "base64...",
  "timestamp": 1701234567890,
  "seq": 1,
  "nonce": "base64..."
}
```

#### FILE_META (File Metadata)
```json
{
  "type": "FILE_META",
  "sessionId": "session-123",
  "sender": "user-1",
  "receiver": "user-2",
  "ciphertext": "base64...",
  "iv": "base64...",
  "authTag": "base64...",
  "timestamp": 1701234567890,
  "seq": 1,
  "nonce": "base64...",
  "meta": {
    "filename": "document.pdf",
    "size": 1048576,
    "totalChunks": 5,
    "mimetype": "application/pdf"
  }
}
```

#### FILE_CHUNK (File Chunk)
```json
{
  "type": "FILE_CHUNK",
  "sessionId": "session-123",
  "sender": "user-1",
  "receiver": "user-2",
  "ciphertext": "base64...",
  "iv": "base64...",
  "authTag": "base64...",
  "timestamp": 1701234567891,
  "seq": 2,
  "nonce": "base64...",
  "meta": {
    "chunkIndex": 0,
    "totalChunks": 5
  }
}
```

---

## AES-GCM Encryption Diagrams

### Encryption Flow

```
┌─────────────────────────────────────────┐
│  Plaintext (Text or File Chunk)        │
│  ArrayBuffer or String                  │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Get Session Key                        │
│  - sendKey (for outgoing)              │
│  - recvKey (for incoming)              │
│  From: sessionManager                   │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Generate IV                            │
│  - 96 bits (12 bytes)                  │
│  - Cryptographically random            │
│  - Unique per message                  │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  AES-256-GCM Encrypt                   │
│  ────────────────────────────────────  │
│  Algorithm: AES-GCM                     │
│  Key: 256-bit session key              │
│  IV: 96-bit random IV                  │
│  Tag Length: 128 bits                  │
└─────────────────────────────────────────┘
              │
        ┌─────┴─────┐
        ▼           ▼
┌──────────┐  ┌──────────┐
│Ciphertext│  │ Auth Tag │
│(base64)  │  │(base64)  │
└──────────┘  └──────────┘
```

### Decryption Flow

```
┌─────────────────────────────────────────┐
│  Message Envelope                       │
│  - ciphertext (base64)                  │
│  - iv (base64)                          │
│  - authTag (base64)                     │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Decode Base64                          │
│  - ciphertext → ArrayBuffer            │
│  - iv → Uint8Array                     │
│  - authTag → ArrayBuffer               │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Get Session Key                        │
│  - recvKey (for incoming messages)     │
│  From: sessionManager                   │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  AES-256-GCM Decrypt                   │
│  ────────────────────────────────────  │
│  Algorithm: AES-GCM                     │
│  Key: 256-bit session key              │
│  IV: 96-bit IV from envelope           │
│  Tag: 128-bit auth tag                 │
│                                          │
│  ⚠️  Throws if auth tag invalid        │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Plaintext                              │
│  - Text: UTF-8 string                  │
│  - File: ArrayBuffer                   │
└─────────────────────────────────────────┘
```

### AES-GCM Properties

- **Confidentiality**: AES-256 encryption
- **Integrity**: 128-bit authentication tag
- **Authenticity**: Tag verification prevents tampering
- **IV Requirements**: 96-bit IV, unique per message
- **Tag Length**: 128 bits (16 bytes)

---

## File Encryption Workflow

### File Sending Flow

```
┌─────────────────────────────────────────┐
│  User Selects File                      │
│  File object (from input)               │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Read File as ArrayBuffer               │
│  file.arrayBuffer()                     │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Calculate Chunks                       │
│  totalChunks = ceil(fileSize / 256KB)   │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Encrypt Metadata                       │
│  - filename, size, totalChunks, mimetype│
│  - Encrypt with AES-GCM                 │
│  - Build FILE_META envelope             │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  For Each Chunk (0 to totalChunks-1)    │
│  ────────────────────────────────────  │
│  1. Extract chunk: fileBuffer.slice()   │
│  2. Encrypt chunk with AES-GCM          │
│  3. Build FILE_CHUNK envelope           │
│  4. Send via WebSocket                  │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  All Chunks Sent                        │
│  File transmission complete              │
└─────────────────────────────────────────┘
```

### File Receiving Flow

```
┌─────────────────────────────────────────┐
│  Receive FILE_META                      │
│  - Decrypt metadata                     │
│  - Extract: filename, size, totalChunks │
│  - Initialize file reconstruction       │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Receive FILE_CHUNK Messages            │
│  - Decrypt each chunk                   │
│  - Store chunks in order                │
│  - Track: chunkIndex, totalChunks       │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Check: All Chunks Received?            │
│  if chunks.length === totalChunks:      │
│    → Reconstruct file                   │
│  else:                                  │
│    → Wait for more chunks               │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Reconstruct File                       │
│  1. Sort chunks by chunkIndex           │
│  2. Combine into single ArrayBuffer     │
│  3. Create Blob with mimetype           │
│  4. Display download button             │
└─────────────────────────────────────────┘
```

### Chunk Size

- **Default**: 256 KB (262,144 bytes)
- **Rationale**: Balance between:
  - Network efficiency (larger chunks = fewer messages)
  - Memory usage (smaller chunks = less RAM)
  - Encryption overhead (each chunk has IV + auth tag)

---

## UI → Crypto → WebSocket → Server → Receiver Flow

### Complete Message Flow Diagram

```
┌──────────┐
│   UI     │
│ (Chat)   │
└────┬─────┘
     │
     │ 1. User types message
     │    sendMessage("Hello")
     ▼
┌─────────────────────────┐
│  messageFlow.js         │
│  sendEncryptedMessage() │
└────┬────────────────────┘
     │
     │ 2. Load session keys
     │    getSendKey(sessionId)
     ▼
┌─────────────────────────┐
│  sessionManager.js       │
│  Returns: sendKey        │
└────┬────────────────────┘
     │
     │ 3. Encrypt message
     │    encryptAESGCM(sendKey, plaintext)
     ▼
┌─────────────────────────┐
│  aesGcm.js              │
│  - Generate IV          │
│  - AES-256-GCM encrypt  │
│  Returns: {ciphertext,  │
│            iv, authTag} │
└────┬────────────────────┘
     │
     │ 4. Build envelope
     │    buildTextMessageEnvelope()
     ▼
┌─────────────────────────┐
│  messageEnvelope.js     │
│  - Add timestamp        │
│  - Add sequence number   │
│  - Add nonce            │
│  Returns: envelope      │
└────┬────────────────────┘
     │
     │ 5. Send via WebSocket
     │    socket.emit("msg:send", envelope)
     ▼
┌─────────────────────────┐
│  WebSocket Client       │
│  (Socket.IO)            │
└────┬────────────────────┘
     │
     │ 6. Transmit over WSS
     ▼
┌─────────────────────────┐
│  Server WebSocket       │
│  socket-handler.js      │
│  "msg:send" handler     │
└────┬────────────────────┘
     │
     │ 7. Validate timestamp
     │ 8. Store metadata
     ▼
┌─────────────────────────┐
│  MongoDB                │
│  MessageMeta collection │
│  - sessionId            │
│  - sender, receiver     │
│  - timestamp, seq       │
│  - type                 │
│  ⚠️  NO ciphertext!     │
└────┬────────────────────┘
     │
     │ 9. Forward to receiver
     │    recipientSocket.emit("msg:receive")
     ▼
┌─────────────────────────┐
│  Receiver WebSocket     │
│  (Socket.IO Client)     │
└────┬────────────────────┘
     │
     │ 10. Receive envelope
     │     socket.on("msg:receive")
     ▼
┌─────────────────────────┐
│  useChat hook           │
│  handleIncomingMessage()│
└────┬────────────────────┘
     │
     │ 11. Validate envelope
     │     - timestamp freshness
     │     - sequence number
     │     - structure
     ▼
┌─────────────────────────┐
│  messageFlow.js         │
│  handleIncomingMessage()│
└────┬────────────────────┘
     │
     │ 12. Load recvKey
     │     getRecvKey(sessionId)
     ▼
┌─────────────────────────┐
│  sessionManager.js      │
│  Returns: recvKey       │
└────┬────────────────────┘
     │
     │ 13. Decrypt
     │     decryptAESGCM(recvKey, ...)
     ▼
┌─────────────────────────┐
│  aesGcm.js              │
│  - AES-256-GCM decrypt  │
│  - Verify auth tag      │
│  Returns: plaintext     │
└────┬────────────────────┘
     │
     │ 14. Update UI
     │     setMessages([...messages, decrypted])
     ▼
┌──────────┐
│   UI     │
│ (Chat)   │
│ Message  │
│ Displayed│
└──────────┘
```

### Key Points

1. **Server Never Sees Plaintext**: Only encrypted ciphertext passes through server
2. **Metadata Only**: Server stores only message metadata (sender, receiver, timestamp, seq)
3. **Real-Time Delivery**: WebSocket provides instant message delivery
4. **Fallback Support**: REST API available if WebSocket unavailable
5. **Client-Side Only**: All encryption/decryption happens in browser

---

## Replay Protection Logic

### Protection Layers

```
┌─────────────────────────────────────────┐
│  Incoming Message Envelope               │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Layer 1: Structure Validation          │
│  - Required fields present?             │
│  - Type valid?                          │
│  - Base64 format correct?               │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Layer 2: Timestamp Validation          │
│  ────────────────────────────────────  │
│  now = Date.now()                       │
│  age = now - message.timestamp          │
│                                          │
│  if |age| > 2 minutes:                  │
│    → REJECT (replay attempt)           │
│    → LOG to replay_attempts.log         │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Layer 3: Sequence Number Validation    │
│  ────────────────────────────────────  │
│  lastSeq = sessionManager.get(sessionId)│
│                                          │
│  if message.seq <= lastSeq:             │
│    → REJECT (replay attempt)            │
│    → LOG to replay_attempts.log        │
│                                          │
│  else:                                   │
│    → ACCEPT                             │
│    → Update lastSeq = message.seq       │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Layer 4: Message ID Uniqueness         │
│  ────────────────────────────────────  │
│  messageId = sessionId:seq:timestamp    │
│                                          │
│  if messageId exists in DB:             │
│    → REJECT (duplicate)                  │
│    → LOG to replay_detected.log        │
│                                          │
│  else:                                   │
│    → Store messageId in DB              │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Layer 5: Authentication Tag            │
│  ────────────────────────────────────  │
│  During decryption:                     │
│    - AES-GCM verifies auth tag          │
│    - If invalid: throws OperationError  │
│    - Prevents tampering                 │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Message Accepted & Decrypted            │
└─────────────────────────────────────────┘
```

### Replay Detection

**Timestamp Window**: ±2 minutes (120,000 ms)
- Messages older than 2 minutes: **REJECTED**
- Messages from future (>2 min): **REJECTED** (clock skew protection)

**Sequence Numbers**: Strictly increasing
- Each message must have `seq > lastSeq`
- Out-of-order messages: **REJECTED**
- Duplicate sequence numbers: **REJECTED**

**Message IDs**: Unique constraint
- Format: `sessionId:seq:timestamp`
- Database enforces uniqueness
- Duplicate IDs: **REJECTED** (replay attempt)

**Nonce**: Included but not validated server-side
- Client can use for additional validation
- Future: Bloom filter for nonce tracking

---

## Storage Rules for Metadata

### Server Storage (MongoDB)

**Collection**: `messages_meta`

**Stored Fields**:
```javascript
{
  messageId: String,        // Unique identifier
  sessionId: String,         // Session identifier
  sender: ObjectId,          // Reference to User
  receiver: ObjectId,        // Reference to User
  type: String,              // "MSG" | "FILE_META" | "FILE_CHUNK"
  timestamp: Number,         // Message timestamp
  seq: Number,              // Sequence number
  delivered: Boolean,       // Delivery status
  deliveredAt: Date,        // Delivery timestamp
  meta: {                   // Optional metadata
    filename: String,        // For files
    size: Number,           // For files
    totalChunks: Number,    // For files
    chunkIndex: Number,     // For chunks
    mimetype: String        // For files
  },
  createdAt: Date,          // Server timestamp
  updatedAt: Date           // Last update
}
```

**NOT Stored**:
- ❌ `ciphertext` - Never stored on server
- ❌ `iv` - Never stored on server
- ❌ `authTag` - Never stored on server
- ❌ `nonce` - Never stored on server
- ❌ Plaintext content - Never accessible to server

### Client Storage (IndexedDB)

**Store**: `sessions`
- Session keys (rootKey, sendKey, recvKey)
- Sequence numbers
- Last timestamp

**Store**: `identityKeys`
- Encrypted private keys
- Password-derived encryption

**NOT Stored**:
- ❌ Plaintext messages - Only in RAM
- ❌ Decrypted files - Only in RAM until download

---

## Security Considerations & Pitfalls

### ✅ Security Strengths

1. **End-to-End Encryption**: Server cannot decrypt messages
2. **Authenticated Encryption**: AES-GCM provides integrity + confidentiality
3. **Forward Secrecy**: Session keys from Phase 3 provide forward secrecy
4. **Replay Protection**: Multiple layers prevent replay attacks
5. **Key Isolation**: Each session has unique keys
6. **No Plaintext Storage**: Plaintext only in browser RAM

### ⚠️ Security Considerations

#### 1. **Browser Compromise**
- **Risk**: Malicious browser extensions can access keys
- **Mitigation**: User education, extension whitelisting
- **Future**: Consider WebAuthn for key storage

#### 2. **XSS Attacks**
- **Risk**: XSS could steal keys from IndexedDB
- **Mitigation**: CSP headers, input sanitization
- **Note**: Keys are encrypted, but password could be stolen

#### 3. **Timing Attacks**
- **Risk**: Timing differences in decryption could leak information
- **Mitigation**: Web Crypto API provides some protection
- **Note**: Constant-time operations where possible

#### 4. **File Size Limits**
- **Risk**: Large files consume memory during encryption/decryption
- **Mitigation**: Chunking (256 KB chunks)
- **Future**: Stream-based encryption for very large files

#### 5. **Key Rotation**
- **Risk**: Long-lived session keys increase compromise risk
- **Current**: No automatic rotation
- **Future**: Implement key rotation protocol (Phase 4+)

#### 6. **Message Ordering**
- **Risk**: Network reordering could cause issues
- **Mitigation**: Sequence numbers enforce ordering
- **Note**: Out-of-order messages are rejected

#### 7. **Clock Skew**
- **Risk**: Client/server clock differences
- **Mitigation**: ±2 minute window accounts for reasonable skew
- **Note**: Future: NTP synchronization

### 🚨 Common Pitfalls

#### Pitfall 1: Reusing IVs
**Problem**: Reusing IVs with same key breaks security
**Solution**: Generate fresh random IV for each message
**Implementation**: `generateIV()` uses `crypto.getRandomValues()`

#### Pitfall 2: Storing Plaintext
**Problem**: Accidentally logging or storing plaintext
**Solution**: Never log plaintext, only metadata
**Implementation**: Server only stores metadata

#### Pitfall 3: Weak Key Derivation
**Problem**: Using weak keys for encryption
**Solution**: Keys from Phase 3 HKDF derivation (cryptographically strong)
**Implementation**: Session keys derived from ECDH shared secret

#### Pitfall 4: Missing Authentication
**Problem**: Encryption without authentication allows tampering
**Solution**: AES-GCM provides built-in authentication
**Implementation**: 128-bit auth tag verified on decryption

#### Pitfall 5: Race Conditions
**Problem**: Multiple messages processed out of order
**Solution**: Sequence number validation enforces ordering
**Implementation**: Strictly increasing sequence numbers

---

## Implementation Details

### Encryption Parameters

- **Algorithm**: AES-GCM
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Block Size**: 128 bits (AES standard)

### Performance Considerations

- **Chunk Size**: 256 KB balances memory and network efficiency
- **Web Workers**: Future optimization for large file encryption
- **Batch Processing**: Multiple chunks can be encrypted in parallel
- **Memory Usage**: Files loaded entirely into memory (chunked for large files)

### Error Handling

- **Decryption Failures**: Logged but not exposed to user (security)
- **Replay Attempts**: Logged and rejected silently
- **Network Errors**: Retry mechanism (future enhancement)
- **Invalid Envelopes**: Rejected with error logging

---

## Testing Recommendations

1. **Unit Tests**:
   - Encryption/decryption round-trip
   - Envelope validation
   - Replay protection logic

2. **Integration Tests**:
   - End-to-end message flow
   - File encryption/decryption
   - WebSocket delivery

3. **Security Tests**:
   - Replay attack attempts
   - Tampered message detection
   - Invalid key handling

4. **Performance Tests**:
   - Large file encryption
   - Multiple concurrent messages
   - Memory usage profiling

---

## Future Enhancements

1. **Message Deletion**: Secure message deletion protocol
2. **Read Receipts**: End-to-end encrypted read receipts
3. **Message Editing**: Encrypted message editing
4. **Group Messaging**: Multi-party encrypted messaging
5. **Key Rotation**: Automatic session key rotation
6. **Streaming Encryption**: For very large files
7. **Message Search**: Encrypted search (homomorphic encryption?)

---

## Conclusion

Phase 4 provides a complete end-to-end encrypted messaging system with:

- ✅ AES-256-GCM encryption for all messages
- ✅ File encryption with chunking
- ✅ Secure message envelopes
- ✅ Replay protection
- ✅ Metadata-only server storage
- ✅ Real-time WebSocket delivery
- ✅ Client-side decryption

The system ensures **no plaintext content is ever accessible to the server**, providing true end-to-end encryption.

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-30  
**Author**: Phase 4 Implementation

