# Demo Script for E2EE System

**Duration**: ~15 minutes  
**Purpose**: Demonstrate complete E2EE messaging and file-sharing system

---

## Pre-Demo Setup

1. **Start Server**:
   ```bash
   cd server
   npm install
   npm run dev
   ```

2. **Start Client**:
   ```bash
   cd client
   npm install
   npm run dev
   ```

3. **Verify MongoDB Atlas Connection**:
   - Check `.env` file has `MONGO_URI`
   - Verify connection in server logs

4. **Open Browser**:
   - Navigate to `https://localhost:5173`
   - Accept self-signed certificate warning

---

## Demo Flow

### 1. User Registration & Identity Key Generation (2 min)

**Steps**:
1. Navigate to `/register`
2. Enter test email: `alice@test.com`
3. Enter password: `SecurePass123!`
4. Click "Register"

**What to Show**:
- Registration form
- Success message
- Identity key generation (check browser console)
- Public key upload to server

**Key Points**:
- "Identity keys are generated client-side"
- "Private key stored encrypted in IndexedDB"
- "Public key uploaded to server"

---

### 2. Second User Registration (1 min)

**Steps**:
1. Open incognito/private window
2. Navigate to `/register`
3. Register: `bob@test.com` / `SecurePass123!`

**What to Show**:
- Two users registered
- Both have identity keys

---

### 3. Key Exchange Protocol (3 min)

**Steps**:
1. Alice logs in
2. Navigate to chat interface
3. Start session with Bob
4. Show key exchange process

**What to Show**:
- KEP_INIT message sent
- KEP_RESPONSE received
- Session keys derived
- Console logs showing key exchange

**Key Points**:
- "Ephemeral keys generated for this session"
- "Shared secret computed via ECDH"
- "Session keys derived via HKDF"
- "Forward secrecy established"

---

### 4. Encrypted Messaging (2 min)

**Steps**:
1. Alice sends message: "Hello, Bob! This is encrypted."
2. Show message in chat
3. Open browser DevTools → Network tab
4. Show WebSocket messages

**What to Show**:
- Message input
- Encrypted envelope (ciphertext, iv, authTag)
- Decrypted message displayed
- Network tab showing only encrypted data

**Key Points**:
- "Message encrypted before leaving client"
- "Server sees only ciphertext"
- "Message decrypted only at Bob's client"
- "No plaintext on server"

---

### 5. Encrypted File Sharing (3 min)

**Steps**:
1. Alice uploads a test file (e.g., `test.txt`)
2. Show file upload progress
3. Show file chunks being sent
4. Bob receives and downloads file

**What to Show**:
- File selection
- Encryption progress
- FILE_META and FILE_CHUNK envelopes
- File reconstruction
- Download button

**Key Points**:
- "File encrypted in 256KB chunks"
- "Each chunk encrypted separately"
- "Server sees only encrypted chunks"
- "File reconstructed at receiver"

---

### 6. MITM Attack Simulation (2 min)

**Steps**:
1. Open attack simulator
2. Run unsigned ECDH simulation
3. Show attack succeeds
4. Run signed ECDH simulation
5. Show attack blocked

**What to Show**:
- Attack simulator UI
- Unsigned ECDH: Attack successful
- Signed ECDH: Attack blocked
- Logs showing signature verification

**Key Points**:
- "Unsigned ECDH is vulnerable to MITM"
- "Digital signatures prevent MITM"
- "Signature verification detects key modification"

---

### 7. Replay Attack Simulation (2 min)

**Steps**:
1. Capture a message
2. Attempt to replay
3. Show rejection
4. Check logs

**What to Show**:
- Message capture
- Replay attempt
- Rejection message
- Logs showing replay detection

**Key Points**:
- "Replay attacks detected"
- "Timestamp freshness check"
- "Sequence number monotonicity"
- "Messages rejected and logged"

---

### 8. Logs & Evidence (1 min)

**Steps**:
1. Show server logs directory
2. Display replay_attempts.log
3. Display invalid_signature.log
4. Show network capture (if available)

**What to Show**:
- Log files
- Attack detection entries
- Network traffic (Wireshark/Burp if captured)

**Key Points**:
- "Comprehensive audit trails"
- "All security events logged"
- "No plaintext in logs"

---

## Closing Analysis

**Summary Points**:
1. ✅ End-to-end encryption implemented
2. ✅ Forward secrecy via key rotation
3. ✅ Replay protection active
4. ✅ MITM protection via signatures
5. ✅ Server stores only metadata
6. ✅ All encryption client-side
7. ✅ Comprehensive logging

**Security Features Demonstrated**:
- ECC P-256 identity keys
- Authenticated ECDH key exchange
- AES-256-GCM encryption
- HKDF key derivation
- Replay protection
- MITM prevention
- Forward secrecy

---

## Troubleshooting

**If key exchange fails**:
- Check WebSocket connection
- Verify both users authenticated
- Check browser console for errors

**If messages don't decrypt**:
- Verify session keys exist
- Check sequence numbers
- Verify timestamp freshness

**If file upload fails**:
- Check file size limits
- Verify chunk encryption
- Check network connection

---

## Notes for Recording

- **Speak clearly** about each step
- **Highlight security features** at each stage
- **Show code/console** when relevant
- **Emphasize** "no plaintext on server"
- **Demonstrate** attack simulations clearly
- **Show logs** as evidence

---

**End of Demo Script**

