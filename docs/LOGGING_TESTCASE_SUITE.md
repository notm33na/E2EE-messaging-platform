# Logging Testcase Suite

## TC-ID: LOG-001

**Title:** Authentication Logs - Successful Login
**Objective:** Verify successful login attempts are logged to auth logs
**Prerequisites:**

- Test user account
- Access to server logs
- Successful login

**Detailed Steps:**

1. User attempts login with correct credentials
2. Login succeeds
3. Check server logs: `server/logs/auth-YYYY-MM-DD.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for login attempt present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `level`: "info"
   - `category`: "auth"
   - `message`: Login success message or object
   - `userId`: User ID
   - `success`: true (if present)
   - `ip`: Client IP (if available)
6. Verify Winston JSON format:
   - Valid JSON format
   - Structured fields
   - All required fields present

**Expected Outcome:**

- Successful login logged to auth log
- Log entry contains all required fields
- Log entry is valid JSON
- Timestamp is ISO format

**Evidence to Capture:**

- Log entry from auth log
- Field verification
- JSON format verification
- Timestamp verification

**Pass/Fail Criteria:**

- PASS: Login logged with all required fields, valid JSON
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Authentication logs
- Successful login logging

---

## TC-ID: LOG-002

**Title:** Authentication Logs - Failed Login
**Objective:** Verify failed login attempts are logged to auth logs
**Prerequisites:**

- Test user account
- Access to server logs
- Failed login attempt

**Detailed Steps:**

1. User attempts login with incorrect password
2. Login fails
3. Check server logs: `server/logs/auth-YYYY-MM-DD.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for failed login present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `level`: "info" or "warn"
   - `category`: "auth"
   - `message`: Login failure message or object
   - `userId`: User ID (if user found) or null
   - `success`: false (if present)
   - `reason`: Failure reason (if present)
   - `ip`: Client IP (if available)
6. Verify Winston JSON format:
   - Valid JSON format
   - Structured fields
   - All required fields present

**Expected Outcome:**

- Failed login logged to auth log
- Log entry contains all required fields
- Log entry is valid JSON
- Failure reason included

**Evidence to Capture:**

- Log entry from auth log
- Field verification
- JSON format verification
- Failure reason

**Pass/Fail Criteria:**

- PASS: Failed login logged with all required fields, valid JSON
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Authentication logs
- Failed login logging

---

## TC-ID: LOG-003

**Title:** Authentication Logs - Account Lockout
**Objective:** Verify account lockout events are logged to auth logs
**Prerequisites:**

- Test user account
- Access to server logs
- Multiple failed login attempts (triggering lockout)

**Detailed Steps:**

1. User makes multiple failed login attempts (5+ failures)
2. Account lockout triggered
3. Check server logs: `server/logs/auth-YYYY-MM-DD.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for account lockout present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `level`: "warn" or "error"
   - `category`: "auth"
   - `message`: Account lockout message or object
   - `userId`: User ID
   - `action`: "LOCKED" or similar
   - `reason`: Lockout reason
   - `ip`: Client IP (if available)
6. Verify Winston JSON format:
   - Valid JSON format
   - Structured fields
   - All required fields present

**Expected Outcome:**

- Account lockout logged to auth log
- Log entry contains all required fields
- Log entry is valid JSON
- Lockout reason included

**Evidence to Capture:**

- Log entry from auth log
- Field verification
- JSON format verification
- Lockout reason

**Pass/Fail Criteria:**

- PASS: Account lockout logged with all required fields, valid JSON
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Authentication logs
- Account lockout logging

---

## TC-ID: LOG-004

**Title:** Key Exchange Logs - KEP_INIT Received
**Objective:** Verify KEP_INIT messages are logged to key exchange logs
**Prerequisites:**

- Two authenticated users
- Access to server logs
- KEP_INIT message sent

**Detailed Steps:**

1. Alice sends KEP_INIT to Bob
2. Server receives KEP_INIT
3. Check server logs: `server/logs/key_exchange_attempts.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for KEP_INIT present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "KEY_EXCHANGE"
   - `sessionId`: Session identifier
   - `fromUserId`: Alice's user ID
   - `toUserId`: Bob's user ID
   - `messageType`: "KEP_INIT"
   - `success`: true or false
   - `action`: "ACCEPTED" or "REJECTED"
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- KEP_INIT logged to key exchange log
- Log entry contains all required fields
- Log entry is HMAC-protected
- Log entry is structured and parseable

**Evidence to Capture:**

- Log entry from key_exchange_attempts.log
- Field verification
- HMAC verification
- Format verification

**Pass/Fail Criteria:**

- PASS: KEP_INIT logged with all required fields, HMAC-protected
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Key exchange logs
- KEP_INIT logging

---

## TC-ID: LOG-005

**Title:** Key Exchange Logs - KEP_RESPONSE Received
**Objective:** Verify KEP_RESPONSE messages are logged to key exchange logs
**Prerequisites:**

- Two authenticated users
- Access to server logs
- KEP_RESPONSE message sent

**Detailed Steps:**

1. Bob sends KEP_RESPONSE to Alice
2. Server receives KEP_RESPONSE
3. Check server logs: `server/logs/key_exchange_attempts.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for KEP_RESPONSE present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "KEY_EXCHANGE"
   - `sessionId`: Session identifier
   - `fromUserId`: Bob's user ID
   - `toUserId`: Alice's user ID
   - `messageType`: "KEP_RESPONSE"
   - `success`: true or false
   - `action`: "ACCEPTED" or "REJECTED"
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- KEP_RESPONSE logged to key exchange log
- Log entry contains all required fields
- Log entry is HMAC-protected
- Log entry is structured and parseable

**Evidence to Capture:**

- Log entry from key_exchange_attempts.log
- Field verification
- HMAC verification
- Format verification

**Pass/Fail Criteria:**

- PASS: KEP_RESPONSE logged with all required fields, HMAC-protected
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Key exchange logs
- KEP_RESPONSE logging

---

## TC-ID: LOG-006

**Title:** Replay Logs - Replay Attempt Detected
**Objective:** Verify replay attempts are logged to replay logs
**Prerequisites:**

- Established session
- Replay attempt made
- Access to server logs

**Detailed Steps:**

1. Attacker makes replay attempt
2. Replay detected and rejected
3. Check server logs: `server/logs/replay_attempts.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for replay attempt present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "REPLAY_ATTEMPT"
   - `sessionId`: Session identifier
   - `userId`: User ID (if available)
   - `seq`: Sequence number
   - `timestamp`: Message timestamp (number)
   - `reason`: Rejection reason
   - `action`: "REJECTED"
   - `ip`: Client IP (if available)
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Replay attempt logged to replay log
- Log entry contains all required fields
- Log entry is HMAC-protected
- Log entry is structured and parseable

**Evidence to Capture:**

- Log entry from replay_attempts.log
- Field verification
- HMAC verification
- Format verification

**Pass/Fail Criteria:**

- PASS: Replay attempt logged with all required fields, HMAC-protected
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Replay logs
- Replay attempt logging

---

## TC-ID: LOG-007

**Title:** Replay Logs - Timestamp Failure
**Objective:** Verify timestamp validation failures are logged to replay logs
**Prerequisites:**

- Established session
- Message with stale timestamp
- Access to server logs

**Detailed Steps:**

1. Message with stale timestamp (3 minutes ago) received
2. Timestamp validation fails
3. Check server logs: `server/logs/replay_attempts.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for timestamp failure present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "REPLAY_ATTEMPT"
   - `sessionId`: Session identifier
   - `userId`: User ID (if available)
   - `seq`: Sequence number
   - `timestamp`: Message timestamp (number, stale)
   - `reason`: "Timestamp out of validity window"
   - `action`: "REJECTED"
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Timestamp failure logged to replay log
- Log entry contains all required fields
- Log entry is HMAC-protected
- Reason field indicates timestamp failure

**Evidence to Capture:**

- Log entry from replay_attempts.log
- Field verification
- HMAC verification
- Reason field

**Pass/Fail Criteria:**

- PASS: Timestamp failure logged with all required fields, HMAC-protected
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Replay logs
- Timestamp failure logging

---

## TC-ID: LOG-008

**Title:** Invalid Signature Logs - KEP_INIT Signature Failure
**Objective:** Verify invalid signatures in KEP_INIT are logged
**Prerequisites:**

- Two authenticated users
- Invalid signature in KEP_INIT
- Access to server logs

**Detailed Steps:**

1. Alice sends KEP_INIT with invalid signature (or attacker modifies it)
2. Bob receives and validates KEP_INIT
3. Signature verification fails
4. Check server logs: `server/logs/invalid_signature.log`
5. Verify log entry exists:
   - Log file exists
   - Entry for invalid signature present
6. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "INVALID_SIGNATURE"
   - `sessionId`: Session identifier
   - `userId`: Bob's userId (receiver)
   - `messageType`: "KEP_INIT"
   - `reason`: "Invalid signature" or specific error
   - `action`: "REJECTED"
7. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Invalid signature logged to invalid_signature.log
- Log entry contains all required fields
- Log entry is HMAC-protected
- Log entry is structured and parseable

**Evidence to Capture:**

- Log entry from invalid_signature.log
- Field verification
- HMAC verification
- Format verification

**Pass/Fail Criteria:**

- PASS: Invalid signature logged with all required fields, HMAC-protected
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Invalid signature logs
- KEP_INIT signature failure logging

---

## TC-ID: LOG-009

**Title:** Invalid Signature Logs - KEP_RESPONSE Signature Failure
**Objective:** Verify invalid signatures in KEP_RESPONSE are logged
**Prerequisites:**

- Two authenticated users
- Invalid signature in KEP_RESPONSE
- Access to server logs

**Detailed Steps:**

1. Bob sends KEP_RESPONSE with invalid signature (or attacker modifies it)
2. Alice receives and validates KEP_RESPONSE
3. Signature verification fails
4. Check server logs: `server/logs/invalid_signature.log`
5. Verify log entry exists:
   - Log file exists
   - Entry for invalid signature present
6. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "INVALID_SIGNATURE"
   - `sessionId`: Session identifier
   - `userId`: Alice's userId (receiver)
   - `messageType`: "KEP_RESPONSE"
   - `reason`: "Invalid signature" or specific error
   - `action`: "REJECTED"
7. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Invalid signature logged to invalid_signature.log
- Log entry contains all required fields
- Log entry is HMAC-protected
- Log entry is structured and parseable

**Evidence to Capture:**

- Log entry from invalid_signature.log
- Field verification
- HMAC verification
- Format verification

**Pass/Fail Criteria:**

- PASS: Invalid signature logged with all required fields, HMAC-protected
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Invalid signature logs
- KEP_RESPONSE signature failure logging

---

## TC-ID: LOG-010

**Title:** File Encryption Logs - FILE_META Forwarding
**Objective:** Verify FILE_META message forwarding is logged
**Prerequisites:**

- Two authenticated users
- File sent (FILE_META envelope)
- Access to server logs

**Detailed Steps:**

1. Alice sends FILE_META envelope to Bob
2. Server receives and forwards FILE_META
3. Check server logs: `server/logs/msg_forwarding.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for FILE_META forwarding present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `senderId`: Alice's user ID
   - `receiverId`: Bob's user ID
   - `sessionId`: Session identifier
   - `messageType`: "FILE_META"
   - `type`: "msg_forwarding"
6. Verify log format:
   - JSON format (may not be HMAC-protected for forwarding logs)
   - All required fields present

**Expected Outcome:**

- FILE_META forwarding logged
- Log entry contains all required fields
- Log entry is valid JSON
- Timestamp is ISO format

**Evidence to Capture:**

- Log entry from msg_forwarding.log
- Field verification
- JSON format verification

**Pass/Fail Criteria:**

- PASS: FILE_META forwarding logged with all required fields
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- File encryption logs
- FILE_META forwarding logging

---

## TC-ID: LOG-011

**Title:** File Encryption Logs - FILE_CHUNK Forwarding
**Objective:** Verify FILE_CHUNK message forwarding is logged
**Prerequisites:**

- Two authenticated users
- File sent (FILE_CHUNK envelope)
- Access to server logs

**Detailed Steps:**

1. Alice sends FILE_CHUNK envelope to Bob
2. Server receives and forwards FILE_CHUNK
3. Check server logs: `server/logs/file_chunk_forwarding.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for FILE_CHUNK forwarding present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `senderId`: Alice's user ID
   - `receiverId`: Bob's user ID
   - `sessionId`: Session identifier
   - `chunkIndex`: Chunk index number
   - `type`: "file_chunk_forwarding"
6. Verify log format:
   - JSON format
   - All required fields present

**Expected Outcome:**

- FILE_CHUNK forwarding logged
- Log entry contains all required fields
- Log entry is valid JSON
- Chunk index included

**Evidence to Capture:**

- Log entry from file_chunk_forwarding.log
- Field verification
- JSON format verification
- Chunk index verification

**Pass/Fail Criteria:**

- PASS: FILE_CHUNK forwarding logged with all required fields
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- File encryption logs
- FILE_CHUNK forwarding logging

---

## TC-ID: LOG-012

**Title:** Key Update Logs - Key Rotation Event
**Objective:** Verify key rotation events are logged to security logs
**Prerequisites:**

- Two authenticated users
- Established session
- Key rotation triggered
- Access to server logs

**Detailed Steps:**

1. User triggers key rotation (or automatic rotation occurs)
2. KEY_UPDATE message sent
3. Check server logs: `server/logs/security-YYYY-MM-DD.log`
4. Verify log entry exists:
   - Log file exists
   - Entry for key rotation present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `level`: "info"
   - `category`: "security"
   - `event`: "key_rotation"
   - `userId`: User ID
   - `sessionId`: Session identifier
   - `rotationSeq`: Rotation sequence number (if present)
6. Verify Winston JSON format:
   - Valid JSON format
   - Structured fields
   - All required fields present

**Expected Outcome:**

- Key rotation logged to security log
- Log entry contains all required fields
- Log entry is valid JSON
- Rotation event identified

**Evidence to Capture:**

- Log entry from security log
- Field verification
- JSON format verification
- Event type verification

**Pass/Fail Criteria:**

- PASS: Key rotation logged with all required fields, valid JSON
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Key update logs
- Key rotation logging

---

## TC-ID: LOG-013

**Title:** Key Update Logs - Key Revocation Event
**Objective:** Verify key revocation events are logged (if implemented)
**Prerequisites:**

- Two authenticated users
- Key revocation functionality
- Access to server logs

**Detailed Steps:**

1. User revokes identity key (if implemented)
2. Revocation event occurs
3. Check server logs: `server/logs/security-YYYY-MM-DD.log`
4. Verify log entry exists (if revocation implemented):
   - Log file exists
   - Entry for key revocation present
5. Verify log entry structure:
   - `timestamp`: ISO timestamp
   - `level`: "warn" or "info"
   - `category`: "security"
   - `event`: "key_revocation" or similar
   - `userId`: User ID
   - `keyHash`: Revoked key hash (if present)
   - `reason`: Revocation reason (if present)
6. Verify Winston JSON format:
   - Valid JSON format
   - Structured fields
   - All required fields present

**Expected Outcome:**

- Key revocation logged (if implemented)
- Log entry contains all required fields
- Log entry is valid JSON
- Revocation event identified

**Evidence to Capture:**

- Log entry from security log (if present)
- Field verification
- JSON format verification
- Event type verification

**Pass/Fail Criteria:**

- PASS: Key revocation logged (if implemented) with all required fields
- FAIL: Not logged or missing fields (if implemented)

**PDF Requirements Validated:**

- Key update logs
- Key revocation logging (if implemented)

---

## TC-ID: LOG-014

**Title:** Log Rotation Correctness - Daily Rotation
**Objective:** Verify logs rotate daily at midnight
**Prerequisites:**

- Server running
- Logs directory access
- Ability to wait for midnight or manipulate system time

**Detailed Steps:**

1. Create log entry in current day's log file
2. Wait for midnight (or manipulate system time)
3. Create new log entry after midnight
4. Verify log rotation:
   - Old log file: `auth-YYYY-MM-DD.log` (previous day)
   - New log file: `auth-YYYY-MM-DD.log` (current day)
   - Old log file compressed: `auth-YYYY-MM-DD.log.gz`
5. Verify old log file:
   - Contains entries from previous day
   - File is readable (or compressed)
6. Verify new log file:
   - Contains entries from current day
   - File is new and separate

**Expected Outcome:**

- Logs rotate daily at midnight
- Old logs compressed
- New log file created
- Entries separated by date

**Evidence to Capture:**

- Old log file (compressed)
- New log file
- File timestamps
- Entry dates

**Pass/Fail Criteria:**

- PASS: Logs rotate daily, old logs compressed, new file created
- FAIL: Rotation doesn't occur or files not separated

**PDF Requirements Validated:**

- Log rotation correctness
- Daily rotation

---

## TC-ID: LOG-015

**Title:** Log Rotation Correctness - Size-Based Rotation
**Objective:** Verify logs rotate when file size exceeds 100MB
**Prerequisites:**

- Server running
- Logs directory access
- Ability to generate large log files

**Detailed Steps:**

1. Generate log entries until file size approaches 100MB
2. Continue generating entries
3. Verify log rotation:
   - File size reaches 100MB
   - Log rotates automatically
   - Old log file: `auth-YYYY-MM-DD.log` (compressed)
   - New log file: `auth-YYYY-MM-DD.log` (new, smaller)
4. Verify old log file:
   - Size approximately 100MB (before compression)
   - Compressed to `.gz` format
   - Contains entries up to rotation point
5. Verify new log file:
   - Size smaller than 100MB
   - Contains entries after rotation

**Expected Outcome:**

- Logs rotate when size exceeds 100MB
- Old logs compressed
- New log file created
- Size limit enforced

**Evidence to Capture:**

- Old log file size (before compression)
- Compressed log file
- New log file
- Rotation trigger point

**Pass/Fail Criteria:**

- PASS: Logs rotate at 100MB, old logs compressed, new file created
- FAIL: Rotation doesn't occur or size limit not enforced

**PDF Requirements Validated:**

- Log rotation correctness
- Size-based rotation

---

## TC-ID: LOG-016

**Title:** Log Rotation Correctness - Retention Policy
**Objective:** Verify old log files are deleted after retention period
**Prerequisites:**

- Server running
- Logs directory access
- Logs older than retention period

**Detailed Steps:**

1. Create log files of various ages:
   - 25 days old (within 30-day retention)
   - 35 days old (beyond 30-day retention for auth logs)
   - 85 days old (within 90-day retention for security logs)
   - 95 days old (beyond 90-day retention for security logs)
2. Wait for retention cleanup (or trigger manually)
3. Verify cleanup:
   - Auth logs older than 30 days: Deleted
   - Security logs older than 90 days: Deleted
   - Recent logs: Retained
4. Verify retention periods:
   - Auth logs: 30 days
   - Security logs: 90 days
   - Replay logs: 90 days
   - Alerts: 180 days

**Expected Outcome:**

- Old logs deleted after retention period
- Retention periods enforced correctly
- Recent logs retained
- Cleanup works as expected

**Evidence to Capture:**

- Log file ages
- Deleted files list
- Retained files list
- Retention period verification

**Pass/Fail Criteria:**

- PASS: Old logs deleted, retention periods enforced, recent logs retained
- FAIL: Cleanup doesn't occur or wrong files deleted

**PDF Requirements Validated:**

- Log rotation correctness
- Retention policy enforcement

---

## TC-ID: LOG-017

**Title:** Structured Log Format - JSON Format Validation
**Objective:** Verify all log entries are valid JSON format
**Prerequisites:**

- Various log files with entries
- Access to server logs

**Detailed Steps:**

1. Select multiple log files:
   - `auth-YYYY-MM-DD.log`
   - `security-YYYY-MM-DD.log`
   - `replay_attempts.log`
   - `invalid_signature.log`
2. Read each log file
3. For each log entry:
   - Extract JSON portion (before `|HMAC:` if present)
   - Parse JSON: `JSON.parse(entryJson)`
   - Verify parsing succeeds
4. Verify JSON structure:
   - Valid JSON syntax
   - Proper object structure
   - No syntax errors
5. Verify all entries:
   - All entries are valid JSON
   - No malformed entries
   - Consistent format

**Expected Outcome:**

- All log entries are valid JSON
- JSON parsing succeeds
- Consistent format across entries
- No syntax errors

**Evidence to Capture:**

- JSON parsing results
- Format verification
- Error count (should be 0)
- Sample entries

**Pass/Fail Criteria:**

- PASS: All entries valid JSON, parsing succeeds
- FAIL: Invalid JSON or parsing errors

**PDF Requirements Validated:**

- Structured log format
- JSON format validation

---

## TC-ID: LOG-018

**Title:** Metadata Presence - Required Fields in Log Entries
**Objective:** Verify all log entries contain required metadata fields
**Prerequisites:**

- Various log files with entries
- Access to server logs

**Detailed Steps:**

1. Define required fields for each log type:
   - Authentication: `timestamp`, `eventType`, `userId`, `success`
   - Key Exchange: `timestamp`, `eventType`, `sessionId`, `fromUserId`, `toUserId`, `messageType`
   - Replay: `timestamp`, `eventType`, `sessionId`, `seq`, `reason`
   - Invalid Signature: `timestamp`, `eventType`, `sessionId`, `userId`, `messageType`, `reason`
2. Read log entries from each log type
3. For each entry:
   - Verify `timestamp` field present
   - Verify `eventType` field present
   - Verify type-specific required fields present
4. Verify field values:
   - Fields are not null or undefined
   - Fields have appropriate types (string, number, boolean)
5. Count missing fields:
   - Track entries with missing required fields
   - Report any missing fields

**Expected Outcome:**

- All log entries contain required metadata fields
- Fields are not null or undefined
- Field types are correct
- No missing required fields

**Evidence to Capture:**

- Field presence verification
- Missing field count (should be 0)
- Field type verification
- Sample entries

**Pass/Fail Criteria:**

- PASS: All entries have required fields, no missing fields
- FAIL: Missing required fields or null values

**PDF Requirements Validated:**

- Metadata presence
- Required fields validation

---

## TC-ID: LOG-019

**Title:** Timestamps - ISO 8601 Format
**Objective:** Verify all log timestamps are in ISO 8601 format
**Prerequisites:**

- Various log files with entries
- Access to server logs

**Detailed Steps:**

1. Read log entries from multiple log files
2. Extract timestamp from each entry:
   - `timestamp` field value
3. Verify timestamp format:
   - Format: ISO 8601 (e.g., "2025-01-27T10:30:45.123Z")
   - Can be parsed: `new Date(timestamp)`
   - Parsing succeeds without errors
4. Verify timestamp validity:
   - Date is valid (not NaN)
   - Date is reasonable (not too far in past/future)
5. Verify consistency:
   - All timestamps in same format
   - No mixed formats
   - Consistent precision

**Expected Outcome:**

- All timestamps in ISO 8601 format
- Timestamps can be parsed
- Dates are valid
- Consistent format across entries

**Evidence to Capture:**

- Timestamp format verification
- Parsing results
- Invalid timestamp count (should be 0)
- Sample timestamps

**Pass/Fail Criteria:**

- PASS: All timestamps ISO 8601, parseable, valid
- FAIL: Invalid format or unparseable timestamps

**PDF Requirements Validated:**

- Timestamps
- ISO 8601 format validation

---

## TC-ID: LOG-020

**Title:** Timestamps - Chronological Order
**Objective:** Verify log entries are in chronological order (or can be sorted)
**Prerequisites:**

- Log file with multiple entries
- Access to server logs

**Detailed Steps:**

1. Read log file with multiple entries
2. Extract timestamps from all entries
3. Parse timestamps: `new Date(timestamp)`
4. Verify chronological order:
   - Sort entries by timestamp
   - Compare with original order
   - Verify entries are in order (or can be sorted)
5. Verify no future timestamps:
   - All timestamps <= current time
   - No timestamps from future
6. Verify reasonable time gaps:
   - Timestamps are not too far apart (unless expected)
   - No suspicious time jumps

**Expected Outcome:**

- Log entries can be sorted chronologically
- No future timestamps
- Reasonable time gaps
- Consistent ordering

**Evidence to Capture:**

- Timestamp sorting results
- Chronological order verification
- Future timestamp count (should be 0)
- Time gap analysis

**Pass/Fail Criteria:**

- PASS: Entries sortable chronologically, no future timestamps
- FAIL: Cannot sort or future timestamps present

**PDF Requirements Validated:**

- Timestamps
- Chronological order validation

---

## TC-ID: LOG-021

**Title:** Alerts - Auth Failure Threshold Alert
**Objective:** Verify auth failure threshold alerts are logged
**Prerequisites:**

- Test user account
- Access to server logs
- 5+ failed login attempts in 5 minutes

**Detailed Steps:**

1. User makes 5 failed login attempts within 5 minutes
2. Alert threshold reached
3. Check server logs: `server/logs/alerts.log`
4. Verify alert entry exists:
   - Log file exists
   - Entry for auth failure threshold present
5. Verify alert entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "AUTH_FAILURE_THRESHOLD"
   - `userId`: User ID (or null if unknown)
   - `ip`: Client IP
   - `attemptCount`: Number of attempts (>= 5)
   - `timeWindow`: "5 minutes"
   - `threshold`: 5
   - `reason`: Alert reason
   - `recentAttempts`: Array of recent attempts
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Auth failure threshold alert logged
- Log entry contains all required fields
- Log entry is HMAC-protected
- Alert triggered at correct threshold

**Evidence to Capture:**

- Log entry from alerts.log
- Field verification
- HMAC verification
- Threshold verification

**Pass/Fail Criteria:**

- PASS: Alert logged with all required fields, HMAC-protected, threshold correct
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Alerts
- Auth failure threshold alert

---

## TC-ID: LOG-022

**Title:** Alerts - Replay Attempt Threshold Alert
**Objective:** Verify replay attempt threshold alerts are logged
**Prerequisites:**

- Established session
- 3+ replay attempts from same IP in 10 minutes
- Access to server logs

**Detailed Steps:**

1. Attacker makes 3 replay attempts from same IP within 10 minutes
2. Alert threshold reached
3. Check server logs: `server/logs/alerts.log`
4. Verify alert entry exists:
   - Log file exists
   - Entry for replay attempt threshold present
5. Verify alert entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "REPLAY_ATTEMPT_THRESHOLD"
   - `ip`: Client IP
   - `attemptCount`: Number of attempts (>= 3)
   - `timeWindow`: "10 minutes"
   - `threshold`: 3
   - `reason`: Alert reason
   - `recentAttempts`: Array of recent attempts
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Replay attempt threshold alert logged
- Log entry contains all required fields
- Log entry is HMAC-protected
- Alert triggered at correct threshold

**Evidence to Capture:**

- Log entry from alerts.log
- Field verification
- HMAC verification
- Threshold verification

**Pass/Fail Criteria:**

- PASS: Alert logged with all required fields, HMAC-protected, threshold correct
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Alerts
- Replay attempt threshold alert

---

## TC-ID: LOG-023

**Title:** Alerts - Signature Failure Threshold Alert
**Objective:** Verify signature failure threshold alerts are logged
**Prerequisites:**

- Two authenticated users
- 2+ signature failures in 10 minutes
- Access to server logs

**Detailed Steps:**

1. User experiences 2 signature validation failures within 10 minutes
2. Alert threshold reached
3. Check server logs: `server/logs/alerts.log`
4. Verify alert entry exists:
   - Log file exists
   - Entry for signature failure threshold present
5. Verify alert entry structure:
   - `timestamp`: ISO timestamp
   - `eventType`: "SIGNATURE_FAILURE_THRESHOLD"
   - `userId`: User ID
   - `failureCount`: Number of failures (>= 2)
   - `timeWindow`: "10 minutes"
   - `threshold`: 2
   - `reason`: Alert reason
   - `recentFailures`: Array of recent failures
6. Verify HMAC protection:
   - Log entry format: `{JSON}|HMAC:{base64-hmac}`
   - HMAC can be verified

**Expected Outcome:**

- Signature failure threshold alert logged
- Log entry contains all required fields
- Log entry is HMAC-protected
- Alert triggered at correct threshold

**Evidence to Capture:**

- Log entry from alerts.log
- Field verification
- HMAC verification
- Threshold verification

**Pass/Fail Criteria:**

- PASS: Alert logged with all required fields, HMAC-protected, threshold correct
- FAIL: Not logged or missing fields

**PDF Requirements Validated:**

- Alerts
- Signature failure threshold alert

---

## TC-ID: LOG-024

**Title:** Log Tamper Detection - HMAC Verification
**Objective:** Verify HMAC verification detects log tampering
**Prerequisites:**

- Log file with HMAC-protected entries
- Access to log file
- Ability to modify log file

**Detailed Steps:**

1. Read HMAC-protected log entry:
   - Format: `{JSON}|HMAC:{base64-hmac}`
2. Verify original entry:
   - Extract JSON and HMAC
   - Verify HMAC: `verifyLogEntry(logLine)`
   - Verification returns `{ valid: true }`
3. Tamper with log entry:
   - Modify JSON content (e.g., change `userId` or `reason`)
   - Keep original HMAC
4. Verify tampering detected:
   - Verify HMAC on tampered entry: `verifyLogEntry(tamperedLine)`
   - Verification returns `{ valid: false, error: "HMAC verification failed" }`
5. Test multiple tampering scenarios:
   - Modify JSON field
   - Corrupt HMAC
   - Remove HMAC
   - Add extra data

**Expected Outcome:**

- Original entry passes HMAC verification
- Tampered entries fail HMAC verification
- All tampering scenarios detected
- Error messages indicate tampering

**Evidence to Capture:**

- Original entry verification (valid: true)
- Tampered entry verification (valid: false)
- Error messages
- Tampering scenarios tested

**Pass/Fail Criteria:**

- PASS: Original valid, tampered entries detected, all scenarios work
- FAIL: Tampering not detected or false positives

**PDF Requirements Validated:**

- Log tamper detection
- HMAC verification

---

## TC-ID: LOG-025

**Title:** Log Tamper Detection - Multiple Tampered Entries
**Objective:** Verify system detects multiple tampered log entries
**Prerequisites:**

- Log file with multiple HMAC-protected entries
- Access to log file
- Ability to modify log file

**Detailed Steps:**

1. Read log file with 10+ entries
2. Tamper with multiple entries:
   - Entry 3: Modify JSON content
   - Entry 7: Corrupt HMAC
   - Entry 9: Remove HMAC
3. Verify each entry:
   - Use `verifyLogEntry()` on each entry
   - Track which entries are valid/invalid
4. Verify detection:
   - Tampered entries return `{ valid: false }`
   - Valid entries return `{ valid: true }`
   - All tampered entries detected
5. Verify error reporting:
   - Each tampered entry has specific error message
   - Errors indicate type of tampering

**Expected Outcome:**

- Multiple tampered entries detected
- Valid entries still pass verification
- Error messages specific to tampering type
- All tampering detected

**Evidence to Capture:**

- Verification results for all entries
- Tampered entry identification
- Error messages
- Detection rate (100%)

**Pass/Fail Criteria:**

- PASS: All tampered entries detected, valid entries pass
- FAIL: Tampered entries not detected or false positives

**PDF Requirements Validated:**

- Log tamper detection
- Multiple entry verification

---

## TC-ID: LOG-026

**Title:** Log Verification Script Behavior - Single File Verification
**Objective:** Verify log verification script works on single file
**Prerequisites:**

- Log file with entries
- Access to verifyLogs.js script
- Command line access

**Detailed Steps:**

1. Run verification script on single file:
   - `node scripts/verifyLogs.js --file=logs/replay_attempts.log`
2. Verify script execution:
   - Script runs without errors
   - Output displayed to console
3. Verify output format:
   - File name displayed
   - Valid entry count displayed
   - Invalid/tampered entry count displayed
   - Integrity score displayed (percentage)
4. Verify verification results:
   - Valid entries counted correctly
   - Invalid entries identified
   - Tampered entries identified
5. Verify error reporting:
   - Errors listed (if any)
   - Error messages descriptive
   - Line numbers included

**Expected Outcome:**

- Script executes successfully
- Output format correct
- Verification results accurate
- Errors reported clearly

**Evidence to Capture:**

- Script output
- Verification results
- Error messages (if any)
- Integrity score

**Pass/Fail Criteria:**

- PASS: Script works, output correct, results accurate
- FAIL: Script fails or incorrect results

**PDF Requirements Validated:**

- Log verification script behavior
- Single file verification

---

## TC-ID: LOG-027

**Title:** Log Verification Script Behavior - Directory Verification
**Objective:** Verify log verification script works on directory
**Prerequisites:**

- Logs directory with multiple log files
- Access to verifyLogs.js script
- Command line access

**Detailed Steps:**

1. Run verification script on directory:
   - `node scripts/verifyLogs.js --dir=logs`
2. Verify script execution:
   - Script runs without errors
   - Processes all .log files in directory
3. Verify output format:
   - Each file processed separately
   - Results for each file displayed
   - Summary section at end
4. Verify summary:
   - Total entries across all files
   - Total valid entries
   - Total invalid/tampered entries
   - Overall integrity score
5. Verify file processing:
   - All .log files processed
   - Non-log files ignored
   - Results accurate for each file

**Expected Outcome:**

- Script processes all log files in directory
- Results displayed for each file
- Summary provides overall statistics
- All files verified correctly

**Evidence to Capture:**

- Script output
- Per-file results
- Summary statistics
- File count verification

**Pass/Fail Criteria:**

- PASS: Script processes directory, all files verified, summary correct
- FAIL: Script fails or files missed

**PDF Requirements Validated:**

- Log verification script behavior
- Directory verification

---

## TC-ID: LOG-028

**Title:** Log Verification Script Behavior - Structure Validation
**Objective:** Verify script validates log entry structure
**Prerequisites:**

- Log file with entries
- Access to verifyLogs.js script
- Log entries with known structure

**Detailed Steps:**

1. Run verification script on log file
2. Verify structure validation:
   - Script checks required fields for each event type
   - Missing fields reported as errors
   - Invalid field types reported
3. Verify required fields:
   - For REPLAY_ATTEMPT: `timestamp`, `eventType`, `sessionId`, `seq`, `reason`
   - For INVALID_SIGNATURE: `timestamp`, `eventType`, `sessionId`, `userId`, `messageType`, `reason`
   - For AUTH_ATTEMPT: `timestamp`, `eventType`, `userId`, `success`, `reason`
4. Verify validation results:
   - Entries with all required fields: Valid
   - Entries missing required fields: Invalid
   - Errors specify missing fields
5. Verify timestamp validation:
   - Valid ISO timestamps: Pass
   - Invalid timestamps: Fail with error

**Expected Outcome:**

- Structure validation works correctly
- Required fields checked
- Missing fields reported
- Timestamp format validated

**Evidence to Capture:**

- Validation results
- Missing field reports
- Timestamp validation results
- Error messages

**Pass/Fail Criteria:**

- PASS: Structure validation works, required fields checked, errors reported
- FAIL: Validation doesn't work or missing fields not detected

**PDF Requirements Validated:**

- Log verification script behavior
- Structure validation

---

## TC-ID: LOG-029

**Title:** Log Verification Script Behavior - HMAC Integrity Verification
**Objective:** Verify script verifies HMAC integrity of log entries
**Prerequisites:**

- Log file with HMAC-protected entries
- Access to verifyLogs.js script
- Some tampered entries (optional)

**Detailed Steps:**

1. Run verification script on log file with HMAC-protected entries
2. Verify HMAC verification:
   - Script verifies HMAC for each entry
   - Valid HMAC: Entry marked as valid
   - Invalid HMAC: Entry marked as tampered
3. Verify tampered entry detection:
   - Tampered entries identified
   - Error message: "HMAC verification failed - log entry may be tampered"
   - Tampered count incremented
4. Verify valid entry handling:
   - Valid entries pass HMAC verification
   - Valid count incremented
5. Verify error reporting:
   - Tampered entries listed in errors
   - Line numbers included
   - Error messages descriptive

**Expected Outcome:**

- HMAC verification works correctly
- Tampered entries detected
- Valid entries pass verification
- Errors reported clearly

**Evidence to Capture:**

- HMAC verification results
- Tampered entry detection
- Valid entry count
- Error messages

**Pass/Fail Criteria:**

- PASS: HMAC verification works, tampered entries detected, valid entries pass
- FAIL: Verification doesn't work or tampering not detected

**PDF Requirements Validated:**

- Log verification script behavior
- HMAC integrity verification

---

## TC-ID: LOG-030

**Title:** Log Verification Script Behavior - Error Reporting
**Objective:** Verify script reports errors clearly and accurately
**Prerequisites:**

- Log file with various entry types (valid, invalid, tampered)
- Access to verifyLogs.js script

**Detailed Steps:**

1. Create log file with mixed entries:
   - Valid entries
   - Invalid entries (missing fields)
   - Tampered entries (invalid HMAC)
2. Run verification script
3. Verify error reporting:
   - Errors listed in output
   - Line numbers included for each error
   - Error messages descriptive
   - Error type identified (invalid vs tampered)
4. Verify error limit:
   - If > 10 errors: First 10 shown, total count displayed
   - If <= 10 errors: All errors shown
5. Verify error accuracy:
   - Errors correspond to actual problems
   - Line numbers correct
   - Error messages accurate

**Expected Outcome:**

- Errors reported clearly
- Line numbers accurate
- Error messages descriptive
- Error limit enforced

**Evidence to Capture:**

- Error output
- Line number verification
- Error message accuracy
- Error count

**Pass/Fail Criteria:**

- PASS: Errors reported clearly, line numbers accurate, messages descriptive
- FAIL: Errors not reported or inaccurate

**PDF Requirements Validated:**

- Log verification script behavior
- Error reporting

---

**End of Logging Testcase Suite**
