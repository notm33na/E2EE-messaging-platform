/**
 * Audit Trail API Tests
 * Tests metadata audit trail endpoints for non-repudiation
 */

import { MetadataAudit } from '../src/models/MetadataAudit.js';
import { MessageMeta } from '../src/models/MessageMeta.js';
import { setupTestDB, cleanTestDB, closeTestDB, generateTestUser } from './setup.js';
import { userService } from '../src/services/user.service.js';

describe('Audit Trail API Tests', () => {
  let testUser1, testUser2;

  beforeAll(async () => {
    await setupTestDB();
  });

  afterAll(async () => {
    await closeTestDB();
  });

  beforeEach(async () => {
    await cleanTestDB();
    const userData1 = generateTestUser();
    const userData2 = generateTestUser();
    testUser1 = await userService.createUser(userData1.email, userData1.password);
    testUser2 = await userService.createUser(userData2.email, userData2.password);
  });

  describe('MetadataAudit Model', () => {
    test('should create audit trail entry', async () => {
      const auditEntry = await MetadataAudit.create({
        messageId: 'msg-123',
        sessionId: 'session-123',
        action: 'CREATE',
        changedBy: testUser1.id,
        newValues: { messageId: 'msg-123', type: 'MSG' },
        timestamp: new Date()
      });

      expect(auditEntry.messageId).toBe('msg-123');
      expect(auditEntry.action).toBe('CREATE');
      expect(auditEntry.changedBy.toString()).toBe(testUser1.id.toString());
    });

    test('should query audit trail by messageId', async () => {
      // Create multiple audit entries
      await MetadataAudit.create({
        messageId: 'msg-123',
        sessionId: 'session-123',
        action: 'CREATE',
        changedBy: testUser1.id,
        timestamp: new Date()
      });

      await MetadataAudit.create({
        messageId: 'msg-123',
        sessionId: 'session-123',
        action: 'UPDATE',
        changedBy: testUser1.id,
        timestamp: new Date()
      });

      const auditTrail = await MetadataAudit.find({ messageId: 'msg-123' })
        .sort({ timestamp: -1 });

      expect(auditTrail.length).toBe(2);
      expect(auditTrail[0].action).toBe('UPDATE'); // Most recent first
      expect(auditTrail[1].action).toBe('CREATE');
    });

    test('should query audit trail by sessionId', async () => {
      await MetadataAudit.create({
        messageId: 'msg-123',
        sessionId: 'session-123',
        action: 'CREATE',
        changedBy: testUser1.id,
        timestamp: new Date()
      });

      const auditTrail = await MetadataAudit.find({ sessionId: 'session-123' });
      expect(auditTrail.length).toBe(1);
      expect(auditTrail[0].messageId).toBe('msg-123');
    });
  });

  describe('Audit Trail Integration', () => {
    test('should support querying audit trail by messageId', async () => {
      // Create audit entry directly
      await MetadataAudit.create({
        messageId: 'msg-audit-1',
        sessionId: 'session-audit-1',
        action: 'CREATE',
        changedBy: testUser1.id,
        timestamp: new Date()
      });

      // Query audit trail
      const auditEntries = await MetadataAudit.find({ messageId: 'msg-audit-1' });
      expect(auditEntries.length).toBe(1);
      expect(auditEntries[0].action).toBe('CREATE');
      expect(auditEntries[0].messageId).toBe('msg-audit-1');
    });
  });
});

