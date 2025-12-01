import mongoose from 'mongoose';

/**
 * Metadata Audit Trail
 * Tracks all changes to message metadata for non-repudiation and security
 */
const metadataAuditSchema = new mongoose.Schema({
  messageId: {
    type: String,
    required: true,
    index: true
  },
  sessionId: {
    type: String,
    required: true,
    index: true
  },
  action: {
    type: String,
    enum: ['CREATE', 'UPDATE', 'DELETE', 'READ'],
    required: true
  },
  changedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null // null for system actions
  },
  oldValues: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  newValues: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for efficient queries
metadataAuditSchema.index({ messageId: 1, timestamp: -1 });
metadataAuditSchema.index({ sessionId: 1, timestamp: -1 });
metadataAuditSchema.index({ changedBy: 1, timestamp: -1 });

// TTL index to auto-delete old audit logs after 1 year
metadataAuditSchema.index({ timestamp: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

export const MetadataAudit =
  mongoose.models.MetadataAudit || mongoose.model('MetadataAudit', metadataAuditSchema);

