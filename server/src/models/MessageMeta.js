import mongoose from 'mongoose';
import crypto from 'crypto';
import { MetadataAudit } from './MetadataAudit.js';

const messageMetaSchema = new mongoose.Schema({
  messageId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  sessionId: {
    type: String,
    required: true,
    index: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
    select: false // Don't select by default to minimize metadata exposure
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
    select: false // Don't select by default to minimize metadata exposure
  },
  type: {
    type: String,
    enum: ['MSG', 'FILE_META', 'FILE_CHUNK'],
    required: true
  },
  timestamp: {
    type: Number,
    required: true
  },
  seq: {
    type: Number,
    required: true
  },
  delivered: {
    type: Boolean,
    default: false
  },
  deliveredAt: {
    type: Date,
    default: null
  },
  meta: {
    filename: String,
    size: Number,
    totalChunks: Number,
    chunkIndex: Number,
    mimetype: String
  },
  metadataHash: {
    type: String,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for efficient queries
messageMetaSchema.index({ receiver: 1, delivered: 1 });
messageMetaSchema.index({ sessionId: 1, seq: 1 });
messageMetaSchema.index({ sender: 1, createdAt: -1 });

// Compound unique index to prevent replay attacks (same sessionId + seq + timestamp)
messageMetaSchema.index({ sessionId: 1, seq: 1, timestamp: 1 }, { unique: true });

/**
 * Application-level safeguard to enforce unique messageId and
 * (sessionId, seq, timestamp) triples even in environments where
 * MongoDB indexes may not yet be built.
 *
 * This ensures replay protection tests that expect duplicate
 * messageIds to be rejected behave deterministically.
 */
messageMetaSchema.pre('save', async function enforceReplayUniqueness(next) {
  try {
    // Enforce unique messageId
    if (this.isNew || this.isModified('messageId')) {
      const existingById = await this.constructor.findOne({ messageId: this.messageId });
      if (existingById && !existingById._id.equals(this._id)) {
        return next(new Error('Duplicate messageId detected'));
      }
    }

    // Enforce unique (sessionId, seq, timestamp) triple
    if (this.isNew || this.isModified('sessionId') || this.isModified('seq') || this.isModified('timestamp')) {
      const existingTriple = await this.constructor.findOne({
        sessionId: this.sessionId,
        seq: this.seq,
        timestamp: this.timestamp
      });

      if (existingTriple && !existingTriple._id.equals(this._id)) {
        return next(new Error('Duplicate message triple detected'));
      }
    }

    // Compute metadata integrity hash
    const metadataString = JSON.stringify({
      sessionId: this.sessionId,
      sender: this.sender,
      receiver: this.receiver,
      type: this.type,
      timestamp: this.timestamp,
      seq: this.seq,
      meta: this.meta
    }, Object.keys({
      sessionId: this.sessionId,
      sender: this.sender,
      receiver: this.receiver,
      type: this.type,
      timestamp: this.timestamp,
      seq: this.seq,
      meta: this.meta
    }).sort());
    
    this.metadataHash = crypto.createHash('sha256').update(metadataString).digest('hex');

    return next();
  } catch (err) {
    return next(err);
  }
});

// Audit trail: Log metadata changes
messageMetaSchema.post('save', async function(doc) {
  try {
    const action = this.isNew ? 'CREATE' : 'UPDATE';
    const oldValues = this.isNew ? null : this._originalValues || null;
    
    await MetadataAudit.create({
      messageId: doc.messageId,
      sessionId: doc.sessionId,
      action: action,
      changedBy: null, // System action
      oldValues: oldValues,
      newValues: doc.toObject(),
      timestamp: new Date()
    });
  } catch (error) {
    // Don't fail save if audit logging fails
    console.error('Failed to log metadata audit:', error);
  }
});

// Audit trail: Log metadata deletions
messageMetaSchema.post('findOneAndDelete', async function(doc) {
  try {
    if (doc) {
      await MetadataAudit.create({
        messageId: doc.messageId,
        sessionId: doc.sessionId,
        action: 'DELETE',
        changedBy: null,
        oldValues: doc.toObject(),
        newValues: null,
        timestamp: new Date()
      });
    }
  } catch (error) {
    console.error('Failed to log metadata deletion audit:', error);
  }
});

/**
 * Verifies metadata integrity hash on read
 * @param {Object} metadata - Message metadata document
 * @returns {boolean} True if hash is valid
 */
export function verifyMetadataHash(metadata) {
  if (!metadata || !metadata.metadataHash) {
    return false; // No hash to verify
  }

  const metadataString = JSON.stringify({
    sessionId: metadata.sessionId,
    sender: metadata.sender,
    receiver: metadata.receiver,
    type: metadata.type,
    timestamp: metadata.timestamp,
    seq: metadata.seq,
    meta: metadata.meta
  }, Object.keys({
    sessionId: metadata.sessionId,
    sender: metadata.sender,
    receiver: metadata.receiver,
    type: metadata.type,
    timestamp: metadata.timestamp,
    seq: metadata.seq,
    meta: metadata.meta
  }).sort());

  const expectedHash = crypto.createHash('sha256').update(metadataString).digest('hex');
  return metadata.metadataHash === expectedHash;
}

export const MessageMeta =
  mongoose.models.MessageMeta || mongoose.model('MessageMeta', messageMetaSchema);

