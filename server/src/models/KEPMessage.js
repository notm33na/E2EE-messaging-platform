import mongoose from 'mongoose';

const kepMessageSchema = new mongoose.Schema({
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
  from: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: ['KEP_INIT', 'KEP_RESPONSE'],
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
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for efficient queries
kepMessageSchema.index({ to: 1, delivered: 1 });
kepMessageSchema.index({ sessionId: 1, seq: 1 });

/**
 * Application-level safeguard to enforce unique messageId even
 * if database indexes are not yet present. This is important
 * for tests that expect duplicate KEP messages to be rejected.
 */
kepMessageSchema.pre('save', async function enforceUniqueKepMessageId(next) {
  try {
    if (this.isNew || this.isModified('messageId')) {
      const existing = await this.constructor.findOne({ messageId: this.messageId });
      if (existing && !existing._id.equals(this._id)) {
        return next(new Error('Duplicate KEP messageId detected'));
      }
    }
    return next();
  } catch (err) {
    return next(err);
  }
});

export const KEPMessage =
  mongoose.models.KEPMessage || mongoose.model('KEPMessage', kepMessageSchema);

