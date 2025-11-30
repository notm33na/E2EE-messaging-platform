import mongoose from 'mongoose';

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
    index: true
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
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

export const MessageMeta = mongoose.model('MessageMeta', messageMetaSchema);

