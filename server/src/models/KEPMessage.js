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

export const KEPMessage = mongoose.model('KEPMessage', kepMessageSchema);

