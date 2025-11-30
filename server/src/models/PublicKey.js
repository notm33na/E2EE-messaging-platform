import mongoose from 'mongoose';

const publicKeySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  publicIdentityKeyJWK: {
    type: Object,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for faster lookups
publicKeySchema.index({ userId: 1 });

export const PublicKey = mongoose.model('PublicKey', publicKeySchema);

