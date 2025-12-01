import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  userAgent: {
    type: String,
    default: ''
  },
  ip: {
    type: String,
    default: ''
  }
}, {
  _id: false
});

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address']
  },
  passwordHash: {
    type: String,
    required: true,
    select: false // Don't include in queries by default
  },
  lastLoginAt: {
    type: Date,
    default: null
  },
  refreshTokens: {
    type: [refreshTokenSchema],
    default: [],
    select: false // Don't include in queries by default
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Index for refresh token lookups (email index is automatically created by unique: true)
userSchema.index({ 'refreshTokens.token': 1 });

export const User =
  mongoose.models.User || mongoose.model('User', userSchema);

