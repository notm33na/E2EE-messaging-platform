import mongoose from 'mongoose';
import crypto from 'crypto';

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
    required: true,
    validate: {
      validator: function(jwk) {
        // Validate JWK structure
        if (!jwk || typeof jwk !== 'object') {
          return false;
        }
        
        // Must be EC key type
        if (jwk.kty !== 'EC') {
          return false;
        }
        
        // Must be P-256 curve
        if (jwk.crv !== 'P-256') {
          return false;
        }
        
        // Must have x and y coordinates
        if (!jwk.x || !jwk.y) {
          return false;
        }
        
        // Must NOT have private key component 'd'
        if (jwk.d !== undefined) {
          return false;
        }
        
        return true;
      },
      message: 'Invalid JWK structure. Must be EC P-256 public key without private key component.'
    }
  },
  keyHash: {
    type: String,
    required: false, // Will be set by pre-save hook, but allow for backward compatibility
    index: true
  },
  version: {
    type: Number,
    default: 1,
    index: true
  },
  previousVersions: [{
    keyHash: String,
    version: Number,
    replacedAt: Date
  }],
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

// Pre-save hook to ensure private key components are removed and compute integrity hash
publicKeySchema.pre('save', function(next) {
  if (this.publicIdentityKeyJWK && typeof this.publicIdentityKeyJWK === 'object') {
    // Remove any private key components
    const { d, ...publicKeyOnly } = this.publicIdentityKeyJWK;
    this.publicIdentityKeyJWK = publicKeyOnly;
    
    // Compute SHA-256 hash of public key for integrity verification
    const keyString = JSON.stringify(publicKeyOnly, Object.keys(publicKeyOnly).sort());
    const newKeyHash = crypto.createHash('sha256').update(keyString).digest('hex');
    
    // If key hash changed, increment version and archive previous version
    if (this.isModified('publicIdentityKeyJWK') && this.keyHash && this.keyHash !== newKeyHash) {
      if (!this.previousVersions) {
        this.previousVersions = [];
      }
      this.previousVersions.push({
        keyHash: this.keyHash,
        version: this.version || 1,
        replacedAt: new Date()
      });
      this.version = (this.version || 1) + 1;
    } else if (!this.keyHash) {
      // First time setting keyHash
      this.version = this.version || 1;
    }
    
    // Always set keyHash (required for integrity verification)
    this.keyHash = newKeyHash;
  } else if (!this.keyHash) {
    // If no JWK but keyHash missing, set a placeholder (shouldn't happen in normal flow)
    this.keyHash = '';
  }
  next();
});

// Note: userId index is automatically created by unique: true

export const PublicKey =
  mongoose.models.PublicKey || mongoose.model('PublicKey', publicKeySchema);

