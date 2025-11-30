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

// Pre-save hook to ensure private key components are removed
publicKeySchema.pre('save', function(next) {
  if (this.publicIdentityKeyJWK && typeof this.publicIdentityKeyJWK === 'object') {
    // Remove any private key components
    const { d, ...publicKeyOnly } = this.publicIdentityKeyJWK;
    this.publicIdentityKeyJWK = publicKeyOnly;
  }
  next();
});

// Note: userId index is automatically created by unique: true

export const PublicKey = mongoose.model('PublicKey', publicKeySchema);

