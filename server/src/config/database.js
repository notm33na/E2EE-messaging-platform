import mongoose from 'mongoose';

/**
 * Connects to MongoDB Atlas
 * @param {string} mongoUri - MongoDB connection string
 */
export async function connectDatabase(mongoUri) {
  try {
    // Ensure database name is included in connection string
    let connectionUri = mongoUri;
    if (!connectionUri.includes('/infosec') && !connectionUri.includes('?') && !connectionUri.includes('#')) {
      // Add database name if not present
      connectionUri = connectionUri.replace(/\/$/, '') + '/infosec';
    }
    
    await mongoose.connect(connectionUri, {
      // Modern MongoDB driver options
      serverSelectionTimeoutMS: 5000,
      dbName: 'infosec', // Explicitly set database name
      // Enhanced security options
      tls: true, // Force TLS/SSL connection
      tlsAllowInvalidCertificates: false, // Require valid certificates
      retryWrites: true, // Enable retryable writes
      retryReads: true, // Enable retryable reads
      // Connection pool settings for DoS protection
      maxPoolSize: 10, // Maximum connections in pool
      minPoolSize: 2, // Minimum connections in pool
      maxIdleTimeMS: 30000, // Close idle connections after 30s
      // Additional security: connection timeout and monitoring
      connectTimeoutMS: 10000, // Connection timeout
      socketTimeoutMS: 45000, // Socket timeout
      // Authentication and encryption
      authSource: 'admin', // Use admin database for authentication
      compressors: ['zlib'], // Enable compression
    });
    
    console.log('✓ Connected to MongoDB Atlas');
    console.log(`✓ Using database: ${mongoose.connection.db.databaseName}`);
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.warn('MongoDB disconnected');
    });
    
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error.message);
    throw error;
  }
}

/**
 * Gracefully closes MongoDB connection
 */
export async function closeDatabase() {
  try {
    await mongoose.connection.close();
    console.log('✓ MongoDB connection closed');
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
  }
}

