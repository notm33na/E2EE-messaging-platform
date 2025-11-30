import mongoose from 'mongoose';

/**
 * Connects to MongoDB Atlas
 * @param {string} mongoUri - MongoDB connection string
 */
export async function connectDatabase(mongoUri) {
  try {
    await mongoose.connect(mongoUri, {
      // Modern MongoDB driver options
      serverSelectionTimeoutMS: 5000,
    });
    
    console.log('✓ Connected to MongoDB Atlas');
    
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

