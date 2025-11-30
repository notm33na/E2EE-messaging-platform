import express from 'express';

const router = express.Router();

/**
 * Health check endpoint
 * GET /api/health
 */
router.get('/', async (req, res) => {
  try {
    res.json({
      status: 'ok',
      message: 'Server is running',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

export default router;

