import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import { createLogger, format, transports } from 'winston';

dotenv.config();

// Configure Winston logger
const logger = createLogger({
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' })
  ]
});

const app = express();
const PORT = process.env.PORT || 3001;

// Basic security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  methods: ['GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Request validation schema
const querySchema = z.object({
  type: z.enum(['ALL', 'CPI', 'CPA', 'PIN', 'VID']).optional().default('ALL')
});

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  logger.error('Error:', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  if (err instanceof z.ZodError) {
    return res.status(400).json({
      success: false,
      error: 'Invalid request parameters',
      details: err.errors
    });
  }

  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Main offers endpoint
app.get('/api/offers', async (req, res, next) => {
  try {
    const { type } = querySchema.parse(req.query);
    const API_KEY = process.env.OGADS_API_KEY;
    
    if (!API_KEY) {
      throw new Error('API key not configured');
    }

    const API_ENDPOINT = 'https://unlockcontent.net/api/v2';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const params = new URLSearchParams({
      ip: ip.toString(),
      user_agent: userAgent || '',
      ...(type !== 'ALL' && { ctype: type })
    });

    logger.info('Fetching offers', {
      type,
      ip: ip.toString().split(',')[0], // Log only first IP if forwarded
      timestamp: new Date().toISOString()
    });

    const response = await fetch(`${API_ENDPOINT}?${params}`, {
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`API responded with status: ${response.status}`);
    }

    const data = await response.json();

    // Cache headers
    res.set('Cache-Control', 'public, max-age=300'); // Cache for 5 minutes
    res.json(data);

  } catch (error) {
    next(error);
  }
});

// Apply error handling middleware
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
