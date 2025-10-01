const rateLimit = require('express-rate-limit');

// Different limiters for different endpoints
const swipeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // 100 swipes per hour
  message: 'Too many swipes, slow down there tiger. Try again in an hour.',
  standardHeaders: true,
  legacyHeaders: false,
});

const messageLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour  
  max: 50, // 50 messages per hour
  message: 'Too many messages. Take a break and touch grass.',
  standardHeaders: true,
  legacyHeaders: false,
});

const signupLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 3, // 3 signups per IP per day
  message: 'Too many registration attempts from this IP. Try again tomorrow.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => req.ip, // Use IP instead of user for signup
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 uploads per hour
  message: 'Too many photo uploads. Your feet need a break.',
  standardHeaders: true,
  legacyHeaders: false,
});

const defaultLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes
  message: 'Too many requests. Please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = {
  swipeLimiter,
  messageLimiter,
  signupLimiter,
  uploadLimiter,
  defaultLimiter
};