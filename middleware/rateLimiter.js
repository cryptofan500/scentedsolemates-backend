const rateLimit = require('express-rate-limit');

// Global baseline for all endpoints
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP per 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again in 15 minutes.' }
});

// Strict limiter for auth endpoints (login/signup)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 attempts per 15 min
  skipSuccessfulRequests: true,
  message: { error: 'Too many authentication attempts. Please try again in 15 minutes.' }
});

// Swipe rate limiting (prevent spam swiping)
const swipeLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 swipes per minute
  message: { error: 'Slow down! You can swipe 30 times per minute max.' }
});

// Message rate limiting (prevent spam messages)
const messageLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 messages per minute
  message: { error: 'Slow down! You can send 10 messages per minute max.' }
});

// Upload rate limiting (prevent photo spam)
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 uploads per hour
  message: { error: 'Upload limit reached. You can upload 20 photos per hour.' }
});

// DEPRECATED: Use authLimiter instead
const signupLimiter = authLimiter;

// DEPRECATED: Use globalLimiter instead
const defaultLimiter = globalLimiter;

module.exports = {
  globalLimiter,
  authLimiter,
  swipeLimiter,
  messageLimiter,
  uploadLimiter,
  signupLimiter, // Kept for backward compatibility
  defaultLimiter  // Kept for backward compatibility
};