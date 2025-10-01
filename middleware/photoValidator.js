const crypto = require('crypto');

const validatePhotoUniqueness = async (req, res, next) => {
  try {
    // Skip if no file uploaded
    if (!req.file) {
      return next();
    }

    // FIX: Use SHA-256 instead of MD5 for better collision resistance
    const photoHash = crypto
      .createHash('sha256')
      .update(req.file.buffer)
      .digest('hex');

    // Store hash in request for later use
    req.photoHash = photoHash;

    // FIX: Get Supabase client from request (injected by server.js)
    // Never create a fallback client - this prevents service key leaks
    const supabase = req.supabase;

    if (!supabase) {
      console.error('CRITICAL: Supabase client not injected into request');
      return res.status(500).json({ error: 'Internal server configuration error' });
    }

    // FIX: Use maybeSingle() instead of single() to handle no results gracefully
    const { data: existingPhoto, error } = await supabase
      .from('photos')
      .select('id, user_id')
      .eq('photo_hash', photoHash)
      .maybeSingle();

    if (error && error.code !== 'PGRST116') { // PGRST116 is "no rows found" which is fine
      console.error('Database error during photo validation:', error);
      // FIX: Fail closed on database errors - don't allow uploads during outages
      return res.status(503).json({ 
        error: 'Photo validation service temporarily unavailable. Please try again.' 
      });
    }

    if (existingPhoto) {
      // Photo already exists - likely a fake profile reusing images
      console.warn(`Duplicate photo detected. Hash: ${photoHash}, Existing user: ${existingPhoto.user_id}, Attempting user: ${req.userId}`);
      
      // Check if it's the same user re-uploading their own photo
      if (existingPhoto.user_id === req.userId) {
        return res.status(400).json({ 
          error: 'You have already uploaded this exact photo. Please use a different photo.' 
        });
      } else {
        // Different user trying to use same photo - major red flag
        // Log this for potential automated suspension
        console.error(`SECURITY: User ${req.userId} attempted to upload photo already owned by user ${existingPhoto.user_id}`);
        
        return res.status(409).json({ 
          error: 'This photo has already been uploaded by another user. Please use original content only.' 
        });
      }
    }

    // Photo is unique, proceed
    next();
  } catch (err) {
    console.error('Critical photo validation error:', err);
    // FIX: Fail closed - if validation breaks, don't allow upload
    // This prevents abuse during system failures
    return res.status(503).json({ 
      error: 'Photo validation service temporarily unavailable. Please try again later.' 
    });
  }
};

// Helper function to validate photo type
const validatePhotoType = (req, res, next) => {
  const validTypes = ['profile', 'verification', 'face', 'feet', 'socks', 'shoes', 'pedicure'];
  
  // Photo type is optional, but if provided must be valid
  if (req.body && req.body.photo_type) {
    if (!validTypes.includes(req.body.photo_type)) {
      return res.status(400).json({ 
        error: `Invalid photo type. Must be one of: ${validTypes.join(', ')}` 
      });
    }
  }
  
  // If no photo_type provided, it will default to 'profile' in server.js
  next();
};

module.exports = { 
  validatePhotoUniqueness,
  validatePhotoType 
};