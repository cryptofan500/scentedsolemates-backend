// C:\ScentedSoleMates_SUPREME4\backend\server.js
// COMPLETE VERSION with all fixes

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Supabase with service key (server-side only)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Configure multer for photo uploads
const upload = multer({ 
  memory: true,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Auth middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// 1. Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { email, username, password, age, city } = req.body;
    
    // Validate required fields
    if (!email || !username || !password || !age || !city) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (parseInt(age) < 18) {
      return res.status(400).json({ error: 'Must be 18 or older' });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    
    const { data, error } = await supabase
      .from('users')
      .insert({ 
        email: email.toLowerCase().trim(),
        username: username.trim(),
        password_hash,
        age: parseInt(age),
        city: city.toLowerCase().trim()
      })
      .select()
      .single();
      
    if (error) {
      if (error.message.includes('duplicate')) {
        return res.status(400).json({ error: 'Email or username already exists' });
      }
      return res.status(400).json({ error: error.message });
    }
    
    const token = jwt.sign({ userId: data.id }, process.env.JWT_SECRET);
    delete data.password_hash;
    res.json({ token, user: data });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase().trim())
      .single();
      
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
    delete user.password_hash;
    res.json({ token, user });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 3. Get own profile
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*, photos(*)')
      .eq('id', req.userId)
      .single();

    if (error) {
      console.error("Error fetching profile:", error);
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove sensitive data
    delete data.password_hash;
    res.json(data);
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// 4. NEW - Check if user can swipe (has photos)
app.get('/api/can-swipe', authenticate, async (req, res) => {
  try {
    const { data: photos } = await supabase
      .from('photos')
      .select('id')
      .eq('user_id', req.userId);
    
    const canSwipe = photos && photos.length > 0;
    res.json({ 
      canSwipe, 
      photoCount: photos?.length || 0,
      message: canSwipe ? 'Ready to swipe' : 'You must upload at least one photo to see other profiles'
    });
  } catch (err) {
    console.error('Can swipe check error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 5. Get profiles to swipe - WITH ALL FIXES
app.get('/api/profiles', authenticate, async (req, res) => {
  try {
    // First check if user has photos
    const { data: userPhotos } = await supabase
      .from('photos')
      .select('id')
      .eq('user_id', req.userId);
      
    if (!userPhotos || userPhotos.length === 0) {
      return res.status(403).json({ 
        error: 'You must upload a photo before viewing profiles',
        requiresPhoto: true 
      });
    }
    
    // Get current user's city
    const { data: currentUser, error: userError } = await supabase
      .from('users')
      .select('city')
      .eq('id', req.userId)
      .single();
      
    if (userError) {
      return res.status(400).json({ error: 'User not found' });
    }
      
    // Get already swiped users
    const { data: swipes } = await supabase
      .from('swipes')
      .select('swiped_id')
      .eq('swiper_id', req.userId);
      
    const swipedIds = swipes?.map(s => s.swiped_id) || [];
    swipedIds.push(req.userId); // exclude self
    
    // Build query for profiles in same city
    let query = supabase
      .from('users')
      .select('id, username, age, city, bio, photos(*)')
      .eq('city', currentUser.city.toLowerCase())
      .limit(20)
      .order('created_at', { ascending: false });
      
    // Properly format the NOT IN filter with quoted UUIDs
    if (swipedIds.length > 0) {
      const quotedIds = swipedIds.map(id => `"${id}"`).join(',');
      query = query.not('id', 'in', `(${quotedIds})`);
    }
    
    const { data, error } = await query;
    
    if (error) {
      console.error('Profiles fetch error:', error);
      return res.status(500).json({ error: 'Failed to fetch profiles' });
    }
    
    // FILTER OUT USERS WITHOUT PHOTOS
    const validProfiles = (data || []).filter(profile => 
      profile.photos && profile.photos.length > 0
    );
    
    res.json(validProfiles);
  } catch (err) {
    console.error('Profiles error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 6. Swipe endpoint - WITH ALL FIXES
app.post('/api/swipe', authenticate, async (req, res) => {
  try {
    const { targetId, direction } = req.body;
    
    if (!targetId || !direction) {
      return res.status(400).json({ error: 'Target and direction required' });
    }
    
    // PREVENT SELF-SWIPING
    if (targetId === req.userId) {
      return res.status(400).json({ error: 'Cannot swipe on yourself' });
    }
    
    // Validate direction
    if (!['like', 'pass'].includes(direction)) {
      return res.status(400).json({ error: 'Invalid swipe direction' });
    }
    
    // Record the swipe
    const { error: swipeError } = await supabase
      .from('swipes')
      .insert({ 
        swiper_id: req.userId, 
        swiped_id: targetId, 
        direction 
      });
      
    if (swipeError) {
      console.error('Swipe error:', swipeError);
      return res.status(400).json({ error: 'Already swiped this user' });
    }
      
    // Check for match if liked
    if (direction === 'like') {
      const { data: reciprocal } = await supabase
        .from('swipes')
        .select('*')
        .eq('swiper_id', targetId)
        .eq('swiped_id', req.userId)
        .eq('direction', 'like')
        .single();
        
      if (reciprocal) {
        // Check if match already exists to avoid duplicate
        const { data: existingMatch } = await supabase
          .from('matches')
          .select('id')
          .or(`and(user1_id.eq.${req.userId},user2_id.eq.${targetId}),and(user1_id.eq.${targetId},user2_id.eq.${req.userId})`)
          .single();
        
        if (!existingMatch) {
          // Create match
          const { error: matchError } = await supabase
            .from('matches')
            .insert({ 
              user1_id: req.userId,
              user2_id: targetId
            });
            
          if (matchError) {
            console.error('Match creation error:', matchError);
            // Don't fail the whole request if match creation fails
          }
        }
        
        return res.json({ match: true });
      }
    }
    
    res.json({ match: false });
  } catch (err) {
    console.error('Swipe error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 7. Get matches endpoint
app.get('/api/matches', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('matches')
      .select(`
        id,
        created_at,
        user1:user1_id(id, username, email, contact_method, contact_info, photos(*)),
        user2:user2_id(id, username, email, contact_method, contact_info, photos(*))
      `)
      .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`)
      .order('created_at', { ascending: false });
      
    if (error) {
      console.error('Matches fetch error:', error);
      return res.status(500).json({ error: 'Failed to fetch matches' });
    }
      
    const matches = data?.map(m => {
      const partner = m.user1.id === req.userId ? m.user2 : m.user1;
      return {
        id: m.id,
        created_at: m.created_at,
        partner: {
          username: partner.username,
          photo: partner.photos?.[0]?.url,
          contact: partner.contact_method === 'phone' && partner.contact_info
            ? partner.contact_info 
            : partner.email
        }
      };
    }) || [];
    
    res.json(matches);
  } catch (err) {
    console.error('Matches error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 8. Upload photo endpoint
app.post('/api/upload', authenticate, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }
    
    // Check existing photo count
    const { data: existingPhotos } = await supabase
      .from('photos')
      .select('id')
      .eq('user_id', req.userId);
      
    if (existingPhotos && existingPhotos.length >= 3) {
      return res.status(400).json({ error: 'Maximum 3 photos allowed' });
    }
    
    const fileName = `${req.userId}/${Date.now()}.jpg`;
    
    // Upload to Supabase Storage
    const { error: uploadError } = await supabase.storage
      .from('photos')
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype || 'image/jpeg',
        upsert: false
      });
      
    if (uploadError) {
      console.error('Storage upload error:', uploadError);
      return res.status(400).json({ error: 'Failed to upload photo' });
    }
    
    // Get public URL
    const { data: { publicUrl } } = supabase.storage
      .from('photos')
      .getPublicUrl(fileName);
      
    // Save to database
    const { error: dbError } = await supabase
      .from('photos')
      .insert({ 
        user_id: req.userId, 
        url: publicUrl,
        display_order: existingPhotos?.length + 1 || 1
      });
      
    if (dbError) {
      console.error('Database photo error:', dbError);
      return res.status(400).json({ error: 'Failed to save photo' });
    }
      
    res.json({ url: publicUrl });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 9. Update profile endpoint
app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const { bio, contact_method, contact_info } = req.body;
    
    const updates = {};
    if (bio !== undefined) updates.bio = bio.substring(0, 500);
    if (contact_method) updates.contact_method = contact_method;
    if (contact_info !== undefined) updates.contact_info = contact_info;
    
    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', req.userId)
      .select()
      .single();
      
    if (error) {
      console.error('Profile update error:', error);
      return res.status(400).json({ error: 'Failed to update profile' });
    }
    
    delete data.password_hash;
    res.json(data);
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ ScentedSoleMates Backend running on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
});