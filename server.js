// COMPLETE VERSION with defensive /api/register endpoint

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const crypto = require('crypto');

// Import middleware
const { swipeLimiter, messageLimiter, signupLimiter, uploadLimiter, defaultLimiter } = require('./middleware/rateLimiter');
const { validatePhotoUniqueness, validatePhotoType } = require('./middleware/photoValidator');

// Import utilities (keeping for now but will be disabled in UI)
const { 
  getTodayChallenge, 
  checkChallengeCompletion, 
  completeChallenge, 
  getUserChallengeStats 
} = require('./utils/challenges');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(defaultLimiter);

// Initialize Supabase with service key (server-side only)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Configure multer properly with memory storage
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Middleware to attach supabase to request
app.use((req, res, next) => {
  req.supabase = supabase;
  next();
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
    environment: process.env.NODE_ENV || 'development',
    features: {
      security: true,
      gamification: true,
      messaging: true,
      modes: true
    }
  });
});

// 1. Register endpoint with DEFENSIVE NORMALIZATION
app.post('/api/register', signupLimiter, async (req, res) => {
  try {
    // Log exactly what arrived from client
    console.log('[REGISTER] Raw request body:', JSON.stringify(req.body));
    
    let { email, username, password, age, city, gender, interested_in } = req.body;
    
    // DEFENSIVE COERCION: Handle multiple possible client shapes
    // If client sent string instead of array, wrap it
    if (typeof interested_in === 'string') {
      interested_in = [interested_in];
    }
    // If undefined/null, initialize as empty array
    if (!Array.isArray(interested_in)) {
      interested_in = [];
    }
    
    // CANONICALIZATION: Map display labels to database values
    const canonicalValues = interested_in
      .map(v => String(v).toLowerCase().trim())
      .map(v => {
        if (v === 'men') return 'male';
        if (v === 'women') return 'female';
        return v;
      })
      .filter(v => ['male', 'female', 'non-binary'].includes(v));
    
    // Remove duplicates
    const uniqueCanonical = [...new Set(canonicalValues)];
    
    console.log('[REGISTER] Normalized interested_in:', uniqueCanonical);
    
    // VALIDATION: Ensure all required fields present
    if (!email || !username || !password || !age || !city || !gender) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // VALIDATION: interested_in must be non-empty array
    if (uniqueCanonical.length === 0) {
      return res.status(400).json({ 
        error: 'Must select at least one preference for interested_in' 
      });
    }

    if (parseInt(age) < 18) {
      return res.status(400).json({ error: 'Must be 18 or older' });
    }
    
    // Validate gender
    if (!['male', 'female', 'non-binary'].includes(gender)) {
      return res.status(400).json({ error: 'Invalid gender selection' });
    }

    // Validate city to prevent injection
    if (!/^[a-zA-Z\s\-]{2,50}$/i.test(city)) {
      return res.status(400).json({ error: 'Invalid city name' });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    
    // INSERT with guaranteed non-null array
    const { data, error } = await supabase
      .from('users')
      .insert({ 
        email: email.toLowerCase().trim(),
        username: username.trim(),
        password_hash,
        age: parseInt(age),
        city: city.toLowerCase().trim(),
        gender,
        interested_in: uniqueCanonical, // GUARANTEED to be non-empty array
        email_verified: false,
        mode: 'tease_toes'
      })
      .select()
      .single();
      
    if (error) {
      console.error('[REGISTER] Supabase error:', error);
      if (error.message.includes('duplicate')) {
        return res.status(400).json({ error: 'Email or username already exists' });
      }
      return res.status(400).json({ error: error.message });
    }
    
    const token = jwt.sign({ userId: data.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    delete data.password_hash;
    
    console.log('[REGISTER] Success - user created:', data.id);
    res.json({ token, user: data, message: 'Account created. Awaiting manual approval (usually < 2 hours).' });
  } catch (err) {
    console.error('[REGISTER] Server error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. Login endpoint with email verification check
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
    
    if (user.is_suspended) {
      return res.status(403).json({ error: 'Your account has been suspended due to multiple reports' });
    }
    
    if (!user.email_verified) {
      return res.status(403).json({ error: 'Account pending manual approval (usually < 2 hours)' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
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

    delete data.password_hash;
    res.json(data);
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// 4. Check if user can swipe (has photos)
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

// 5. Get profiles to swipe with blocking and mode filtering
app.get('/api/profiles', authenticate, async (req, res) => {
  try {
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
    
    const { data: currentUser, error: userError } = await supabase
      .from('users')
      .select('city, gender, interested_in, mode')
      .eq('id', req.userId)
      .single();
      
    if (userError) {
      return res.status(400).json({ error: 'User not found' });
    }
      
    const { data: swipes } = await supabase
      .from('swipes')
      .select('swiped_id')
      .eq('swiper_id', req.userId);
      
    const swipedIds = swipes?.map(s => s.swiped_id) || [];
    swipedIds.push(req.userId);
    
    const { data: blocks } = await supabase
      .from('blocks')
      .select('blocked_id, blocker_id')
      .or(`blocker_id.eq.${req.userId},blocked_id.eq.${req.userId}`);
      
    const blockedIds = blocks?.reduce((acc, block) => {
      if (block.blocker_id === req.userId) acc.push(block.blocked_id);
      if (block.blocked_id === req.userId) acc.push(block.blocker_id);
      return acc;
    }, []) || [];
    
    let { data: profiles, error } = await supabase
      .from('users')
      .select('id, username, age, city, bio, gender, interested_in, mode, photos(*)')
      .ilike('city', currentUser.city)
      .eq('is_suspended', false)
      .limit(50)
      .order('created_at', { ascending: false });
      
    if (error) {
      console.error('Profiles fetch error:', error);
      return res.status(500).json({ error: 'Failed to fetch profiles' });
    }
    
    const validProfiles = (profiles || []).filter(profile => {
      if (swipedIds.includes(profile.id)) return false;
      if (blockedIds.includes(profile.id)) return false;
      if (!profile.photos || profile.photos.length === 0) return false;
      
      const theyLikeMe = profile.interested_in && profile.interested_in.includes(currentUser.gender);
      const iLikeThem = currentUser.interested_in && currentUser.interested_in.includes(profile.gender);
      
      return theyLikeMe && iLikeThem;
    });
    
    res.json(validProfiles.slice(0, 20));
  } catch (err) {
    console.error('Profiles error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 6. Swipe endpoint with rate limiting and atomic upsert
app.post('/api/swipe', authenticate, swipeLimiter, async (req, res) => {
  try {
    const { targetId, direction } = req.body;
    
    if (!targetId || !direction) {
      return res.status(400).json({ error: 'Target and direction required' });
    }
    
    if (targetId === req.userId) {
      return res.status(400).json({ error: 'Cannot swipe on yourself' });
    }
    
    if (!['like', 'pass'].includes(direction)) {
      return res.status(400).json({ error: 'Invalid swipe direction' });
    }
    
    const { error: swipeError } = await supabase
      .from('swipes')
      .upsert({ 
        swiper_id: req.userId, 
        swiped_id: targetId, 
        direction 
      }, { 
        onConflict: 'swiper_id,swiped_id',
        ignoreDuplicates: false 
      });
      
    if (swipeError) {
      console.error('Swipe error:', swipeError);
      return res.status(500).json({ error: 'Failed to record swipe' });
    }
      
    if (direction === 'like') {
      const { data: reciprocal } = await supabase
        .from('swipes')
        .select('*')
        .eq('swiper_id', targetId)
        .eq('swiped_id', req.userId)
        .eq('direction', 'like')
        .maybeSingle();
        
      if (reciprocal) {
        const { data: existingMatch } = await supabase
          .from('matches')
          .select('id')
          .or(`user1_id.eq.${req.userId}.and.user2_id.eq.${targetId},user1_id.eq.${targetId}.and.user2_id.eq.${req.userId}`)
          .maybeSingle();
        
        if (!existingMatch) {
          const user1 = req.userId < targetId ? req.userId : targetId;
          const user2 = req.userId < targetId ? targetId : req.userId;
          
          const { error: matchError } = await supabase
            .from('matches')
            .insert({ 
              user1_id: user1,
              user2_id: user2
            });
            
          if (matchError) {
            console.error('Match creation error:', matchError);
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
          id: partner.id,
          username: partner.username,
          photo: partner.photos?.[0]?.url
        }
      };
    }) || [];
    
    res.json(matches);
  } catch (err) {
    console.error('Matches error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 8. Unmatch endpoint
app.delete('/api/matches/:matchId', authenticate, async (req, res) => {
  try {
    const { matchId } = req.params;
    
    const { data: match, error: fetchError } = await supabase
      .from('matches')
      .select('user1_id, user2_id')
      .eq('id', matchId)
      .maybeSingle();
      
    if (fetchError || !match) {
      return res.status(404).json({ error: 'Match not found' });
    }
    
    if (match.user1_id !== req.userId && match.user2_id !== req.userId) {
      return res.status(403).json({ error: 'Not your match' });
    }
    
    const { error: deleteError } = await supabase
      .from('matches')
      .delete()
      .eq('id', matchId);
      
    if (deleteError) {
      console.error('Unmatch error:', deleteError);
      return res.status(500).json({ error: 'Failed to unmatch' });
    }
    
    res.json({ success: true, message: 'Unmatched successfully' });
  } catch (err) {
    console.error('Unmatch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 9. Send message endpoint with rate limiting
app.post('/api/messages', authenticate, messageLimiter, async (req, res) => {
  try {
    const { matchId, content } = req.body;
    
    if (!matchId || !content) {
      return res.status(400).json({ error: 'Match ID and content required' });
    }
    
    if (content.length > 5000) {
      return res.status(400).json({ error: 'Message too long (max 5000 characters)' });
    }
    
    const { data: match, error: matchError } = await supabase
      .from('matches')
      .select('user1_id, user2_id')
      .eq('id', matchId)
      .maybeSingle();
      
    if (matchError || !match) {
      return res.status(404).json({ error: 'Match not found' });
    }
    
    if (match.user1_id !== req.userId && match.user2_id !== req.userId) {
      return res.status(403).json({ error: 'Not your match' });
    }
    
    const { data: message, error: messageError } = await supabase
      .from('messages')
      .insert({
        match_id: matchId,
        sender_id: req.userId,
        content: content.trim()
      })
      .select()
      .single();
      
    if (messageError) {
      console.error('Message send error:', messageError);
      return res.status(500).json({ error: 'Failed to send message' });
    }
    
    res.json(message);
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 10. Get messages for a match
app.get('/api/messages/:matchId', authenticate, async (req, res) => {
  try {
    const { matchId } = req.params;
    
    const { data: match, error: matchError } = await supabase
      .from('matches')
      .select('user1_id, user2_id')
      .eq('id', matchId)
      .maybeSingle();
      
    if (matchError || !match) {
      return res.status(404).json({ error: 'Match not found' });
    }
    
    if (match.user1_id !== req.userId && match.user2_id !== req.userId) {
      return res.status(403).json({ error: 'Not your match' });
    }
    
    const { data: messages, error: messagesError } = await supabase
      .from('messages')
      .select('*')
      .eq('match_id', matchId)
      .order('created_at', { ascending: true });
      
    if (messagesError) {
      console.error('Messages fetch error:', messagesError);
      return res.status(500).json({ error: 'Failed to fetch messages' });
    }
    
    const fetchTime = new Date().toISOString();
    await supabase
      .from('messages')
      .update({ is_read: true })
      .eq('match_id', matchId)
      .neq('sender_id', req.userId)
      .lte('created_at', fetchTime);
    
    res.json(messages || []);
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 11. Upload photo with deduplication and rate limiting
app.post('/api/upload', authenticate, uploadLimiter, upload.single('photo'), validatePhotoUniqueness, validatePhotoType, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      return res.status(400).json({ error: 'Invalid image type. Only JPEG, PNG, and WebP are allowed.' });
    }
    
    const { data: existingPhotos } = await supabase
      .from('photos')
      .select('id')
      .eq('user_id', req.userId);
      
    if (existingPhotos && existingPhotos.length >= 3) {
      return res.status(400).json({ error: 'Maximum 3 photos allowed' });
    }
    
    const randomSuffix = Math.random().toString(36).substring(2, 9);
    const fileName = `${req.userId}/${Date.now()}-${randomSuffix}.jpg`;
    
    const { error: uploadError } = await supabase.storage
      .from('photos')
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });
      
    if (uploadError) {
      console.error('Storage upload error:', uploadError);
      return res.status(400).json({ error: 'Failed to upload photo' });
    }
    
    const { data: { publicUrl } } = supabase.storage
      .from('photos')
      .getPublicUrl(fileName);
      
    const { error: dbError } = await supabase
      .from('photos')
      .insert({ 
        user_id: req.userId, 
        url: publicUrl,
        display_order: existingPhotos?.length + 1 || 1,
        photo_hash: req.photoHash,
        photo_type: req.body?.photo_type || 'profile'
      });
      
    if (dbError) {
      console.error('Database photo error:', dbError);
      return res.status(400).json({ error: 'Failed to save photo' });
    }
      
    res.json({ url: publicUrl, type: req.body?.photo_type });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 12. Update profile endpoint
app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const { bio, contact_method, contact_info, gender, interested_in } = req.body;
    
    const updates = {};
    if (bio !== undefined) updates.bio = bio.substring(0, 500);
    if (contact_method !== undefined) updates.contact_method = contact_method;
    if (contact_info !== undefined) updates.contact_info = contact_info || null;
    
    if (gender && ['male', 'female', 'non-binary'].includes(gender)) {
      updates.gender = gender;
    }
    
    if (interested_in && Array.isArray(interested_in) && interested_in.length > 0) {
      updates.interested_in = interested_in;
    }
    
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

// 13. Block user endpoint
app.post('/api/block', authenticate, async (req, res) => {
  try {
    const { targetId } = req.body;
    
    if (!targetId) {
      return res.status(400).json({ error: 'Target user required' });
    }
    
    if (targetId === req.userId) {
      return res.status(400).json({ error: 'Cannot block yourself' });
    }
    
    const { error } = await supabase
      .from('blocks')
      .insert({ 
        blocker_id: req.userId, 
        blocked_id: targetId 
      });
      
    if (error) {
      console.error('Block error:', error);
      return res.status(400).json({ error: 'Already blocked this user' });
    }
    
    res.json({ success: true, message: 'User blocked successfully' });
  } catch (err) {
    console.error('Block error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 14. Report user endpoint
app.post('/api/report', authenticate, async (req, res) => {
  try {
    const { targetId, reason, details } = req.body;
    
    if (!targetId || !reason) {
      return res.status(400).json({ error: 'Target and reason required' });
    }

    if (!['spam', 'fake', 'inappropriate', 'other'].includes(reason)) {
      return res.status(400).json({ error: 'Invalid report reason' });
    }
    
    const { error } = await supabase
      .from('reports')
      .insert({ 
        reporter_id: req.userId, 
        reported_id: targetId,
        reason,
        details: details || null
      });
      
    if (error) {
      console.error('Report error:', error);
      return res.status(400).json({ error: 'Failed to submit report' });
    }
    
    const { count, error: countError } = await supabase
      .from('reports')
      .select('*', { count: 'exact', head: true })
      .eq('reported_id', targetId);
      
    if (!countError && count >= 3) {
      await supabase
        .from('users')
        .update({ is_suspended: true })
        .eq('id', targetId);
    }
    
    res.json({ success: true, message: 'Report submitted' });
  } catch (err) {
    console.error('Report error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 15. Update user mode (keeping for compatibility but disabled in UI)
app.put('/api/mode', authenticate, async (req, res) => {
  try {
    const { mode } = req.body;
    
    if (!['tease_toes', 'apocalypse_ankles'].includes(mode)) {
      return res.status(400).json({ error: 'Invalid mode' });
    }
    
    const { data, error } = await supabase
      .from('users')
      .update({ mode })
      .eq('id', req.userId)
      .select()
      .single();
      
    if (error) {
      console.error('Mode update error:', error);
      return res.status(400).json({ error: 'Failed to update mode' });
    }
    
    res.json({ mode: data.mode, message: `Switched to ${mode.replace('_', ' ')} mode` });
  } catch (err) {
    console.error('Mode error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 16. Get today's challenge (keeping for compatibility but disabled in UI)
app.get('/api/challenge/today', authenticate, async (req, res) => {
  try {
    const challenge = getTodayChallenge();
    const completed = await checkChallengeCompletion(req.userId, challenge.id, supabase);
    
    res.json({
      ...challenge,
      completed
    });
  } catch (err) {
    console.error('Challenge fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 17. Get challenge stats (keeping for compatibility but disabled in UI)
app.get('/api/challenge/stats', authenticate, async (req, res) => {
  try {
    const stats = await getUserChallengeStats(req.userId, supabase);
    res.json(stats || {
      totalCompleted: 0,
      weeklyCompleted: 0,
      completedToday: false,
      todayChallenge: getTodayChallenge(),
      streakBonus: false
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 18. Complete challenge (keeping for compatibility but disabled in UI)
app.post('/api/challenge/complete', authenticate, async (req, res) => {
  try {
    const { challengeId } = req.body;
    
    if (!challengeId) {
      return res.status(400).json({ error: 'Challenge ID required' });
    }
    
    const todayChallenge = getTodayChallenge();
    if (challengeId !== todayChallenge.id) {
      return res.status(400).json({ error: 'Can only complete today\'s challenge' });
    }
    
    const alreadyComplete = await checkChallengeCompletion(req.userId, challengeId, supabase);
    if (alreadyComplete) {
      return res.status(400).json({ error: 'Challenge already completed today' });
    }
    
    const success = await completeChallenge(req.userId, challengeId, supabase);
    
    if (success) {
      res.json({ 
        success: true, 
        message: 'Challenge completed!',
        reward: todayChallenge.reward 
      });
    } else {
      res.status(500).json({ error: 'Failed to complete challenge' });
    }
  } catch (err) {
    console.error('Challenge completion error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ ScentedSoleMates Backend running on port ${PORT}`);
  console.log(`🔒 Security: Manual email verification, blocks, reports, rate limiting`);
  console.log(`🎮 Gamification: API endpoints active but disabled in UI`);
  console.log(`💬 Features: Gender filtering, unmatch, messaging`);
  console.log(`🚀 Health check: http://localhost:${PORT}/health`);
  console.log(`⚠️  IMPORTANT: Manually verify users in Supabase dashboard`);
});