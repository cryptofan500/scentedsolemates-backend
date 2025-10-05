// COMPLETE VERSION - GTA cluster + 6 photos + EXIF preservation
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const crypto = require('crypto');

const { swipeLimiter, messageLimiter, signupLimiter, uploadLimiter, defaultLimiter } = require('./middleware/rateLimiter');
const { validatePhotoUniqueness, validatePhotoType } = require('./middleware/photoValidator');
const { getTodayChallenge, checkChallengeCompletion, completeChallenge, getUserChallengeStats } = require('./utils/challenges');
const legalRoutes = require('./routes/legal');

// GTA CLUSTER NORMALIZATION - Maps all GTA cities to 'toronto' for matching
const GTA_CITIES = {
  'toronto': 'toronto', 'tdot': 'toronto', 't.o.': 'toronto', 'the 6': 'toronto', 'the 6ix': 'toronto', 'yyz': 'toronto',
  'mississauga': 'toronto', 'sauga': 'toronto', 'missisauga': 'toronto', 'mississauaga': 'toronto',
  'brampton': 'toronto', 'bramption': 'toronto',
  'vaughan': 'toronto', 'vaughn': 'toronto',
  'markham': 'toronto',
  'richmond hill': 'toronto', 'richmondhill': 'toronto',
  'scarborough': 'toronto', 'scarbrough': 'toronto', 'scarboro': 'toronto',
  'etobicoke': 'toronto', 'etobico': 'toronto',
  'north york': 'toronto', 'northyork': 'toronto',
  'oakville': 'toronto',
  'ajax': 'toronto',
  'pickering': 'toronto',
  'burlington': 'toronto'
};

function normalizeCity(city) {
  if (!city) return null;
  const cleaned = city.toLowerCase().trim().replace(/[^a-z\s]/g, '').replace(/\s+/g, ' ');
  return GTA_CITIES[cleaned] || null;
}

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(defaultLimiter);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.use((req, res, next) => {
  req.supabase = supabase;
  next();
});

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

app.use('/api/legal', legalRoutes);

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    features: {
      gta_cluster: true,
      photo_limit: 6,
      exif_preservation: true,
      compression: 'client_side',
      security: true,
      legal_pages: true
    }
  });
});

// 1. REGISTER - GTA ENFORCEMENT
app.post('/api/register', signupLimiter, async (req, res) => {
  try {
    console.log('[REGISTER] Raw request:', JSON.stringify(req.body));
    
    let { email, username, password, age, city, gender, interested_in } = req.body;
    
    // Defensive normalization
    if (typeof interested_in === 'string') interested_in = [interested_in];
    if (!Array.isArray(interested_in)) interested_in = [];
    
    const canonicalValues = interested_in
      .map(v => String(v).toLowerCase().trim())
      .map(v => {
        if (v === 'men') return 'male';
        if (v === 'women') return 'female';
        return v;
      })
      .filter(v => ['male', 'female', 'non-binary'].includes(v));
    
    const uniqueCanonical = [...new Set(canonicalValues)];
    
    console.log('[REGISTER] Normalized interested_in:', uniqueCanonical);
    
    if (!email || !username || !password || !age || !city || !gender) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (uniqueCanonical.length === 0) {
      return res.status(400).json({ error: 'Must select at least one preference' });
    }

    if (parseInt(age) < 18) {
      return res.status(400).json({ error: 'Must be 18 or older' });
    }
    
    if (!['male', 'female', 'non-binary'].includes(gender)) {
      return res.status(400).json({ error: 'Invalid gender selection' });
    }

    // GTA ENFORCEMENT
    const normalizedCity = normalizeCity(city);
    if (!normalizedCity) {
      return res.status(400).json({ 
        error: `We're launching exclusively in the GTA. "${city}" is not in our current service area.`,
        gtaOnly: true 
      });
    }
    
    // Password validation
    if (password.length < 10) {
      return res.status(400).json({ error: 'Password must be at least 10 characters' });
    }
    if (!/[A-Z]/.test(password)) {
      return res.status(400).json({ error: 'Password must contain at least 1 uppercase letter' });
    }
    if (!/[a-z]/.test(password)) {
      return res.status(400).json({ error: 'Password must contain at least 1 lowercase letter' });
    }
    if (!/[0-9]/.test(password)) {
      return res.status(400).json({ error: 'Password must contain at least 1 number' });
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      return res.status(400).json({ error: 'Password must contain at least 1 special character' });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    
    const { data, error } = await supabase
      .from('users')
      .insert({ 
        email: email.toLowerCase().trim(),
        username: username.trim(),
        password_hash,
        age: parseInt(age),
        city: normalizedCity, // STORES AS 'toronto' for GTA cluster
        gender,
        interested_in: uniqueCanonical,
        email_verified: true,
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
    
    console.log('[REGISTER] Success - GTA user created:', data.id, 'City:', normalizedCity);
    res.json({ token, user: data, message: 'Account created successfully!' });
  } catch (err) {
    console.error('[REGISTER] Server error:', err);
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

// 4. Check if user can swipe
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

// 5. Get profiles - GTA CLUSTER MATCHING
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
    
    // GTA CLUSTER: All 'toronto' users match together
    let { data: profiles, error } = await supabase
      .from('users')
      .select('id, username, age, city, bio, gender, interested_in, mode, photos(*)')
      .eq('city', 'toronto') // CHANGED: GTA cluster (was .ilike('city', currentUser.city))
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

// 6. Swipe endpoint
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

// 7. Get matches
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

// 8. Unmatch
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

// 9. Send message
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

// 10. Get messages
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

// 11. UPLOAD PHOTO - 6 PHOTO LIMIT + EXIF PRESERVATION
app.post('/api/upload', authenticate, uploadLimiter, upload.single('photo'), validatePhotoUniqueness, validatePhotoType, async (req, res) => {
  try {
    console.log('[UPLOAD] Request received. File present:', !!req.file);
    
    if (!req.file) {
      console.error('[UPLOAD] ERROR: No file in req.file');
      return res.status(400).json({ error: 'No file provided' });
    }

    console.log('[UPLOAD] File details:', {
      originalname: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      return res.status(400).json({ error: 'Invalid image type. Only JPEG, PNG, and WebP are allowed.' });
    }
    
    const { data: existingPhotos } = await supabase
      .from('photos')
      .select('id')
      .eq('user_id', req.userId);
      
    // CHANGED: 6 photo limit (was 3)
    if (existingPhotos && existingPhotos.length >= 6) {
      return res.status(400).json({ error: 'Maximum 6 photos allowed' });
    }
    
    const randomSuffix = Math.random().toString(36).substring(2, 9);
    let extension = '.jpg';
    if (req.file.mimetype === 'image/png') extension = '.png';
    else if (req.file.mimetype === 'image/webp') extension = '.webp';
    
    const fileName = `${req.userId}/${Date.now()}-${randomSuffix}${extension}`;
    
    console.log('[UPLOAD] Uploading to Supabase Storage:', fileName);
    
    const { error: uploadError } = await supabase.storage
      .from('photos')
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });
      
    if (uploadError) {
      console.error('[UPLOAD] Storage upload error:', uploadError);
      return res.status(400).json({ error: 'Failed to upload photo' });
    }
    
    console.log('[UPLOAD] Storage upload successful. Getting public URL...');
    
    const { data: { publicUrl } } = supabase.storage
      .from('photos')
      .getPublicUrl(fileName);
      
    // NOTE: EXIF data is preserved in the file stored in Supabase Storage
    // Client compresses but preserves EXIF via browser-image-compression library
    // Future: Add exif_data column to extract and store for fake detection
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
      console.error('[UPLOAD] Database photo error:', dbError);
      return res.status(400).json({ error: 'Failed to save photo' });
    }
    
    console.log('[UPLOAD] Success! URL:', publicUrl);
    res.json({ url: publicUrl, type: req.body?.photo_type });
  } catch (err) {
    console.error('[UPLOAD] Critical error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 12. Update profile
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

// 13. Block user
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

// 14. Report user
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

// 15. Update user mode
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

// 16. Get today's challenge
app.get('/api/challenge/today', authenticate, async (req, res) => {
  try {
    const challenge = getTodayChallenge();
    const completed = await checkChallengeCompletion(req.userId, challenge.id, supabase);
    res.json({ ...challenge, completed });
  } catch (err) {
    console.error('Challenge fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 17. Get challenge stats
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

// 18. Complete challenge
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

// ERROR HANDLING MIDDLEWARE
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        error: 'Photo must be under 5MB. Please compress or use a smaller image.' 
      });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  
  if (err.message && err.message.includes('File')) {
    return res.status(400).json({ error: err.message });
  }
  
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ ScentedSoleMates Backend running on port ${PORT}`);
  console.log(`🌍 GTA Metro Cluster: ACTIVE (all cities → toronto)`);
  console.log(`📸 Photo limit: 6 (upgraded from 3)`);
  console.log(`📊 EXIF: Preserved for fake detection`);
  console.log(`🔐 Auth: Bcrypt (working perfectly)`);
  console.log(`🚀 Health: http://localhost:${PORT}/health`);
});