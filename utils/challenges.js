// IMPORTANT: This file is kept for API compatibility but all gamification
// features are disabled in the UI for MVP. Do not spend time fixing bugs here.

// Daily challenge rotation system
const dailyChallenges = [
  {
    id: 'upload_socks',
    title: 'Sock It To Me',
    description: 'Upload a photo wearing your favorite socks',
    type: 'upload',
    requirement: 'photo_type:socks',
    reward: 'Unlock Apocalypse mode for 24 hours'
  },
  {
    id: 'fresh_feet',
    title: 'Fresh Feet Friday',
    description: 'Upload a new barefoot photo',
    type: 'upload', 
    requirement: 'photo_type:feet',
    reward: '5 bonus swipes'
  },
  {
    id: 'rate_feet',
    title: 'Sole Searcher',
    description: 'Swipe on at least 10 profiles today',
    type: 'engagement',
    requirement: 'swipes:10',
    reward: 'See who liked you'
  },
  {
    id: 'send_compliment',
    title: 'Toe-tal Charmer',
    description: 'Send a foot-related compliment to a match',
    type: 'message',
    requirement: 'message_sent:1',
    reward: 'Priority in match queue'
  },
  {
    id: 'complete_profile',
    title: 'Sole Identity',
    description: 'Add a bio mentioning your foot preferences',
    type: 'profile',
    requirement: 'bio_contains:feet',
    reward: 'Verified badge for 7 days'
  }
];

// Get today's challenge based on date rotation
function getTodayChallenge() {
  const today = new Date();
  const dayOfYear = Math.floor((today - new Date(today.getFullYear(), 0, 0)) / 86400000);
  const challengeIndex = dayOfYear % dailyChallenges.length;
  return dailyChallenges[challengeIndex];
}

// Check if user completed today's challenge
async function checkChallengeCompletion(userId, challengeId, supabase) {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    // FIX: Use maybeSingle instead of single
    const { data, error } = await supabase
      .from('challenge_completions')
      .select('id')
      .eq('user_id', userId)
      .eq('challenge_type', challengeId)
      .gte('completed_at', today)
      .maybeSingle();
      
    return !!data;
  } catch (err) {
    return false;
  }
}

// Mark challenge as complete
async function completeChallenge(userId, challengeId, supabase) {
  try {
    // Record completion
    const { error: completionError } = await supabase
      .from('challenge_completions')
      .insert({
        user_id: userId,
        challenge_type: challengeId
      });
      
    // FIX: Handle unique constraint violation properly
    if (completionError) {
      if (completionError.code === '23505') { // PostgreSQL unique violation
        // Already completed today, that's fine
        return true;
      }
      throw completionError;
    }
    
    // Update user's challenge count
    // FIX: Use maybeSingle for user fetch
    const { data: user } = await supabase
      .from('users')
      .select('challenges_completed')
      .eq('id', userId)
      .maybeSingle();
      
    await supabase
      .from('users')
      .update({ 
        challenges_completed: (user?.challenges_completed || 0) + 1,
        last_challenge_date: new Date().toISOString().split('T')[0]
      })
      .eq('id', userId);
      
    return true;
  } catch (err) {
    console.error('Challenge completion error:', err);
    return false;
  }
}

// Get user's challenge stats
async function getUserChallengeStats(userId, supabase) {
  try {
    // FIX: Get total completions with proper count syntax
    const { count: totalCount } = await supabase
      .from('challenge_completions')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', userId);
      
    // Get this week's completions
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    // FIX: Get weekly count with proper syntax
    const { count: weeklyCount } = await supabase
      .from('challenge_completions')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', userId)
      .gte('completed_at', weekAgo.toISOString());
      
    // Check if completed today's challenge
    const todayChallenge = getTodayChallenge();
    const completedToday = await checkChallengeCompletion(userId, todayChallenge.id, supabase);
    
    return {
      totalCompleted: totalCount || 0,
      weeklyCompleted: weeklyCount || 0,
      completedToday,
      todayChallenge,
      streakBonus: weeklyCount >= 3 // 3+ challenges in a week = bonus
    };
  } catch (err) {
    console.error('Stats error:', err);
    return null;
  }
}

module.exports = {
  dailyChallenges,
  getTodayChallenge,
  checkChallengeCompletion,
  completeChallenge,
  getUserChallengeStats
};