const express = require('express');
const router = express.Router();
const { supabase } = require('../config/supabase');

// Get legal document by type
router.get('/:type', async (req, res) => {
  try {
    const { type } = req.params;
    
    // Validate type
    const validTypes = ['privacy', 'terms', 'guidelines'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: 'Invalid document type' });
    }
    
    const { data, error } = await supabase
      .from('legal_documents')
      .select('content, last_updated')
      .eq('doc_type', type)
      .single();
    
    if (error) {
      console.error('Legal doc fetch error:', error);
      return res.status(404).json({ error: 'Document not found' });
    }
    
    res.json(data);
  } catch (err) {
    console.error('Legal route error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;