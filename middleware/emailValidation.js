const disposableDomains = require('disposable-email-domains');

const TRUSTED = new Set([
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 
  'icloud.com', 'protonmail.com', 'aol.com'
]);

function emailValidationMiddleware(req, res, next) {
  const email = String(req.body?.email || '').trim().toLowerCase();
  
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  const domain = email.split('@')[1];

  if (disposableDomains.includes(domain)) {
    return res.status(400).json({ 
      error: 'Disposable emails blocked. Use Gmail, Yahoo, or Outlook.' 
    });
  }

  if (!TRUSTED.has(domain)) {
    return res.status(400).json({ 
      error: 'Please use a major email provider' 
    });
  }

  next();
}

module.exports = { emailValidationMiddleware };