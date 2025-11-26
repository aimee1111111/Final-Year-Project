const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../databaseConnection');
const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'All fields required.' });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const usernameNorm = String(username).trim();

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [usernameNorm, emailNorm, hashedPassword]
    );

    const newUser = result.rows[0];

    return res.status(201).json({ 
      success: true, 
      user_id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      redirectUrl: '/Home.html' 
    });
  } catch (err) {
    console.error('[SIGNUP] error:', err);
    return res.status(500).json({ success: false, error: 'Error signing up. Please try again.' });
  }
});


router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'All fields required.' });
  }

  try {
    const emailNorm = String(email).trim().toLowerCase();
    const r = await pool.query(
      'SELECT id, email, username, password FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [emailNorm]
    );

    if (r.rows.length === 0) {
      console.warn('[LOGIN] user not found:', emailNorm);
      return res.status(400).json({ success: false, error: 'Invalid email or password.' });
    }

    const user = r.rows[0];
    const hashPrefix = String(user.password).slice(0, 4);
    console.log('[LOGIN] found user:', user.email, 'hashPrefix:', hashPrefix, 'hashLen:', String(user.password).length);

    const ok = await bcrypt.compare(password, user.password);
    console.log('[LOGIN] bcrypt.compare ->', ok);

    if (!ok) {
      return res.status(400).json({ success: false, error: 'Invalid email or password.' });
    }
    
    return res.status(200).json({ 
      success: true, 
      user_id: user.id,
      username: user.username,
      email: user.email,
      redirectUrl: '/Home.html' 
    });
  } catch (e) {
    console.error('[LOGIN] error:', e);
    return res.status(500).json({ success: false, error: 'Error logging in.' });
  }
});

module.exports = router;