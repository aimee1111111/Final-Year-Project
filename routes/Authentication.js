 /*
This file handles user sign-up and login for the application using Express.
It validates the user’s input, hashes passwords with bcrypt for security,
stores new users in the database, and checks login details against saved records.
If authentication is successful, it returns the user details and a redirect path.
*/

const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../databaseConnection');
const router = express.Router();

// Sign-up route
router.post('/signup', async (req, res) => {
  try {
    // Get values from request body
    const { username, email, password } = req.body || {};

    // Make sure all fields are filled in
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'All fields required.' });
    }

    // Clean up input values
    const emailNorm = String(email).trim().toLowerCase();
    const usernameNorm = String(username).trim();

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert new user into the database and return key user details
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [usernameNorm, emailNorm, hashedPassword]
    );

    // Get inserted user from returned rows
    const newUser = result.rows[0];

    // Send success response back to frontend
    return res.status(201).json({ 
      success: true, 
      user_id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      redirectUrl: '/Home.html' 
    });
  } catch (err) {
    // Log error for debugging
    console.error('[SIGNUP] error:', err);

    // Return generic server error
    return res.status(500).json({ success: false, error: 'Error signing up. Please try again.' });
  }
});


// Login route
router.post('/login', async (req, res) => {
  // Get login details from request body
  const { email, password } = req.body || {};

  // Check that both fields were provided
  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'All fields required.' });
  }

  try {
    // Normalise email to make login more consistent
    const emailNorm = String(email).trim().toLowerCase();

    // Look up user by email
    const r = await pool.query(
      'SELECT id, email, username, password FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [emailNorm]
    );

    // If no user was found, return login error
    if (r.rows.length === 0) {
      console.warn('[LOGIN] user not found:', emailNorm);
      return res.status(400).json({ success: false, error: 'Invalid email or password.' });
    }

    const user = r.rows[0];

    // Log part of the password hash for debugging
    const hashPrefix = String(user.password).slice(0, 4);
    console.log('[LOGIN] found user:', user.email, 'hashPrefix:', hashPrefix, 'hashLen:', String(user.password).length);

    // Compare entered password with stored hashed password
    const ok = await bcrypt.compare(password, user.password);
    console.log('[LOGIN] bcrypt.compare ->', ok);

    // If password does not match, return error
    if (!ok) {
      return res.status(400).json({ success: false, error: 'Invalid email or password.' });
    }
    
    // Return successful login response
    return res.status(200).json({ 
      success: true, 
      user_id: user.id,
      username: user.username,
      email: user.email,
      redirectUrl: '/Home.html' 
    });
  } catch (e) {
    // Log server-side login error
    console.error('[LOGIN] error:', e);

    // Return generic error response
    return res.status(500).json({ success: false, error: 'Error logging in.' });
  }
});

// Export router so it can be used in the main app
module.exports = router;