const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const pool = require('../db');

const router = express.Router();

// Serve signup page
router.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, '../WebPages/signup.html'));
});

// Handle signup
router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).send('All fields required.');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        //checks if user exists
        const existingUser = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
        if (existingUser.rows.length > 0) return res.status(400).send('Email exists.');

        //enters new user into the users table
        await pool.query('INSERT INTO users (username,email,password) VALUES($1,$2,$3)', [username, email, hashedPassword]);
        res.redirect('/Home.html');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error signing up.');
    }
});

// Handle login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('All fields required.');

    try {
        //Checks if the email exists in the database.
        const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
        if (result.rows.length === 0) return res.status(400).send('Invalid email or password.');

        //Compares the provided password with the hashed password in the database.
        const match = await bcrypt.compare(password, result.rows[0].password);
        if (!match) return res.status(400).send('Invalid email or password.');

        res.redirect('/Home.html');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error logging in.');
    }
});

module.exports = router;
