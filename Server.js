/*
  Main Express server

  This file starts the Node.js server for the frontend side of the project.
  It sets up middleware, loads the authentication routes, serves the static
  files from the WebPages folder, and defines the main HTML page routes
  such as login, signup, and home.
*/

const express = require('express');
const path = require('path');
const authRoutes = require('./routes/Authentication');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware for reading JSON and form data from requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authentication-related routes
app.use('/', authRoutes);

// Serve static files like HTML, CSS, and JavaScript from WebPages
app.use(express.static(path.join(__dirname, 'WebPages')));

// Main HTML routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/Login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/SignUp.html'));
});

app.get('/Home.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/Home.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);

  // Small check to confirm the auth route file is being found correctly
  try {
    console.log('Loaded routes from:', require.resolve('./routes/Authentication'));
  } catch (e) {
    console.warn('Could not resolve ./routes/Authentication:', e?.message);
  }
});