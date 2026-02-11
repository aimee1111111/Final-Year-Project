const express = require('express');
const path = require('path');
const authRoutes = require('./routes/Authentication');
const statsRoutes = require('./routes/stats');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mount API routes first (to avoid collisions)

// Then other routes
app.use('/', authRoutes);

// Static files
app.use(express.static(path.join(__dirname, 'WebPages')));

// HTML routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/Login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/SignUp.html'));
});

app.get('/Home.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/Home.html'));
});

// Optional: global 404 to debug unmatched paths
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found', path: req.originalUrl });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});