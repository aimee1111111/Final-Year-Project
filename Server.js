const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const authRoutes = require('./routes/auth');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'WebPages')));

// Routes
app.use(authRoutes);

// Default route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'WebPages/Login.html'));
});

// Serve homepage
app.get('/Home.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'WebPages/Home.html'));
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
