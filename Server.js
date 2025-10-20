const express = require('express');
const path = require('path');
const authRoutes = require('./routes/Authentication'); // Make sure this path is correct!

const app = express();
const port = 4000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/', authRoutes);

app.use(express.static(path.join(__dirname, 'WebPages')));

// HTML Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/Login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/SignUp.html'));
});

app.get('/Home.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'WebPages/Home.html'));
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log('Loaded routes from:', require.resolve('./routes/Authentication'));
});