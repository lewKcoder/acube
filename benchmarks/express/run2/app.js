const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const JWT_SECRET = 'secret123';
const users = {};

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Create user
app.post('/users', authMiddleware, (req, res) => {
  const { username, email, display_name } = req.body;

  // Basic validation
  if (!username || username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Username must be between 3 and 30 characters' });
  }

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email is required' });
  }

  if (!display_name || display_name.length > 100) {
    return res.status(400).json({ error: 'Display name is required and must be under 100 characters' });
  }

  const id = uuidv4();
  const user = {
    id,
    username,
    email,
    display_name,
    created_at: new Date().toISOString(),
  };

  users[id] = user;
  res.status(201).json(user);
});

// Get user
app.get('/users/:id', authMiddleware, (req, res) => {
  const user = users[req.params.id];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});

// Delete user
app.delete('/users/:id', authMiddleware, (req, res) => {
  if (!users[req.params.id]) {
    return res.status(404).json({ error: 'User not found' });
  }
  delete users[req.params.id];
  res.status(204).send();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
