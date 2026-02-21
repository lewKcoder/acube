const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

app.use(express.json());

// In-memory user store
const users = new Map();

// JWT auth middleware
const requireAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',
        message: 'Authorization header is required',
      },
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      error: {
        code: 'INVALID_TOKEN',
        message: 'Authorization header must be in the format: Bearer <token>',
      },
    });
  }

  try {
    const decoded = jwt.verify(parts[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Token has expired',
        },
      });
    }
    return res.status(401).json({
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid token',
      },
    });
  }
};

// Validation helpers
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isAlphanumeric = (str) => /^[a-zA-Z0-9]+$/.test(str);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Create a new user
app.post('/users', requireAuth, (req, res) => {
  const { username, email, display_name } = req.body;
  const errors = [];

  // Validate username
  if (!username || typeof username !== 'string') {
    errors.push({ field: 'username', message: 'Username is required' });
  } else if (username.length < 3 || username.length > 30) {
    errors.push({ field: 'username', message: 'Username must be between 3 and 30 characters' });
  } else if (!isAlphanumeric(username)) {
    errors.push({ field: 'username', message: 'Username must contain only alphanumeric characters' });
  }

  // Validate email
  if (!email || typeof email !== 'string') {
    errors.push({ field: 'email', message: 'Email is required' });
  } else if (!isValidEmail(email)) {
    errors.push({ field: 'email', message: 'Invalid email format' });
  }

  // Validate display_name
  if (!display_name || typeof display_name !== 'string') {
    errors.push({ field: 'display_name', message: 'Display name is required' });
  } else if (display_name.length < 1 || display_name.length > 100) {
    errors.push({ field: 'display_name', message: 'Display name must be between 1 and 100 characters' });
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: errors,
      },
    });
  }

  // Check for duplicate username or email
  for (const [, existingUser] of users) {
    if (existingUser.username === username) {
      return res.status(409).json({
        error: {
          code: 'DUPLICATE_USERNAME',
          message: `Username '${username}' is already taken`,
        },
      });
    }
    if (existingUser.email === email) {
      return res.status(409).json({
        error: {
          code: 'DUPLICATE_EMAIL',
          message: 'A user with this email already exists',
        },
      });
    }
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const newUser = {
    id,
    username,
    email,
    display_name,
    created_at: now,
    updated_at: now,
  };

  users.set(id, newUser);

  return res.status(201).json({
    data: newUser,
  });
});

// Get user by ID
app.get('/users/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const user = users.get(id);

  if (!user) {
    return res.status(404).json({
      error: {
        code: 'USER_NOT_FOUND',
        message: `User with ID '${id}' not found`,
      },
    });
  }

  return res.json({
    data: user,
  });
});

// Delete user by ID
app.delete('/users/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  if (!users.has(id)) {
    return res.status(404).json({
      error: {
        code: 'USER_NOT_FOUND',
        message: `User with ID '${id}' not found`,
      },
    });
  }

  users.delete(id);
  return res.status(204).send();
});

// Handle 404 for unmatched routes
app.use((req, res) => {
  res.status(404).json({
    error: {
      code: 'ROUTE_NOT_FOUND',
      message: `Cannot ${req.method} ${req.originalUrl}`,
    },
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Something went wrong',
    },
  });
});

app.listen(PORT, () => {
  console.log(`User API server listening on port ${PORT}`);
});

module.exports = app;
