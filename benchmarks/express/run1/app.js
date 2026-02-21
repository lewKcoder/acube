const express = require('express');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(express.json());

// In-memory storage
const users = new Map();

// JWT Authentication Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header',
      },
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Invalid or expired token',
      },
    });
  }
};

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: errors.array().map((err) => ({
          field: err.path,
          message: err.msg,
        })),
      },
    });
  }
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

// Create user
app.post(
  '/users',
  authenticate,
  [
    body('username')
      .isString()
      .isLength({ min: 3, max: 30 })
      .matches(/^[a-zA-Z0-9]+$/)
      .withMessage('Username must be 3-30 alphanumeric characters'),
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Must be a valid email address'),
    body('display_name')
      .isString()
      .isLength({ min: 1, max: 100 })
      .withMessage('Display name must be 1-100 characters'),
  ],
  handleValidationErrors,
  (req, res) => {
    const { username, email, display_name } = req.body;

    // Check for duplicate username
    for (const [, user] of users) {
      if (user.username === username) {
        return res.status(409).json({
          error: {
            code: 'CONFLICT',
            message: 'Username already exists',
          },
        });
      }
      if (user.email === email) {
        return res.status(409).json({
          error: {
            code: 'CONFLICT',
            message: 'Email already exists',
          },
        });
      }
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const user = {
      id,
      username,
      email,
      display_name,
      created_at: now,
      updated_at: now,
    };

    users.set(id, user);

    res.status(201).json({
      data: user,
    });
  }
);

// Get user by ID
app.get(
  '/users/:id',
  authenticate,
  [param('id').isUUID().withMessage('Invalid user ID format')],
  handleValidationErrors,
  (req, res) => {
    const user = users.get(req.params.id);

    if (!user) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
        },
      });
    }

    res.json({
      data: user,
    });
  }
);

// Delete user by ID
app.delete(
  '/users/:id',
  authenticate,
  [param('id').isUUID().withMessage('Invalid user ID format')],
  handleValidationErrors,
  (req, res) => {
    const user = users.get(req.params.id);

    if (!user) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
        },
      });
    }

    users.delete(req.params.id);

    res.status(204).send();
  }
);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found`,
    },
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
    },
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
