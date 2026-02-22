const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.error("JWT_SECRET environment variable is required");
  process.exit(1);
}

const app = express();
app.use(express.json());

const profiles = new Map();
const usernameIndex = new Map();
const emailIndex = new Map();

function generateId() {
  return crypto.randomUUID();
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed authorization header" });
  }
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, SECRET);
    req.subject = decoded.sub;
    if (!req.subject) {
      return res.status(401).json({ error: "Token missing sub claim" });
    }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateCreateBody(body) {
  const errors = [];
  const { username, email, display_name } = body;

  if (typeof username !== "string" || !USERNAME_RE.test(username)) {
    errors.push("username must be 3-30 alphanumeric or underscore characters");
  }

  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    errors.push("email must be a valid email address");
  }

  if (
    typeof display_name !== "string" ||
    display_name.length < 1 ||
    display_name.length > 100
  ) {
    errors.push("display_name must be between 1 and 100 characters");
  }

  return errors;
}

function validateUpdateBody(body) {
  const errors = [];
  const { display_name } = body;

  if (
    typeof display_name !== "string" ||
    display_name.length < 1 ||
    display_name.length > 100
  ) {
    errors.push("display_name must be between 1 and 100 characters");
  }

  return errors;
}

function publicView(profile) {
  return {
    id: profile.id,
    username: profile.username,
    display_name: profile.display_name,
  };
}

function fullView(profile) {
  return {
    id: profile.id,
    username: profile.username,
    email: profile.email,
    display_name: profile.display_name,
    created_at: profile.created_at,
  };
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/users", authenticate, (req, res) => {
  const errors = validateCreateBody(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: "Validation failed", details: errors });
  }

  const { username, email, display_name } = req.body;
  const lowerUsername = username.toLowerCase();
  const lowerEmail = email.toLowerCase();

  if (usernameIndex.has(lowerUsername)) {
    return res.status(409).json({ error: "Username already taken" });
  }
  if (emailIndex.has(lowerEmail)) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const profile = {
    id: generateId(),
    username,
    email,
    display_name,
    owner_id: req.subject,
    created_at: new Date().toISOString(),
  };

  profiles.set(profile.id, profile);
  usernameIndex.set(lowerUsername, profile.id);
  emailIndex.set(lowerEmail, profile.id);

  res.status(201).json(fullView(profile));
});

app.get("/users/:id", authenticate, (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ error: "User not found" });
  }

  if (req.subject === profile.owner_id) {
    return res.json(fullView(profile));
  }

  res.json(publicView(profile));
});

app.put("/users/:id", authenticate, (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ error: "User not found" });
  }

  if (req.subject !== profile.owner_id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const errors = validateUpdateBody(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: "Validation failed", details: errors });
  }

  profile.display_name = req.body.display_name;

  res.json(fullView(profile));
});

app.delete("/users/:id", authenticate, (req, res) => {
  const profile = profiles.get(req.params.id);
  if (!profile) {
    return res.status(404).json({ error: "User not found" });
  }

  if (req.subject !== profile.owner_id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  usernameIndex.delete(profile.username.toLowerCase());
  emailIndex.delete(profile.email.toLowerCase());
  profiles.delete(profile.id);

  res.json({ deleted: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`User Profile Service listening on port ${PORT}`);
});

module.exports = app;
