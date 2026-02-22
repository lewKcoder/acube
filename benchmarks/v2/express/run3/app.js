const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const SECRET = process.env.JWT_SECRET;
const app = express();

app.use(express.json());

const profiles = new Map();
const usernameIndex = new Map();
const emailIndex = new Map();

function mint_id() {
  return crypto.randomUUID();
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token", message: "Authorization header with Bearer token is required" });
  }
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, SECRET);
    req.subject = decoded.sub;
    if (!req.subject) {
      return res.status(401).json({ error: "invalid_token", message: "Token must contain a sub claim" });
    }
    next();
  } catch (err) {
    return res.status(401).json({ error: "invalid_token", message: "Token verification failed" });
  }
}

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validate_creation(body) {
  const problems = [];
  const { username, email, display_name } = body;

  if (typeof username !== "string" || !USERNAME_RE.test(username)) {
    problems.push("username must be 3-30 alphanumeric or underscore characters");
  }
  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    problems.push("email must be a valid email address");
  }
  if (typeof display_name !== "string" || display_name.length < 1 || display_name.length > 100) {
    problems.push("display_name must be between 1 and 100 characters");
  }
  return problems;
}

function validate_update(body) {
  const { display_name } = body;
  if (typeof display_name !== "string" || display_name.length < 1 || display_name.length > 100) {
    return ["display_name must be between 1 and 100 characters"];
  }
  return [];
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/users", authenticate, (req, res) => {
  const issues = validate_creation(req.body);
  if (issues.length > 0) {
    return res.status(400).json({ error: "validation_error", details: issues });
  }

  const { username, email, display_name } = req.body;
  const lower_username = username.toLowerCase();
  const lower_email = email.toLowerCase();

  if (usernameIndex.has(lower_username)) {
    return res.status(409).json({ error: "conflict", message: "Username already taken" });
  }
  if (emailIndex.has(lower_email)) {
    return res.status(409).json({ error: "conflict", message: "Email already registered" });
  }

  const id = mint_id();
  const created_at = new Date().toISOString();

  const record = {
    id,
    username,
    email,
    display_name,
    owner_id: req.subject,
    created_at,
  };

  profiles.set(id, record);
  usernameIndex.set(lower_username, id);
  emailIndex.set(lower_email, id);

  res.status(201).json({
    id: record.id,
    username: record.username,
    email: record.email,
    display_name: record.display_name,
    created_at: record.created_at,
  });
});

app.get("/users/:id", authenticate, (req, res) => {
  const record = profiles.get(req.params.id);
  if (!record) {
    return res.status(404).json({ error: "not_found", message: "User profile not found" });
  }

  if (req.subject === record.owner_id) {
    return res.json({
      id: record.id,
      username: record.username,
      email: record.email,
      display_name: record.display_name,
      created_at: record.created_at,
    });
  }

  res.json({
    id: record.id,
    username: record.username,
    display_name: record.display_name,
  });
});

app.put("/users/:id", authenticate, (req, res) => {
  const record = profiles.get(req.params.id);
  if (!record) {
    return res.status(404).json({ error: "not_found", message: "User profile not found" });
  }

  if (req.subject !== record.owner_id) {
    return res.status(403).json({ error: "forbidden", message: "Only the profile owner can perform this action" });
  }

  const issues = validate_update(req.body);
  if (issues.length > 0) {
    return res.status(400).json({ error: "validation_error", details: issues });
  }

  record.display_name = req.body.display_name;

  res.json({
    id: record.id,
    username: record.username,
    email: record.email,
    display_name: record.display_name,
    created_at: record.created_at,
  });
});

app.delete("/users/:id", authenticate, (req, res) => {
  const record = profiles.get(req.params.id);
  if (!record) {
    return res.status(404).json({ error: "not_found", message: "User profile not found" });
  }

  if (req.subject !== record.owner_id) {
    return res.status(403).json({ error: "forbidden", message: "Only the profile owner can perform this action" });
  }

  profiles.delete(record.id);
  usernameIndex.delete(record.username.toLowerCase());
  emailIndex.delete(record.email.toLowerCase());

  res.json({ deleted: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`user-profile-service listening on port ${PORT}`);
});

module.exports = app;
