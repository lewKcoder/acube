"use strict";

const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

const users = new Map();
const usernameIndex = new Map();
const emailIndex = new Map();

function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.sub;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateCreateBody(body) {
  const errors = [];

  if (typeof body.username !== "string" || !USERNAME_RE.test(body.username)) {
    errors.push("username must be 3-30 alphanumeric or underscore characters");
  }

  if (typeof body.email !== "string" || !EMAIL_RE.test(body.email)) {
    errors.push("email must be a valid email address");
  }

  if (
    typeof body.display_name !== "string" ||
    body.display_name.length < 1 ||
    body.display_name.length > 100
  ) {
    errors.push("display_name must be between 1 and 100 characters");
  }

  return errors;
}

function validateUpdateBody(body) {
  const errors = [];

  if (
    typeof body.display_name !== "string" ||
    body.display_name.length < 1 ||
    body.display_name.length > 100
  ) {
    errors.push("display_name must be between 1 and 100 characters");
  }

  return errors;
}

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.post("/users", authenticateJWT, (req, res) => {
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
    return res.status(409).json({ error: "Email already in use" });
  }

  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();

  const user = {
    id,
    username,
    email,
    display_name,
    owner_id: req.userId,
    created_at,
  };

  users.set(id, user);
  usernameIndex.set(lowerUsername, id);
  emailIndex.set(lowerEmail, id);

  res.status(201).json({
    id: user.id,
    username: user.username,
    email: user.email,
    display_name: user.display_name,
    created_at: user.created_at,
  });
});

app.get("/users/:id", authenticateJWT, (req, res) => {
  const user = users.get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (req.userId === user.owner_id) {
    return res.status(200).json({
      id: user.id,
      username: user.username,
      email: user.email,
      display_name: user.display_name,
      created_at: user.created_at,
    });
  }

  res.status(200).json({
    id: user.id,
    username: user.username,
    display_name: user.display_name,
  });
});

app.put("/users/:id", authenticateJWT, (req, res) => {
  const user = users.get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (req.userId !== user.owner_id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const errors = validateUpdateBody(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: "Validation failed", details: errors });
  }

  user.display_name = req.body.display_name;

  res.status(200).json({
    id: user.id,
    username: user.username,
    email: user.email,
    display_name: user.display_name,
    created_at: user.created_at,
  });
});

app.delete("/users/:id", authenticateJWT, (req, res) => {
  const user = users.get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (req.userId !== user.owner_id) {
    return res.status(403).json({ error: "Forbidden" });
  }

  users.delete(user.id);
  usernameIndex.delete(user.username.toLowerCase());
  emailIndex.delete(user.email.toLowerCase());

  res.status(200).json({ deleted: true });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

module.exports = app;
