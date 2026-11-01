// Hardened version of examples/vulnerable/app.js.
const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { execFile } = require("child_process");
const { URL } = require("url");
const app = express();

// A size limit bounds how much memory one request body can consume.
app.use(express.json({ limit: "100kb" }));

// Single unbounded group, no nesting -- nothing to be ambiguous about.
const EMAIL_RE = /^[a-zA-Z0-9_.-]+@/;

app.get("/search", (req, res) => {
  // Parameterized query: the driver builds the SQL, not a template literal.
  db.query("SELECT * FROM users WHERE name = ?", [req.query.name]);
});

app.post("/convert", (req, res) => {
  // execFile with an argument array: no shell, nothing to inject into.
  execFile("convert", [req.body.file, "out.png"]);
});

app.get("/hash", (req, res) => {
  // bcrypt is a slow, salted KDF -- appropriate for passwords.
  const bcrypt = require("bcrypt");
  res.send(bcrypt.hashSync(req.query.password, 12));
});

const ALLOWED_PREVIEW_HOSTS = new Set(["images.example.com"]);

app.get("/token", (req, res) => {
  // crypto.randomBytes is seeded from the OS CSPRNG.
  const sessionToken = crypto.randomBytes(32).toString("hex");
  res.send(sessionToken);
});

app.get("/preview", (req, res) => {
  // Validate the host against an allow-list before fetching it.
  const target = new URL(req.query.url);
  if (!ALLOWED_PREVIEW_HOSTS.has(target.hostname)) return res.status(400).end();
  fetch(target).then(r => r.text()).then(t => res.send(t));
});

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).end();
  next();
}

// Ownership check before the resource is returned.
app.get("/orders/:id", requireAuth, function (req, res) {
  const order = db.find(req.params.id);
  if (!order || order.ownerId !== req.session.userId) return res.status(403).end();
  return res.json(order);
});

app.post("/login", async (req, res) => {
  const { user, pass } = req.body;
  // Check against a stored, properly hashed credential, not a literal pair.
  const account = await db.findUser(user);
  if (!account || !(await bcrypt.compare(pass, account.passwordHash))) {
    return res.status(401).end();
  }
  // httpOnly + secure: not readable from JS, not sent over plain HTTP.
  res.cookie("session", crypto.randomBytes(32).toString("hex"), { httpOnly: true, secure: true, sameSite: "lax" });
  res.send("ok");
});

app.listen(3000);
