// Intentionally vulnerable Node.js/Express code for demo and CI purposes.
// See examples/safe/app.js for the corrected version.
const express = require("express");
const crypto = require("crypto");
const { exec } = require("child_process");
const app = express();

// CWE-400: no size limit on the JSON request body
app.use(express.json());

// CWE-1333 (ReDoS): nested unbounded quantifier
const EMAIL_RE = /^([a-zA-Z0-9_.-]+)*@/;

app.get("/search", (req, res) => {
  // CWE-89: SQL built with a template-literal interpolation
  db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
});

app.post("/convert", (req, res) => {
  // CWE-78: exec() with a built (not literal) command string
  exec("convert " + req.body.file + " out.png");
});

app.get("/hash", (req, res) => {
  // CWE-327: MD5 is not a password hash
  res.send(crypto.createHash("md5").update(req.query.password).digest("hex"));
});

app.get("/token", (req, res) => {
  // CWE-330: non-cryptographic RNG used for a security token
  const sessionToken = Math.random().toString(36).slice(2);
  res.send(sessionToken);
});

app.get("/preview", (req, res) => {
  // CWE-918: outbound request built directly from request input
  fetch(req.query.url).then(r => r.text()).then(t => res.send(t));
});

// CWE-639: route takes an id-like parameter, no auth/ownership check nearby
app.get("/orders/:id", function (req, res) {
  return db.find(req.params.id);
});

app.post("/login", (req, res) => {
  const { user, pass } = req.body;
  // CWE-798: hardcoded credential check (a backdoor, intentionally or not)
  if (user === "admin" && pass === "admin123") {
    // CWE-614: session cookie set without httpOnly/secure flags
    res.cookie("session", "abc123");
    return res.send("ok");
  }
  res.status(401).end();
});

app.listen(3000);
