// C:\.Test C\Innocent\routes\helpers.js
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const DATA_DIR = path.join(__dirname, "..", "data"); // adjust if your data dir differs
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

// ---------- small utils ----------
function nowIso() { return new Date().toISOString(); }

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

// read/write JSON files under DATA_DIR
function read(file, fallback) {
  try {
    const p = path.join(DATA_DIR, file);
    if (!fs.existsSync(p)) return fallback;
    const raw = fs.readFileSync(p, "utf8");
    return JSON.parse(raw || "null") ?? fallback;
  } catch {
    return fallback;
  }
}
function write(file, data) {
  ensureDir(DATA_DIR);
  const p = path.join(DATA_DIR, file);
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
}

// simple audit logger -> data/audit.json
function audit(actorId, action, entity, entityId, extra) {
  const list = read("audit.json", []);
  list.unshift({
    id: `aud_${Date.now()}`,
    ts: nowIso(),
    actorId: actorId || "-",
    action, entity, entityId,
    extra: extra || null
  });
  write("audit.json", list.slice(0, 5000)); // keep last 5k
}

// ---------- auth middlewares ----------
function auth(req, res, next) {
  const raw = (req.headers.authorization || req.headers.Authorization || "").toString().trim();
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  if (!m) return res.status(401).json({ error: "missing token" });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

function requireRole(...roles) {
  const allowed = roles.map(r => String(r||"").toUpperCase());
  return (req, res, next) => {
    const role = String(req.user?.role || "").toUpperCase();
    if (role === "ADMIN" || allowed.includes(role)) return next();
    return res.status(403).json({ error: "forbidden" });
  };
}

module.exports = {
  DATA_DIR,
  nowIso,
  ensureDir,
  read, write,
  audit,
  auth,
  requireRole,
};