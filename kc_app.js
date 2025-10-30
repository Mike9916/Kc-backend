/**
 * KC App — Unified Backend (JSON store)
 * Single-file Express server with:
 *  - Auth (login-json, /me)
 *  - Reports (service, education, evangelism, offering) with correct per-type+date duplicate logic
 *  - Leaders: summary + fill-missing, contacts lookup
 *  - Issues: saints → anonymous → Comms inbox
 *  - Announcements: list + admin/culture create
 *  - Evangelism Media: list (JYK), upload (multipart), URL add, owner-only edit/delete
 *  - Admin console basics: whitelist upsert, set role, support inbox/override, feature flags, audit
 *  - Static serving of uploaded files under /uploads
 */
require('dotenv').config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const multer = require("multer");

const { Pool } = require('pg');

let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
  (async () => {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS reports (
          id SERIAL PRIMARY KEY,
          scj_id TEXT NOT NULL,
          type TEXT NOT NULL,
          payload JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);
      // Accounts table (DB-first) — id is your existing acc_*, scj_id unique
await pool.query(`
  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    scj_id TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    password_reset_at TIMESTAMPTZ
  )
`);

// Whitelist table (DB-first)
await pool.query(`
  CREATE TABLE IF NOT EXISTS whitelist (
    scj_id TEXT PRIMARY KEY,
    name  TEXT,
    phone TEXT,
    jyk   TEXT,
    dept  TEXT,
    cell  TEXT,
    role  TEXT
  )
`);
// Media table (stores uploaded/linked items)
await pool.query(`
  CREATE TABLE IF NOT EXISTS media (
    id TEXT PRIMARY KEY,
    scj_id TEXT,
    name   TEXT,
    jyk    TEXT,
    type   TEXT,            -- "image" | "video"
    url    TEXT,            -- "uploads/..." or external URL
    title  TEXT,
    caption TEXT,
    size_bytes INTEGER,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`);

// Support inbox table
await pool.query(`
  CREATE TABLE IF NOT EXISTS support_inbox (
    id TEXT PRIMARY KEY,
    type TEXT,              -- "forgot_password" | "create_account" | "other"
    name TEXT,
    scj_id TEXT,
    phone TEXT,
    jyk TEXT,
    dept TEXT,
    cell TEXT,
    details TEXT,
    status TEXT,            -- "Open" | "Pending" | "Resolved"
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
  )
`);
// Audit log (append-only)
await pool.query(`
  CREATE TABLE IF NOT EXISTS audit (
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_scj_id TEXT,
    action TEXT,
    entity TEXT,
    entity_id TEXT,
    meta JSONB
  )
`);

// Forwards state (leaders workflow)
await pool.query(`
  CREATE TABLE IF NOT EXISTS forwards (
    key TEXT PRIMARY KEY,
    date TEXT,
    type TEXT,
    by_scj_id TEXT,
    forward_attempts INT DEFAULT 0,
    needs_verify BOOLEAN DEFAULT false,
    status TEXT,           -- e.g., "Pending","Returned","Verified"
    returns INT DEFAULT 0,
    note TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`);

// Feature flags (optional JSON values)
await pool.query(`
  CREATE TABLE IF NOT EXISTS flags (
    name TEXT PRIMARY KEY,
    value JSONB
  )
`);
      console.log('Reports table ready');
    } catch (e) {
      console.error('DB init failed:', e);
    }
  })();
} else {
  console.warn('DATABASE_URL not set — DB features are disabled locally.');
}
const app = express();

/* -------------------------- DATA & HELPERS -------------------------- */

const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function read(file, fallback) {
  const p = path.join(DATA_DIR, file);
  if (!fs.existsSync(p)) return fallback;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return fallback; }
}
function write(file, obj) {
  const p = path.join(DATA_DIR, file);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
}

function ensure(file, seed) {
  const p = path.join(DATA_DIR, file);
  if (!fs.existsSync(p)) write(file, seed);
}

function pruneAnnouncements() {
  const list = read("announcements.json", []);
  const now = Date.now();
  const kept = [];
  let changed = false;

  for (const a of list) {
    const exp = a.expiresAt ? Date.parse(a.expiresAt) : 0;
    if (exp && exp <= now) { changed = true; continue; }
    kept.push(a);
  }

  if (changed) write("announcements.json", kept);
  return kept;
}


// --- Support inbox helpers ---
function ms(n){ return n; }
const HOUR = 60 * 60 * 1000;

function cleanupSupportInbox(){
  const list = read("support_inbox.json", []);
  const now = Date.now();
  const pruned = list.filter(x => {
    const ts = Date.parse(x.ts || 0) || 0;
    // auto-delete after 72 hours regardless of status
    return (now - ts) < (72 * HOUR);
  });
  if (pruned.length !== list.length) write("support_inbox.json", pruned);
  return pruned;
}
/* --- seed data (safe defaults) --- */
ensure("whitelist.json", [
  { scjId: "KC2024-1001", name: "Test Saint", phone: "0712345678", role: "SAINT", jyk: "Kawangware", dept: "Education", cell: "Cell1" },
  { scjId: "KC2024-1002", name: "Test GYJN",  phone: "0712345679", role: "GYJN",  jyk: "Kawangware", dept: "Education", cell: "Cell2" },
  { scjId: "KC2024-9001", name: "Test Admin",  phone: "0712000000", role: "ADMIN", jyk: "HQ",         dept: "Admin",     cell: "—"    }
]);
ensure("accounts.json", [
  // passwordHash = bcrypt.hashSync("0000", 10)
  { id: "acc_1001", scjId: "KC2024-1001", passwordHash: bcrypt.hashSync("0000", 10) },
  { id: "acc_1002", scjId: "KC2024-1002", passwordHash: bcrypt.hashSync("0000", 10) },
  { id: "acc_9001", scjId: "KC2024-9001", passwordHash: bcrypt.hashSync("0000", 10) },
]);
ensure("reports_service.json", []);
ensure("reports_education.json", []);
ensure("reports_evangelism.json", []);
ensure("reports_offering.json", []);
ensure("forwards.json", []);
ensure("announcements.json", []);
ensure("issues.json", []);
ensure("media.json", []);
ensure("support_inbox.json", []);
ensure("audit.json", []);
ensure("flags.json", { jykActivities: false });

async function loadUsers() {
  return read("accounts.json", []);
}
async function findUserByScjId(scjId) {
  const users = await loadUsers();
  return users.find(u => String(u.scjId).toLowerCase() === String(scjId).toLowerCase());
}
async function saveUser(updatedUser) {
  const users = await loadUsers();
  const i = users.findIndex(u => u.id === updatedUser.id);
  if (i >= 0) users[i] = updatedUser;
  write("accounts.json", users);
}
/* --- tiny utils --- */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { throw new Error("JWT_SECRET is required"); }
const ROLES = new Set(["SAINT","GYJN","JYJN","WEJANM","NEMOBU", "CHMN","DNGSN","CULTURE","COMMS","ADMIN"]);
// >>> LEADERS: Roles (NEMOBU added)
const LEADER_ROLES = new Set(["GYJN", "JYJN", "WEJANM", "NEMOBU", "CHMN", "DNGSN", "ADMIN"]);
// <<< LEADERS

// NEW: robust boolean parser (prevents "false" from becoming true)
function toBool(v) {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  const s = String(v ?? "").trim().toLowerCase();
  if (["true","1","yes","y"].includes(s)) return true;
  if (["false","0","no","n",""].includes(s)) return false;
  return false;
}

function audit(actorScjId, action, entity, entityId, meta = {}) {
  if (pool) {
    // fire-and-forget; don't block request if audit fails
    pool.query(
      `insert into audit (actor_scj_id, action, entity, entity_id, meta)
       values ($1,$2,$3,$4,$5)`,
      [actorScjId || null, action || "", entity || "", entityId || "", JSON.stringify(meta || {})]
    ).catch(()=>{});
    return;
  }
  // JSON fallback (dev/offline)
  const log = read("audit.json", []);
  log.unshift({ ts: new Date().toISOString(), actorScjId, action, entity, entityId, meta });
  write("audit.json", log.slice(0, 5000));
}
function profileFor(scjId) {
  const wl = read("whitelist.json", []);
  return wl.find(w => String(w.scjId) === String(scjId)) || null;
}

function tokenFor(account, profile) {
  const payload = {
    id: account.id, scjId: account.scjId,
    role: profile?.role || "SAINT",
    name: profile?.name || "",
    jyk: profile?.jyk || "", dept: profile?.dept || "", cell: profile?.cell || ""
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "10h" });
}


// normalize answer before hashing (trim & lowercase)
function normAnswer(a) { return String(a||"").trim().toLowerCase(); }
/* ----------------------------- MIDDLEWARE ----------------------------- */


// Your current deployed frontend (keep this so it works even if env var is empty)
const FRONTEND_HOST = "https://kc-frontend-9916.onrender.com";

// Render sets this to your backend’s public URL. Normalize & strip trailing slash.
const RENDER_HOST = (process.env.RENDER_EXTERNAL_URL || "").replace(/\/+$/, "").toLowerCase();

// Optional: comma-separated list of extra origins from env (good for future frontends)
const EXTRA_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean)
  .map(s => s.replace(/\/+$/, "").toLowerCase());

// Helper to normalize an origin string safely
function norm(o) {
  if (!o) return "";
  return o.toString().trim().replace(/\/+$/, "").toLowerCase();
}

const corsOpts = {
  origin: function (origin, cb) {
    // allow non-browser / same-origin calls
    if (!origin) return cb(null, true);

    const o = norm(origin);

    // Local dev + Capacitor WebView
    if (o.startsWith("http://localhost")) return cb(null, true);
    if (o.startsWith("https://localhost")) return cb(null, true);
    if (o === "capacitor://localhost") return cb(null, true);

    // Your deployed frontend (hard-coded safety net)
    if (o === norm(FRONTEND_HOST)) return cb(null, true);

    // This backend’s own public host (Render)
    if (RENDER_HOST && o === RENDER_HOST) return cb(null, true);

    // Any extra allowed origins from env
    if (EXTRA_ORIGINS.includes(o)) return cb(null, true);

    // otherwise block
    return cb(new Error("CORS not allowed: " + origin));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["Content-Disposition"],
  credentials: true,
};

app.use(cors(corsOpts));

// Fast-path preflight without using app.options('*')
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    return res.sendStatus(204);
  }
  next();
});
// Optional: nicer JSON error instead of crashing
app.use((err, req, res, next) => {
  if (String(err?.message || "").startsWith("CORS not allowed:")) {
    return res.status(403).json({ ok: false, error: err.message });
  }
  next(err);
});


// make sure preflights are handled
app.use(express.json());
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(express.urlencoded({ extended: true }));

// Rate limiting (general)
const limiter = rateLimit({ windowMs: 60_000, max: 300 }); // 300 req/min per IP
app.use(limiter);
app.use('/api/auth', require('./routes/auth')); // <- the file you pasted

// Auth (robust)
function auth(req, res, next) {
  const raw = (req.headers.authorization ?? req.headers.Authorization ?? "").toString().trim();
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  if (!m) return res.status(401).json({ error: "missing token" });
  const token = m[1];
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token", details: e.message });
  }
}

// Static uploads folder
const UP_DIR = path.join(DATA_DIR, "uploads");
if (!fs.existsSync(UP_DIR)) fs.mkdirSync(UP_DIR, { recursive: true });
app.use("/uploads", express.static(UP_DIR));

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UP_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    const base = path.basename(file.originalname || "upload", ext).replace(/\s+/g, "_");
    cb(null, `${Date.now()}_${base}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 1024 * 1024 * 1024 } }); // 1GB cap

/* ------------------------------- AUTH ------------------------------- */
function dbg(...a){ console.log('[LOGINDBG]', ...a); }

// Optional signup (validate against whitelist)
app.post("/api/auth/signup", (req, res) => {
  const { scjId, name, phone, password } = req.body || {};
  const wl = read("whitelist.json", []);
  const ok = wl.find(w => String(w.scjId) === String(scjId) && String(w.name).toLowerCase() === String(name).toLowerCase());
  if (!ok) return res.status(403).json({ error: "Access denied. Not in whitelist." });

  const accounts = read("accounts.json", []);
  if (accounts.some(a => a.scjId === scjId)) return res.status(409).json({ error: "Account already exists" });
  const acc = { id: `acc_${Date.now()}`, scjId, passwordHash: bcrypt.hashSync(String(password || "0000"), 10) };
  accounts.push(acc); write("accounts.json", accounts);

  const token = tokenFor(acc, ok);
  audit(scjId, "SIGNUP", "account", acc.id);
  res.json({ ok: true, token, profile: ok });
});


// token check
app.get("/api/me", auth, (req, res) => {
  res.json({ ok: true, user: req.user });
});


// ---------------- Password Recovery (public entry points) ----------------

// 1) Start recovery: return the recovery question (if set) for the given scjId
app.post("/api/auth/recovery-start", async (req, res) => {
  try {
    const { scjId = "" } = req.body || {};
    if (!scjId) return res.status(400).json({ error: "scjId required" });

    const accounts = read("accounts.json", []);
    const acc = accounts.find(a => String(a.scjId).toLowerCase() === String(scjId).toLowerCase());
    if (!acc) return res.status(404).json({ error: "account not found" });

    const rq = acc.recovery || null;
    if (!rq || (!rq.question && !rq.questionId)) {
      return res.status(400).json({ error: "recovery not set" });
    }

    // Only return the question (never the answer hash)
    res.json({ questionId: rq.questionId || "", question: rq.question || "" });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

// 2) Finish recovery: verify answer, then set new password
app.post("/api/auth/recovery-reset", async (req, res) => {
  try {
    const { scjId = "", answer = "", newPassword = "" } = req.body || {};
    if (!scjId || !answer || !newPassword) {
      return res.status(400).json({ error: "scjId, answer, newPassword required" });
    }

    const accounts = read("accounts.json", []);
    const idx = accounts.findIndex(a => String(a.scjId).toLowerCase() === String(scjId).toLowerCase());
    if (idx < 0) return res.status(404).json({ error: "account not found" });

    const acc = accounts[idx];
    if (!acc.recovery?.answerHash) return res.status(400).json({ error: "recovery not set" });

    const ok = bcrypt.compareSync(normAnswer(answer), acc.recovery.answerHash);
    if (!ok) return res.status(401).json({ error: "invalid answer" });

    acc.passwordHash = bcrypt.hashSync(String(newPassword), 10);
    acc.passwordResetAt = new Date().toISOString();
    accounts[idx] = acc;
    write("accounts.json", accounts);

    audit(scjId, "PASSWORD_RESET_RECOVERY", "account", acc.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

// ===== Password & Recovery API =====

// Reset password via recovery question (NO auth)
// If the recovery answer matches, set password to default "0000"
app.post("/api/auth/password/reset-by-recovery", async (req, res) => {
  try {
    const { scjId = "", answer = "" } = req.body || {};
    if (!scjId || !answer) return res.status(400).json({ error: "scjId & answer required" });

    const acc = await findUserByScjId(scjId);
    if (!acc) return res.status(404).json({ error: "account not found" });
    if (!acc.recovery?.answerHash) {
      return res.status(400).json({ error: "recovery not set" });
    }
    if (!bcrypt.compareSync(String(answer), acc.recovery.answerHash)) {
      return res.status(401).json({ error: "invalid answer" });
    }

    acc.passwordHash = bcrypt.hashSync("0000", 10); // default after reset
    acc.passwordResetAt = new Date().toISOString();
    await saveUser(acc);
    audit(scjId, "PASSWORD_RESET_RECOVERY", "account", acc.id);
    res.json({ ok: true, newPassword: "0000" });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});


// ======================================
// POST /api/auth/password/change
// ======================================
// Logged-in user changes password by providing current & next
app.post("/api/auth/password/change", auth, async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ error: "Not authenticated" });

    const { current, next, oldPassword, newPassword } = req.body || {};
    const cur = current ?? oldPassword;
    const nxt = next ?? newPassword;
    if (!cur || !nxt) return res.status(400).json({ error: "Missing fields" });

    // Compare with migration support
    const { ok } = await compareAndMaybeMigratePassword(user, cur);
    if (!ok) return res.status(400).json({ error: "Current password incorrect" });

    // Set new password
    user.passwordHash = await bcrypt.hash(String(nxt), 10);
    if ("password" in user) user.password = undefined; // clear legacy if present
    await saveUser(user);

    res.json({ ok: true });
  } catch (err) {
    console.error("PASSWORD CHANGE ERROR:", err);
    res.status(500).json({ error: "Password change failed" });
  }
});

// ======================================
// POST /api/auth/recovery/set
// ======================================
// Logged-in user sets (or updates) their recovery question & answer
app.post("/api/auth/recovery/set", auth, async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ error: "Not authenticated" });

    const { qid, questionId, answer, password } = req.body || {};
    const _qid = (qid ?? questionId) ? String(qid ?? questionId).trim() : null;
    if (!_qid || !answer) return res.status(400).json({ error: "Missing fields" });

    const r = user.recovery || {};
    const alreadySet = !!(r.qid ?? r.questionId);

    // If already set, require current password (with legacy support)
    if (alreadySet) {
      if (!password) return res.status(400).json({ error: "Password required to change recovery question" });
      const { ok } = await compareAndMaybeMigratePassword(user, password);
      if (!ok) return res.status(400).json({ error: "Password incorrect" });
    }

    const normalizedAns = String(answer).trim().toLowerCase();
    const ansHash = await bcrypt.hash(normalizedAns, 10);

    user.recovery = {
      qid: _qid,
      ansHash,
      // mirror legacy keys too (compat)
      questionId: _qid,
      answerHash: ansHash,
    };
    await saveUser(user);

    res.json({ ok: true });
  } catch (err) {
    console.error("SET RECOVERY ERROR:", err);
    res.status(500).json({ error: "Failed to set recovery" });
  }
});

// ======================================
// POST /api/auth/forgot/answer
// ======================================
app.post("/api/auth/forgot/answer", async (req, res) => {
  try {
    const { scjId, qid, answer } = req.body;
    if (!scjId || !qid || !answer)
      return res.status(400).json({ error: "Missing fields" });

    const user = await findUserByScjId(scjId);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.recovery || user.recovery.qid !== qid)
      return res.status(400).json({ error: "Recovery question mismatch" });

    const normalizedAns = answer.trim().toLowerCase();
    const ok = await bcrypt.compare(normalizedAns, user.recovery.ansHash);
    if (!ok) return res.status(400).json({ error: "Incorrect answer" });

    const newHash = await bcrypt.hash("0000", 10);
    user.passwordHash = newHash;
    user.mustChangePassword = true;
    await saveUser(user);

    res.json({ ok: true, resetTo: "0000" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to reset password" });
  }
});
/* ------------------------------ CONTACTS ------------------------------ */

// Lookup names/phones for scjId list
app.get("/api/contacts", auth, (req, res) => {
  const ids = String(req.query.ids || "").split(",").map(s => s.trim()).filter(Boolean);
  if (!ids.length) return res.json({ items: [] });
  const wl = read("whitelist.json", []);
  const items = Array.isArray(wl) ? wl : (wl.items || []);
  const byId = Object.fromEntries(items.map(x => [String(x.scjId), x]));
  const out = ids.map(id => {
    const x = byId[id] || null;
    return x ? { scjId: id, name: x.name || "", phone: x.phone || "" } : { scjId: id, name: "", phone: "" };
  });
  res.json({ items: out });
});

/* ------------------------------- REPORTS ------------------------------ */
/** Duplicate rule:
 * For each SCJ ID, a saint may submit **one** record per TYPE per DATE.
 * Four types are independent, so same date across different types is allowed.
 */

function already(store, scjId, scjDate) {
  return store.some(r => r.scjId === scjId && r.scjDate === scjDate);
}
function validDate(s) { return /^\d{4}-\d{2}-\d{2}$/.test(String(s||"")); }

app.post("/api/reports/service", auth, async (req, res) => {
  const me = req.user;
  const { scjDate, method = "physical", notAttended = false, realization = "" } = req.body || {};
  if (!validDate(scjDate)) return res.status(400).json({ error: "invalid date" });
  if (pool) {
  // duplicate by (scjId, type, scjDate)
  const dup = await pool.query(
    `select 1 from reports 
     where scj_id=$1 and type='service' and payload->>'scjDate'=$2 limit 1`,
    [me.scjId, scjDate]
  );
  if (dup.rowCount) return res.status(409).json({ error:"duplicate", details:"service already submitted for this date" });

  const rec = {
    id: `svc_${Date.now()}`,
    scjId: me.scjId,
    scjDate,
    method: String(method).toLowerCase(),
    notAttended: toBool(notAttended),
    realization: String(realization || ""),
    createdAt: new Date().toISOString()
  };
  await pool.query(
    `insert into reports (scj_id, type, payload) values ($1,'service',$2::jsonb)`,
    [me.scjId, JSON.stringify(rec)]
  );

  // (temporary) mirror to JSON so existing leader views still see it
  try { const s = read("reports_service.json", []); s.push(rec); write("reports_service.json", s); } catch {}
  audit(me.scjId, "SUBMIT", "report_service", rec.id, { scjDate });
  return res.json({ ok:true, record:rec });
}

// fallback: original JSON path
const store = read("reports_service.json", []);
if (already(store, me.scjId, scjDate)) return res.status(409).json({ error:"duplicate", details:"service already submitted for this date" });
const rec = { id:`svc_${Date.now()}`, scjId: me.scjId, scjDate, method:String(method).toLowerCase(), notAttended:toBool(notAttended), realization:String(realization||""), createdAt:new Date().toISOString() };
store.push(rec); write("reports_service.json", store);
audit(me.scjId, "SUBMIT", "report_service", rec.id, { scjDate });
return res.json({ ok:true, record:rec });
});

app.post("/api/reports/education", auth, async (req, res) => {
  const me = req.user;
  const { scjDate, session = "ALL_SUN", method = "physical", notAttended = false, realization = "" } = req.body || {};
  if (!validDate(scjDate)) return res.status(400).json({ error: "invalid date" });
 if (pool) {
  const dup = await pool.query(
    `select 1 from reports 
     where scj_id=$1 and type='education' and payload->>'scjDate'=$2 limit 1`,
    [me.scjId, scjDate]
  );
  if (dup.rowCount) return res.status(409).json({ error:"duplicate", details:"education already submitted for this date" });

  const rec = {
    id: `edu_${Date.now()}`,
    scjId: me.scjId,
    scjDate,
    session: String(session).toUpperCase(),
    method: String(method).toLowerCase(),
    notAttended: toBool(notAttended),
    realization: String(realization || ""),
    createdAt: new Date().toISOString()
  };
  await pool.query(
    `insert into reports (scj_id, type, payload) values ($1,'education',$2::jsonb)`,
    [me.scjId, JSON.stringify(rec)]
  );

  try { const s = read("reports_education.json", []); s.push(rec); write("reports_education.json", s); } catch {}
  audit(me.scjId, "SUBMIT", "report_education", rec.id, { scjDate, session });
  return res.json({ ok:true, record:rec });
}

// fallback: original JSON path (keep)
const store = read("reports_education.json", []);
if (already(store, me.scjId, scjDate)) return res.status(409).json({ error:"duplicate", details:"education already submitted for this date" });
const rec = { id:`edu_${Date.now()}`, scjId: me.scjId, scjDate, session:String(session).toUpperCase(), method:String(method).toLowerCase(), notAttended:toBool(notAttended), realization:String(realization||""), createdAt:new Date().toISOString() };
store.push(rec); write("reports_education.json", store);
audit(me.scjId, "SUBMIT", "report_education", rec.id, { scjDate, session });
return res.json({ ok:true, record:rec });
});

app.post("/api/reports/evangelism", auth, async (req, res) => {
  const me = req.user;
  const { scjDate, participated = false, findings = 0, nfp = 0, rp = 0, bb = 0 } = req.body || {};

  if (!validDate(scjDate)) {
    return res.status(400).json({ error: "invalid date" });
  }

  // helper: clean non-negative integers
  const n = (v) => {
    const x = Number(v);
    return Number.isFinite(x) && x >= 0 ? Math.floor(x) : 0;
  };

  // compute metrics FIRST
  const F = n(findings);
  const N = n(nfp);
  const R = n(rp);
  const B = n(bb);

  // infer participation if any metric > 0
  const inferred = (F > 0) || (N > 0) || (R > 0) || (B > 0);
  const part = Boolean(participated) || inferred;

  // --- DB-first path ---
  if (pool) {
    const dup = await pool.query(
      `select 1 from reports 
       where scj_id=$1 and type='evangelism' and payload->>'scjDate'=$2
       limit 1`,
      [me.scjId, scjDate]
    );
    if (dup.rowCount) {
      return res.status(409).json({ error: "duplicate", details: "evangelism already submitted for this date" });
    }

    const rec = {
      id: `ev_${Date.now()}`,
      scjId: me.scjId,
      scjDate: String(scjDate),
      participated: part,
      findings: part ? F : 0,
      nfp: part ? N : 0,
      rp: part ? R : 0,
      bb: part ? B : 0,
      createdAt: new Date().toISOString(),
    };

    await pool.query(
      `insert into reports (scj_id, type, payload) values ($1,'evangelism',$2::jsonb)`,
      [me.scjId, JSON.stringify(rec)]
    );

    // Optional: mirror to JSON so existing leader views still work
    try {
      const s = read("reports_evangelism.json", []);
      s.push(rec);
      write("reports_evangelism.json", s);
    } catch {}

    audit(me.scjId, "SUBMIT", "report_evangelism", rec.id, { scjDate });
    return res.json({ ok: true, record: rec });
  }

  // --- Fallback JSON path ---
  const store = read("reports_evangelism.json", []);
  if (already(store, me.scjId, scjDate)) {
    return res.status(409).json({ error: "duplicate", details: "evangelism already submitted for this date" });
  }

  const rec = {
    id: `ev_${Date.now()}`,
    scjId: me.scjId,
    scjDate: String(scjDate),
    participated: part,
    findings: part ? F : 0,
    nfp: part ? N : 0,
    rp: part ? R : 0,
    bb: part ? B : 0,
    createdAt: new Date().toISOString(),
  };

  store.push(rec);
  write("reports_evangelism.json", store);
  audit(me.scjId, "SUBMIT", "report_evangelism", rec.id, { scjDate });
  return res.json({ ok: true, record: rec });
});
app.post("/api/reports/offering", auth, async (req, res) => {
  const me = req.user;
  const { scjDate, channel = "cash", amount = 0 } = req.body || {};
  if (!validDate(scjDate)) return res.status(400).json({ error: "invalid date" });
  const amt = Number(amount); if (!isFinite(amt) || amt < 0) return res.status(400).json({ error: "invalid amount" });
  if (pool) {
  const dup = await pool.query(
    `select 1 from reports 
     where scj_id=$1 and type='offering' and payload->>'scjDate'=$2 limit 1`,
    [me.scjId, scjDate]
  );
  if (dup.rowCount) return res.status(409).json({ error:"duplicate", details:"offering already submitted for this date" });

  const rec = {
    id: `off_${Date.now()}`,
    scjId: me.scjId,
    scjDate,
    channel: String(channel).toLowerCase(),
    amount: amt,
    createdAt: new Date().toISOString()
  };
  await pool.query(
    `insert into reports (scj_id, type, payload) values ($1,'offering',$2::jsonb)`,
    [me.scjId, JSON.stringify(rec)]
  );

  try { const s = read("reports_offering.json", []); s.push(rec); write("reports_offering.json", s); } catch {}
  audit(me.scjId, "SUBMIT", "report_offering", rec.id, { scjDate });
  return res.json({ ok:true, record:rec });
}

// fallback: original JSON path (keep)
const store = read("reports_offering.json", []);
if (already(store, me.scjId, scjDate)) return res.status(409).json({ error:"duplicate", details:"offering already submitted for this date" });
const rec = { id:`off_${Date.now()}`, scjId: me.scjId, scjDate, channel:String(channel).toLowerCase(), amount:amt, createdAt:new Date().toISOString() };
store.push(rec); write("reports_offering.json", store);
audit(me.scjId, "SUBMIT", "report_offering", rec.id, { scjDate });
return res.json({ ok:true, record:rec });
});

/* ------------------------------- LEADERS ------------------------------ */

// --- LEADERS PATCH START ---
// Everything below is added ONLY to make the current Leaders.jsx/api.js work,
// without changing your other app behavior.

const TYPE_FILES = {
  service: "reports_service.json",
  education: "reports_education.json",
  evangelism: "reports_evangelism.json",
  offering: "reports_offering.json",
};

function isLeader(u){
  return LEADER_ROLES.has(String(u.role||"").toUpperCase());
}
function nextRoleOf(role){
  const R = String(role||"").toUpperCase();
  if (R==="GYJN") return "JYJN";
  if (R==="JYJN") return "WEJANM";
  if (R==="WEJANM") return "NEMOBU";
  if (R==="NEMOBU") return "CHMN";
  if (R==="CHMN") return "DNGSN";
  return null;
}
function scopeFilter(me, s){
  const role = String(me.role||"").toUpperCase();
  const sameJ = (s.jyk||"").toUpperCase()===(me.jyk||"").toUpperCase();
  const sameD = (s.dept||"").toUpperCase()===(me.dept||"").toUpperCase();
  const sameC = (s.cell||"").toUpperCase()===(me.cell||"").toUpperCase();
  
  if (s.scjId === me.scjId) return true;

// GYJN: same JYK + same department + same cell
if (role === "GYJN") return sameJ && sameD && sameC;

// JYJN: same JYK + same department
if (role === "JYJN") return sameJ && sameD;

// WEJANM: department-wide across ALL JYKs
if (role === "WEJANM") return sameD;

// NEMOBU: whole church EXCEPT CHUMN and DNGSN
if (role === "NEMOBU") return s.role !== "CHUMN" && s.role !== "DNGSN";

// CHUMN: whole church EXCEPT DNGSN
if (role === "CHUMN") return s.role !== "DNGSN";

// DNGSN: sees everyone (no exceptions)
if (role === "DNGSN") return true;
if (role === "ADMIN") return true;

return false;
}
 
function buildRow(type, saint, report){
  const row = {
    id: saint.scjId,
    kind: "saint",
    name: saint.name,
    displayName: saint.name,
    status: report ? "Submitted" : "Missing",
    contact: { phone: saint.phone || "" }
  };
  if (!report) return row;

  if (type==="service") {
    const method = String(report.method || "physical").toLowerCase();
    row.service = {
      method,
      notAttended: toBool(report.notAttended),
      realization: report.realization || ""
    };
  } else if (type==="education") {
    const method = String(report.method || "physical").toLowerCase();
    row.education = {
      session: String(report.session || "ALL_SUN").toUpperCase(),
      method,
      notAttended: toBool(report.notAttended),
      realization: report.realization || ""
    };
  } else if (type==="evangelism") {
    row.evangelism = {
      participated: toBool(report.participated),
      findings: Number(report.findings)||0,
      nfp: Number(report.nfp)||0,
      rp: Number(report.rp)||0,
      bb: Number(report.bb)||0
    };
  } else if (type==="offering") {
    const amt = Number(report.amount)||0;
    row.offering = {
      notOffered: amt <= 5,
      channel: report.channel || null,
      amount: amt
    };
  }
  return row;
}
function computeTotals(type, rows){
  const t = {
    members: rows.length,
    reported: 0,
    byMethod:{ not:0 }, // used by UI for attendance calc
    // extra fields
    physical:0, online:0, other:0, notAttended:0,
    findings:0, nfp:0, rp:0, bb:0,
    amount:0, offeredCount:0, notOfferedCount:0,
    participated:0, notParticipated:0
  };
  for (const r of rows){
    if (type==="service" || type==="education"){
      const obj = r.service || r.education || {};
      const notAtt = toBool(obj.notAttended);
      const method = String(obj.method||"").toLowerCase();
      if (r.status==="Submitted" && !notAtt) {
        t.reported++;
        if (method==="physical") t.physical++;
        else if (method==="online") t.online++;
        else if (method==="other" || method) t.other++;
      } else {
        // not attended OR missing
        t.byMethod.not++; t.notAttended++;
      }
  } else if (type === "evangelism") {
  const ev = r.evangelism || {};
  const F = Number(ev.findings) || 0;
  const N = Number(ev.nfp) || 0;
  const R = Number(ev.rp) || 0;
  const B = Number(ev.bb) || 0;

  // ✅ treat any positive metric as participation
  const did = Boolean(ev.participated) || (F > 0 || N > 0 || R > 0 || B > 0);

  if (r.status === "Submitted" && did) {
    t.reported++; 
    t.participated++;
    t.findings += F;
    t.nfp      += N;
    t.rp       += R;
    t.bb       += B;
  } else {
    t.notParticipated++;
  }
}else if (type==="offering") {
      const off = r.offering || {};
      const amt = Number(off.amount)||0;
      t.amount += amt;
      if (r.status==="Submitted" && amt > 5) { t.reported++; t.offeredCount++; }
      else t.notOfferedCount++;
    }
  }
  return t;
}

// SUMMARY (shape that Leaders.jsx expects)
app.get("/api/leader/summary", auth, async (req, res) => {
  try{
    const me = req.user;
    if (!isLeader(me)) return res.status(403).json({ error: "leaders only" });

    const scjDate = String(req.query.date||"").trim();
    const type = String(req.query.type||"service").toLowerCase();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(scjDate)) return res.status(400).json({ error: "invalid date" });
    const file = TYPE_FILES[type];
    if (!file) return res.status(400).json({ error: "invalid type" });

    const wl = pool ? (await pool.query(`select * from whitelist`)).rows : read("whitelist.json", []);
    const all = Array.isArray(wl) ? wl : (wl.items||[]);
    const meProf = all.find(x => String(x.scjId)===String(me.scjId)) || { scjId: me.scjId, role: me.role, jyk: me.jyk, dept: me.dept, cell: me.cell, name: me.name||"" };

    const scope = all.filter(s => scopeFilter(meProf, {
      scjId:String(s.scjId||""),
      jyk:String(s.jyk||""),
      dept:String(s.dept||""),
      cell:String(s.cell||"")
    }));

    let reportsOnDate = [];
if (pool) {
  const { rows } = await pool.query(
    `select payload from reports 
     where type=$1 and payload->>'scjDate'=$2`,
    [type, scjDate]
  );
  reportsOnDate = rows.map(r => r.payload);
} else {
  const file = TYPE_FILES[type];
  const store = read(file, []);
  reportsOnDate = store.filter(r => String(r.scjDate)===scjDate);
}
    const byId = new Map();
    for (const r of reportsOnDate) byId.set(String(r.scjId), r);

    const rows = scope.map(s => buildRow(type, s, byId.get(String(s.scjId))));

    const totals = computeTotals(type, rows);

    // workflow + forwardTo
    const forwards = read("forwards.json", []);
    const key = `${scjDate}:${type}:${me.scjId}`;
    const wf = forwards.find(f => f.key===key) || { key, date: scjDate, type, by: me.scjId, forwardAttempts: 0, needsVerify: false, status: "Pending", returns: 0 };
    const nextRole = nextRoleOf(me.role);
    const nextLeader = nextRole
      ? all.find(p => String(p.role||"").toUpperCase()===nextRole) || null
      : null;

    res.json({
      role: String(me.role||""),
      workflow: wf,
      forwardTo: nextRole ? { role: nextRole, name: nextLeader ? nextLeader.name : "" } : {},
      totals,
      rows
    });
  } catch(e){
    console.error("summary error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// FILL MISSING (GYJN upsert on behalf of saint)
app.post("/api/leader/reports/:type", auth, (req, res) => {
  try{
    const me = req.user;
    const role = String(me.role||"").toUpperCase();
    if (role!=="GYJN" && role!=="ADMIN") return res.status(403).json({ error: "GYJN only" });

    const type = String(req.params.type||"").toLowerCase();
    const file = TYPE_FILES[type];
    if (!file) return res.status(400).json({ error: "invalid type" });

    const { scjId, scjDate } = req.body || {};
    if (!scjId) return res.status(400).json({ error: "scjId required" });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(scjDate||""))) return res.status(400).json({ error: "invalid date" });

    const store = read(file, []);

    // upsert by (scjId, scjDate)
    const idx = store.findIndex(r => String(r.scjId)===String(scjId) && String(r.scjDate)===String(scjDate));
    let rec;
    if (type==="service"){
      rec = { id: idx>=0? store[idx].id : `svc_${Date.now()}`, scjId, scjDate,
        method: String(req.body.method||"physical").toLowerCase(), notAttended: toBool(req.body.notAttended), realization: String(req.body.realization||""),
        createdAt: idx>=0? store[idx].createdAt : new Date().toISOString(), updatedAt: new Date().toISOString()
      };
    } else if (type==="education"){
      rec = { id: idx>=0? store[idx].id : `edu_${Date.now()}`, scjId, scjDate,
        session: String(req.body.session||"ALL_SUN").toUpperCase(), method: String(req.body.method||"physical").toLowerCase(),
        notAttended: toBool(req.body.notAttended), realization: String(req.body.realization||""),
        createdAt: idx>=0? store[idx].createdAt : new Date().toISOString(), updatedAt: new Date().toISOString()
      };
    } else if (type==="evangelism"){
      const part = toBool(req.body.participated);
      rec = { id: idx>=0? store[idx].id : `ev_${Date.now()}`, scjId, scjDate,
        participated: part, findings: part? Number(req.body.findings||0):0, nfp: part? Number(req.body.nfp||0):0,
        rp: part? Number(req.body.rp||0):0, bb: part? Number(req.body.bb||0):0,
        createdAt: idx>=0? store[idx].createdAt : new Date().toISOString(), updatedAt: new Date().toISOString()
      };
    } else if (type==="offering"){
      const not = toBool(req.body.notOffered);
      rec = { id: idx>=0? store[idx].id : `off_${Date.now()}`, scjId, scjDate,
        channel: not? null : String(req.body.channel||"cash").toLowerCase(),
        amount: not? 0 : Number(req.body.amount||0),
        createdAt: idx>=0? store[idx].createdAt : new Date().toISOString(), updatedAt: new Date().toISOString()
      };
    }

    if (idx>=0) store[idx] = rec; else store.push(rec);
    write(file, store);
    audit(me.scjId, "LEADER_FILL", `report_${type}`, rec.id, { scjId, scjDate });

    res.json({ ok:true, record: rec });
  } catch(e){
    console.error("leader fill error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// VERIFY
// VERIFY a report for a given date & type
app.post("/api/leader/verify/:type", auth, async (req, res) => {
  const me = req.user || {};
  const type = String(req.params.type || "").toLowerCase();

  // scjDate can come from body or query
  const scjDate = String(
    (req.body && req.body.scjDate) ||
    (req.query && req.query.scjDate) ||
    ""
  );

  if (!scjDate) return res.status(400).json({ error: "missing scjDate" });

  const key = `${scjDate}:${type}:${me.scjId}`;

  // --- DB-first path ---
  if (pool) {
    await pool.query(
      `insert into forwards (key, date, type, by_scj_id, forward_attempts, needs_verify, status, returns, note)
       values ($1,$2,$3,$4,0,false,'Verified',0,null)
       on conflict (key) do update set
         status='Verified',
         needs_verify=false,
         note=null`,
      [key, scjDate, type, me.scjId]
    );
    audit(me.scjId, "LEADER_VERIFY", "workflow", key);
    return res.json({ ok: true });
  }

  // --- JSON fallback (local/dev) ---
  const forwards = read("forwards.json", []);
  const i = forwards.findIndex(f => f.key === key);
  if (i >= 0) {
    forwards[i].status = "Verified";
    forwards[i].needsVerify = false;
    forwards[i].note = null;
  } else {
    forwards.push({
      key, date: scjDate, type, byScjId: me.scjId,
      forwardAttempts: 0, needsVerify: false, status: "Verified",
      returns: 0, note: null
    });
  }
  write("forwards.json", forwards);
  audit(me.scjId, "LEADER_VERIFY", "workflow", key);
  return res.json({ ok: true });
});

// RETURN
// RETURN a report for a given date & type (marks it as Returned + needs verify + saves note)
app.post("/api/leader/return/:type", auth, async (req, res) => {
  const me = req.user || {};
  const type = String(req.params.type || "").toLowerCase();

  const scjDate = String(
    (req.body && req.body.scjDate) ||
    (req.query && req.query.scjDate) ||
    ""
  );
  if (!scjDate) return res.status(400).json({ error: "missing scjDate" });

  const note = String((req.body && req.body.note) || "");
  const key = `${scjDate}:${type}:${me.scjId}`;

  // --- DB-first path ---
  if (pool) {
    await pool.query(
      `insert into forwards (key, date, type, by_scj_id, forward_attempts, needs_verify, status, returns, note)
       values ($1,$2,$3,$4,0,true,'Returned',1,$5)
       on conflict (key) do update set
         status='Returned',
         needs_verify=true,
         returns = coalesce(forwards.returns,0) + 1,
         note=$5`,
      [key, scjDate, type, me.scjId, note]
    );
    audit(me.scjId, "LEADER_RETURN", "workflow", key, { note });
    return res.json({ ok: true });
  }

  // --- JSON fallback (local/dev) ---
  const forwards = read("forwards.json", []);
  const i = forwards.findIndex(f => f.key === key);
  if (i >= 0) {
    forwards[i].status = "Returned";
    forwards[i].needsVerify = true;
    forwards[i].returns = (Number(forwards[i].returns) || 0) + 1;
    forwards[i].note = note;
  } else {
    forwards.push({
      key, date: scjDate, type, byScjId: me.scjId,
      forwardAttempts: 0, needsVerify: true, status: "Returned",
      returns: 1, note
    });
  }
  write("forwards.json", forwards);
  audit(me.scjId, "LEADER_RETURN", "workflow", key, { note });
  return res.json({ ok: true });
});

// FORWARD
// FORWARD a report for a given date & type (increments forward attempts, sets Pending)
app.post("/api/leader/forward/:type", auth, async (req, res) => {
  const me = req.user || {};
  const type = String(req.params.type || "").toLowerCase();

  const scjDate = String(
    (req.body && req.body.scjDate) ||
    (req.query && req.query.scjDate) ||
    ""
  );
  if (!scjDate) return res.status(400).json({ error: "missing scjDate" });

  const key = `${scjDate}:${type}:${me.scjId}`;

  // --- DB-first path ---
  if (pool) {
    await pool.query(
      `insert into forwards (key, date, type, by_scj_id, forward_attempts, needs_verify, status, returns, note)
       values ($1,$2,$3,$4,1,false,'Pending',0,null)
       on conflict (key) do update set
         forward_attempts = coalesce(forwards.forward_attempts,0) + 1,
         status='Pending',
         needs_verify=false`,
      [key, scjDate, type, me.scjId]
    );
    audit(me.scjId, "LEADER_FORWARD", "workflow", key);
    return res.json({ ok: true });
  }

  // --- JSON fallback (local/dev) ---
  const forwards = read("forwards.json", []);
  const i = forwards.findIndex(f => f.key === key);
  if (i >= 0) {
    forwards[i].forwardAttempts = (Number(forwards[i].forwardAttempts) || 0) + 1;
    forwards[i].status = "Pending";
    forwards[i].needsVerify = false;
  } else {
    forwards.push({
      key, date: scjDate, type, byScjId: me.scjId,
      forwardAttempts: 1, needsVerify: false, status: "Pending",
      returns: 0, note: null
    });
  }
  write("forwards.json", forwards);
  audit(me.scjId, "LEADER_FORWARD", "workflow", key);
  return res.json({ ok: true });
});
// --- export footer helpers (ADD ONLY) ---
function _aggForFooter(type, rows){
  const t = {
    members: rows.length,
    physical: 0, online: 0, other: 0, notAttended: 0,
    findingsSum: 0, nfpSum: 0, rpSum: 0, bbSum: 0, participated: 0, notParticipated: 0,
    amountSum: 0, offeredCount: 0
  };

  for (const r of rows){
    const svc = r.service || null;
    const edu = r.education || null;
    const evg = r.evangelism || null;
    const off = r.offering || null;

    if ((type === "service") && svc){
      if (!svc.notAttended) {
        if (svc.method === "physical") t.physical++;
        else if (svc.method === "online") t.online++;
        else if (svc.method === "other") t.other++;
      } else t.notAttended++;
    }
    if ((type === "education") && edu){
      if (!edu.notAttended) {
        if (edu.method === "physical") t.physical++;
        else if (edu.method === "online") t.online++;
        else if (edu.method === "other") t.other++;
      } else t.notAttended++;
    }
    if ((type === "evangelism") && evg){
      if (evg.participated){
        t.participated++;
        t.findingsSum += Number(evg.findings||0);
        t.nfpSum      += Number(evg.nfp||0);
        t.rpSum       += Number(evg.rp||0);
        t.bbSum       += Number(evg.bb||0);
      } else t.notParticipated++;
    }
    if ((type === "offering") && off){
      const amt = Number(off.amount||0);
      t.amountSum += amt;
      if (amt >= 5) t.offeredCount++;
    }
  }

  const pct = (n,d)=> d ? Math.round((n/d)*100) : 0;
  t.pctPhysical     = pct(t.physical, t.members);
  t.pctOnline       = pct(t.online, t.members);
  t.pctOther        = pct(t.other, t.members);
  t.pctNotAttended  = pct(t.notAttended, t.members);
  t.pctParticipated = pct(t.participated, t.members);
  t.pctOffered      = pct(t.offeredCount, t.members);
  return t;
}

function appendExportFooter(type, rows, csvString){
  const t = _aggForFooter(type, rows);
  const out = csvString.split("\n");

  // spacer
  out.push("");

  // Totals row: put numbers only where they make sense for the given type
  const totalsRow = [
    "", "", "Totals",
    (type==="service"||type==="education") ? t.physical : "",
    (type==="service"||type==="education") ? t.online   : "",
    (type==="service"||type==="education") ? t.other    : "",
    (type==="service"||type==="education") ? t.notAttended : "",
    (type==="evangelism") ? t.findingsSum : "",
    (type==="evangelism") ? t.nfpSum : "",
    (type==="evangelism") ? t.rpSum : "",
    (type==="evangelism") ? t.bbSum : "",
    "",
    (type==="offering") ? t.amountSum : ""
  ];
  out.push(totalsRow.join(","));

  // Percentages row
  const percRow = ["", "", "Percentages"];
  if (type==="service" || type==="education"){
    percRow.push(
      `${t.physical}/${t.members}=${t.pctPhysical}%`,
      `${t.online}/${t.members}=${t.pctOnline}%`,
      `${t.other}/${t.members}=${t.pctOther}%`,
      `${t.notAttended}/${t.members}=${t.pctNotAttended}%`,
      "", "", "", "", "", "" // pad to Channel + Amount cols
    );
  } else if (type==="evangelism"){
    // Show participation % in the first slot and pad others
    percRow.push(
      `Participated: ${t.participated}/${t.members}=${t.pctParticipated}%`,
      "", "", "", "", "", "", "", "", "" // pad to Channel + Amount
    );
  } else if (type==="offering"){
    // Only show offered % under Amount
    percRow.push("", "", "", "", "", "", "", "", "", "", "", `Offered≥5: ${t.offeredCount}/${t.members}=${t.pctOffered}%`);
  }
  out.push(percRow.join(","));

  return out.join("\n");
}
// EXPORT (CSV / XLSX)
// --- export helpers: totals/percentages footer ---
function aggregateForExport(type, rows){
  const t = {
    members: rows.length,
    // service/education
    physical: 0, online: 0, other: 0, notAttended: 0,
    // evangelism
    findingsSum: 0, nfpSum: 0, rpSum: 0, bbSum: 0, participated: 0, notParticipated: 0,
    // offering
    amountSum: 0, offeredCount: 0,
  };

  for (const r of rows){
    const svc = r.service || null;
    const edu = r.education || null;
    const evg = r.evangelism || null;
    const off = r.offering || null;

    if (type === "service" && svc){
      if (!svc.notAttended) {
        if (svc.method === "physical") t.physical++;
        else if (svc.method === "online") t.online++;
        else if (svc.method === "other") t.other++;
      } else {
        t.notAttended++;
      }
    }

    if (type === "education" && edu){
      if (!edu.notAttended) {
        if (edu.method === "physical") t.physical++;
        else if (edu.method === "online") t.online++;
        else if (edu.method === "other") t.other++;
      } else {
        t.notAttended++;
      }
    }

    if (type === "evangelism" && evg){
      if (evg.participated) {
        t.participated++;
        t.findingsSum += Number(evg.findings||0);
        t.nfpSum      += Number(evg.nfp||0);
        t.rpSum       += Number(evg.rp||0);
        t.bbSum       += Number(evg.bb||0);
      } else {
        t.notParticipated++;
      }
    }

    if (type === "offering" && off){
      const amt = Number(off.amount||0);
      t.amountSum += amt;
      if (amt >= 5) t.offeredCount++;
    }
  }

  // percentages (string-friendly)
  function pct(n, d){ return d ? Math.round((n/d)*100) : 0; }
  t.pctPhysical     = pct(t.physical, t.members);
  t.pctOnline       = pct(t.online, t.members);
  t.pctOther        = pct(t.other, t.members);
  t.pctNotAttended  = pct(t.notAttended, t.members);
  t.pctParticipated = pct(t.participated, t.members);
  t.pctOffered      = pct(t.offeredCount, t.members);

  return t;
}

function buildCsv(rows, type){
  const head = ["SCJ ID","Name","Status","Physical","Online","Other","NotAttended","Findings","NFP","RP","BB","Channel","Amount"];
  const lines = [head.join(",")];

  for (const r of rows){
    const svc = r.service||{};
    const edu = r.education||{};
    const evg = r.evangelism||{};
    const off = r.offering||{};
    lines.push([
      r.id,
      `"${(r.name||"").replace(/"/g,'""')}"`,
      r.status,
      // Physical/Online/Other/NotAttended (service/education only → ticks)
      ((svc.method==="physical" && !svc.notAttended) || (edu.method==="physical" && !edu.notAttended)) ? 1 : 0,
      ((svc.method==="online"   && !svc.notAttended) || (edu.method==="online"   && !edu.notAttended)) ? 1 : 0,
      ((svc.method==="other"    && !svc.notAttended) || (edu.method==="other"    && !edu.notAttended)) ? 1 : 0,
      (svc.notAttended || edu.notAttended) ? 1 : 0,
      // Evangelism numbers (0 for non-evangelism)
      Number(evg.findings||0),
      Number(evg.nfp||0),
      Number(evg.rp||0),
      Number(evg.bb||0),
      // Offering
      (off.channel||""),
      Number(off.amount||0)
    ].join(","));
  }

  // --- totals & percentages footer
  const t = aggregateForExport(type, rows);
  lines.push(""); // blank spacer

  // Totals row — put totals only where they make sense per type
  const totalsRow = [
    "", "", "Totals",
    (type==="service"||type==="education") ? t.physical : "",
    (type==="service"||type==="education") ? t.online   : "",
    (type==="service"||type==="education") ? t.other    : "",
    (type==="service"||type==="education") ? t.notAttended : "",
    (type==="evangelism") ? t.findingsSum : "",
    (type==="evangelism") ? t.nfpSum : "",
    (type==="evangelism") ? t.rpSum : "",
    (type==="evangelism") ? t.bbSum : "",
    "",
    (type==="offering") ? t.amountSum : ""
  ];
  lines.push(totalsRow.join(","));

  // Percentages row — formatted as "x/members = y%"
  const percRow = ["", "", "Percentages"];
  if (type==="service" || type==="education"){
    percRow.push(
      `${t.physical}/${t.members}=${t.pctPhysical}%`,
      `${t.online}/${t.members}=${t.pctOnline}%`,
      `${t.other}/${t.members}=${t.pctOther}%`,
      `${t.notAttended}/${t.members}=${t.pctNotAttended}%`
    );
    // Evangelism columns blank
    percRow.push("", "", "", "");
    // Channel blank
    percRow.push("");
    // Amount column blank
    percRow.push("");
  } else if (type==="evangelism"){
    // Use Physical column to show participation %, others blank except evg totals columns already above
    percRow.push(
      `Participated: ${t.participated}/${t.members}=${t.pctParticipated}%`,
      "", "", ""
    );
    // Findings/NFP/RP/BB are totals above (no percentages usually needed)
    percRow.push("", "", "", "");
    // Channel blank
    percRow.push("");
    // Amount blank
    percRow.push("");
  } else if (type==="offering"){
    // Service/Education/NotAttended/Evg metrics blank here
    percRow.push("", "", "", "", "", "", "", "");
    // Channel blank
    percRow.push("");
    // Amount column shows offering participation %
    percRow.push(`Offered≥5: ${t.offeredCount}/${t.members}=${t.pctOffered}%`);
  }
  lines.push(percRow.join(","));

  return lines.join("\n");
}

// helpers for XLSX (no deps): tiny ZIP (store only) + minimal OOXML
function crc32Buf(buf){
  let c = ~0>>>0;
  for (let i=0;i<buf.length;i++){
    c = (c>>>8) ^ CRC_TABLE[(c ^ buf[i]) & 0xff];
  }
  return (~c)>>>0;
}
const CRC_TABLE = (()=>{ // generate table once
  let c, table = new Array(256);
  for (let n=0;n<256;n++){
    c=n;
    for(let k=0;k<8;k++) c = (c&1)? (0xEDB88320 ^ (c>>>1)) : (c>>>1);
    table[n]=c>>>0;
  }
  return table;
})();
function le32(n){ const b=Buffer.alloc(4); b.writeUInt32LE(n>>>0); return b; }
function le16(n){ const b=Buffer.alloc(2); b.writeUInt16LE(n&0xFFFF); return b; }
function zipStore(files){ // [{name, data:Buffer}]
  let offset = 0;
  const localParts = [];
  const centralParts = [];
  for (const f of files){
    const nameBuf = Buffer.from(f.name, "utf8");
    const dataBuf = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, "utf8");
    const crc = crc32Buf(dataBuf);
    const localHeader = Buffer.concat([
      Buffer.from([0x50,0x4b,0x03,0x04]),      // local file header sig
      le16(20), le16(0), le16(0),              // version, flags, method=store
      le16(0), le16(0),                        // time,date (zero)
      le32(crc), le32(dataBuf.length), le32(dataBuf.length),
      le16(nameBuf.length), le16(0),           // name len, extra len
      nameBuf, dataBuf
    ]);
    localParts.push(localHeader);

    const central = Buffer.concat([
      Buffer.from([0x50,0x4b,0x01,0x02]),      // central dir header
      le16(20), le16(20), le16(0), le16(0),    // versions, method
      le16(0), le16(0),
      le32(crc), le32(dataBuf.length), le32(dataBuf.length),
      le16(nameBuf.length), le16(0), le16(0),  // name, extra, comment
      le16(0), le16(0), le32(0),               // disk, attr, ext attr
      le32(offset),
      nameBuf
    ]);
    centralParts.push(central);
    offset += localHeader.length;
  }
  const centralDir = Buffer.concat(centralParts);
  const locals = Buffer.concat(localParts);
  const end = Buffer.concat([
    Buffer.from([0x50,0x4b,0x05,0x06]),
    le16(0), le16(0),
    le16(files.length), le16(files.length),
    le32(centralDir.length),
    le32(locals.length),
    le16(0)
  ]);
  return Buffer.concat([locals, centralDir, end]);
}
function xEsc(s){ return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function sheetXmlFromRows(rows){
  // columns same as CSV
  const colsHeader = ["SCJ ID","Name","Status","Physical","Online","Other","NotAttended","Findings","NFP","RP","BB","Channel","Amount"];
  let r = 1;
  const lines = [];
  // header
  lines.push(`<row r="${r}">` + colsHeader.map((v,i)=>`<c r="${String.fromCharCode(65+i)}${r}" t="inlineStr"><is><t>${xEsc(v)}</t></is></c>`).join("") + `</row>`);
  // data
  for (const item of rows){
    r++;
    const svc = item.service||{};
    const edu = item.education||{};
    const evg = item.evangelism||{};
    const off = item.offering||{};
    const vals = [
      item.id,
      item.name||"",
      item.status||"",
      ((svc.method==="physical" && !svc.notAttended) || (edu.method==="physical" && !edu.notAttended)) ? 1 : 0,
      ((svc.method==="online"   && !svc.notAttended) || (edu.method==="online"   && !edu.notAttended)) ? 1 : 0,
      ((svc.method==="other"    && !svc.notAttended) || (edu.method==="other"    && !edu.notAttended)) ? 1 : 0,
      (svc.notAttended || edu.notAttended) ? 1 : 0,
      evg.findings||0, evg.nfp||0, evg.rp||0, evg.bb||0,
      off.channel||"", Number(off.amount||0)
    ];
    const cells = vals.map((v,i)=>{
      const col = String.fromCharCode(65+i);
      if (typeof v === "number")
        return `<c r="${col}${r}"><v>${v}</v></c>`;
      return `<c r="${col}${r}" t="inlineStr"><is><t>${xEsc(v)}</t></is></c>`;
    }).join("");
    lines.push(`<row r="${r}">${cells}</row>`);
  }
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheetData>
    ${lines.join("")}
  </sheetData>
</worksheet>`;
}
function buildXlsxBuffer(rows, sheetName="Sheet1"){
  const files = [
    { name:'[Content_Types].xml', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>` },
    { name:'_rels/.rels', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>` },
    { name:'xl/_rels/workbook.xml.rels', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>` },
    { name:'xl/workbook.xml', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="${xEsc(sheetName)}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>` },
    { name:'xl/styles.xml', data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>` },
    { name:'xl/worksheets/sheet1.xml', data: sheetXmlFromRows(rows) }
  ];
  return zipStore(files);
}

app.get("/api/leader/export.csv", auth,async (req, res) => {
  try{
    const me = req.user;
    if (!isLeader(me)) return res.status(403).json({ error: "leaders only" });

    const scjDate = String(req.query.date||"");
    const type = String(req.query.type||"service").toLowerCase();
    if (!TYPE_FILES[type]) return res.status(400).json({ error: "invalid type" });

    // reuse summary build to get rows in scope
    const wl = pool ? (await pool.query(`select * from whitelist`)).rows : read("whitelist.json", []);
    const all = Array.isArray(wl) ? wl : (wl.items||[]);
    const meProf = all.find(x => String(x.scjId)===String(me.scjId)) || me;
    const scope = all.filter(s => scopeFilter(meProf, s));
    const reports = await loadReports(type);
    let reportsOnDate = [];
if (pool) {
  const { rows } = await pool.query(
    `select payload from reports 
     where type=$1 and payload->>'scjDate'=$2`,
    [type, scjDate]
  );
  reportsOnDate = rows.map(r => r.payload);
} else {
  const store = read(TYPE_FILES[type], []);
  reportsOnDate = store.filter(r => String(r.scjDate)===scjDate);
}
    const byId = new Map(); for (const r of reportsOnDate) byId.set(String(r.scjId), r);
    const rows = scope.map(s => buildRow(type, s, byId.get(String(s.scjId))));

    const csv = buildCsv(rows, type);
    const fname = `kc_${type}_${scjDate}.csv`;
    res.setHeader("Content-Type","text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
    res.send(csv);
  } catch(e){
    res.status(500).json({ error: "export failed" });
  }
});

app.get("/api/leader/export.xlsx", auth, async (req, res) => {
  try{
    const me = req.user;
    if (!isLeader(me)) return res.status(403).json({ error: "leaders only" });

    const scjDate = String(req.query.date||"");
    const type = String(req.query.type||"service").toLowerCase();
    if (!TYPE_FILES[type]) return res.status(400).json({ error: "invalid type" });

    const wl = pool ? (await pool.query(`select * from whitelist`)).rows : read("whitelist.json", []);
    const all = Array.isArray(wl) ? wl : (wl.items||[]);
    const meProf = all.find(x => String(x.scjId)===String(me.scjId)) || me;
    const scope = all.filter(s => scopeFilter(meProf, s));
    let reportsOnDate = [];
if (pool) {
  const { rows } = await pool.query(
    `select payload from reports 
     where type=$1 and payload->>'scjDate'=$2`,
    [type, scjDate]
  );
  reportsOnDate = rows.map(r => r.payload);
} else {
  const store = read(TYPE_FILES[type], []);
  reportsOnDate = store.filter(r => String(r.scjDate)===scjDate);
}
    const byId = new Map(); for (const r of reportsOnDate) byId.set(String(r.scjId), r);
    const rows = scope.map(s => buildRow(type, s, byId.get(String(s.scjId))));

    const xbuf = buildXlsxBuffer(rows, `${type}-${scjDate}`);
    const fname = `kc_${type}_${scjDate}.xlsx`;
    res.setHeader("Content-Type","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
    res.send(xbuf);
  } catch(e){
    console.error("xlsx export error:", e);
    res.status(500).json({ error: "export failed" });
  }
});
// --- LEADERS PATCH END ---

/* --------------------------- EVANGELISM MEDIA ------------------------- */

// list my JYK (saints see their JYK; you can extend server-side policy later)
app.get("/api/media/jyk", auth, async (req, res) => {
  const me = req.user || {};
  const jyk = String(me.jyk || "");
  if (pool) {
    const { rows } = await pool.query(
      `select * from media where jyk=$1 order by ts desc`, [jyk]
    );
    return res.json(rows);
  }
  const all = read("media.json", []);
  const list = all.filter(x => String(x.jyk) === jyk);
  res.json(list);
});
// JSON URL add (legacy)
app.post("/api/media", auth, async (req, res) => {
  const { type = "image", url = "", sizeBytes = 0 } = req.body || {};
  if (!url.trim()) return res.status(400).json({ error: "url required" });
  const me = req.user || {};
  const rec = {
    id: `m_${Date.now()}`,
    scjId: me.scjId, name: me.name || "", jyk: me.jyk || "",
    type: String(type).toLowerCase(),
    url: String(url),
    title: "", caption: "", sizeBytes: Number(sizeBytes)||0,
    ts: new Date().toISOString()
  };

  if (pool) {
    await pool.query(
      `insert into media (id, scj_id, name, jyk, type, url, title, caption, size_bytes, ts)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [rec.id, rec.scjId, rec.name, rec.jyk, rec.type, rec.url, rec.title, rec.caption, rec.sizeBytes, rec.ts]
    );
    audit(me.scjId, "MEDIA_ADD_URL", "media", rec.id);
    return res.json({ ok: true, record: rec });
  }

  const items = read("media.json", []);
  items.unshift(rec); write("media.json", items);
  audit(me.scjId, "MEDIA_ADD_URL", "media", rec.id);
  res.json({ ok: true, record: rec });
});

// multipart upload
app.post("/api/media/upload", auth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "File missing" });
  const me = req.user || {};
  const mime = String(req.file.mimetype || "");
  const typ = mime.startsWith("video") ? "video" : "image";

  const rec = {
    id: `m_${Date.now()}`,
    scjId: me.scjId, name: me.name || "", jyk: me.jyk || "",
    type: typ,
    url: `uploads/${req.file.filename}`,
    title: "", caption: "", sizeBytes: Number(req.file.size)||0,
    ts: new Date().toISOString()
  };

  if (pool) {
    await pool.query(
      `insert into media (id, scj_id, name, jyk, type, url, title, caption, size_bytes, ts)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [rec.id, rec.scjId, rec.name, rec.jyk, rec.type, rec.url, rec.title, rec.caption, rec.sizeBytes, rec.ts]
    );
    audit(me.scjId, "MEDIA_UPLOAD", "media", rec.id, { file: rec.url });
    return res.json({ ok: true, record: rec });
  }

  const items = read("media.json", []);
  items.unshift(rec); write("media.json", items);
  audit(me.scjId, "MEDIA_UPLOAD", "media", rec.id, { file: rec.url });
  res.json({ ok: true, record: rec });
});

// optional edit (owner only)
app.post("/api/media/update", auth, async (req, res) => {
  const { id, title = "", caption = "" } = req.body || {};
  if (!id) return res.status(400).json({ error: "id required" });
  const me = req.user || {};

  if (pool) {
    const r = await pool.query(
      `update media set title=$1, caption=$2 where id=$3 and scj_id=$4 returning *`,
      [String(title||""), String(caption||""), id, String(me.scjId)]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: "not found/owner only" });
    audit(me.scjId, "MEDIA_EDIT", "media", id);
    return res.json({ ok: true, record: r.rows[0] });
  }

  const items = read("media.json", []);
  const idx = items.findIndex(x => x.id === id);
  if (idx < 0) return res.status(404).json({ error: "not found" });
  if (String(items[idx].scjId) !== String(me.scjId)) return res.status(403).json({ error: "owner only" });
  items[idx].title = String(title || "");
  items[idx].caption = String(caption || "");
  write("media.json", items);
  audit(me.scjId, "MEDIA_EDIT", "media", id);
  res.json({ ok: true, record: items[idx] });
});

// delete (owner only)
app.post("/api/media/delete", auth, async (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: "id required" });
  const me = req.user || {};

  if (pool) {
    // get item to know the url for disk cleanup
    const { rows } = await pool.query(
      `select * from media where id=$1 and scj_id=$2`, [id, String(me.scjId)]
    );
    if (rows.length === 0) return res.status(404).json({ error: "not found/owner only" });
    const item = rows[0];

    // delete DB row
    await pool.query(`delete from media where id=$1 and scj_id=$2`, [id, String(me.scjId)]);

    // remove disk file if it's a local upload
    const url = String(item.url || "");
    if (url.startsWith("uploads/")) {
      const abs = path.join(DATA_DIR, url);
      try { if (fs.existsSync(abs)) fs.unlinkSync(abs); } catch {}
    }

    audit(me.scjId, "MEDIA_DELETE", "media", id);
    return res.json({ ok: true });
  }

  // JSON fallback
  const items = read("media.json", []);
  const idx = items.findIndex(x => x.id === id);
  if (idx < 0) return res.status(404).json({ error: "not found" });
  if (String(items[idx].scjId) !== String(me.scjId)) return res.status(403).json({ error: "owner only" });
  const url = String(items[idx].url || "");
  if (url.startsWith("uploads/")) {
    const abs = path.join(DATA_DIR, url);
    try { if (fs.existsSync(abs)) fs.unlinkSync(abs); } catch {}
  }
  items.splice(idx, 1); write("media.json", items);
  audit(me.scjId, "MEDIA_DELETE", "media", id);
  res.json({ ok: true });
});

/* ------------------------------ PUBLIC SUPPORT ------------------------------ */
// Saints (no auth) can open a support ticket (forgot password / can't create account / other)
app.post("/api/support/request", async (req, res) => {
  try {
    const { name="", scjId="", phone="", jyk="", dept="", cell="", type="help", details="" } = req.body || {};
    if (!name.trim() || !scjId.trim() || !phone.trim() || !jyk.trim() || !dept.trim() || !cell.trim()) {
      return res.status(400).json({ error: "All fields are required: name, scjId, phone, jyk, dept, cell" });
    }

    const rec = {
      id: `sup_${Date.now()}`,
      type, name, scjId, phone, jyk, dept, cell,
      details: details || "",
      status: "Open",
      ts: new Date().toISOString()
    };

    if (pool) {
      await pool.query(
        `insert into support_inbox (id, type, name, scj_id, phone, jyk, dept, cell, details, status, ts)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [rec.id, rec.type, rec.name, rec.scjId, rec.phone, rec.jyk, rec.dept, rec.cell, rec.details, rec.status, rec.ts]
      );
      return res.json({ ok: true, ticket: rec });
    }

    const inbox = read("support_inbox.json", []);
    inbox.unshift(rec);
    write("support_inbox.json", inbox);
    res.json({ ok: true, ticket: rec });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

/* --------------------------------- ADMIN ------------------------------ */

// Whitelist upsert (create/update)
app.post("/api/admin/whitelist/upsert", auth, (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });
  const entry = req.body || {};
  if (!entry.scjId || !entry.name) return res.status(400).json({ error: "scjId & name required" });
  const wl = read("whitelist.json", []);
  const idx = wl.findIndex(w => String(w.scjId) === String(entry.scjId));
  if (idx >= 0) wl[idx] = { ...wl[idx], ...entry };
  else wl.push(entry);
  write("whitelist.json", wl);
  audit(req.user.scjId, "WL_UPSERT", "whitelist", entry.scjId);
  res.json({ ok: true, entry });
});

// Set role on an account (and whitelist role)
app.post("/api/admin/account/role", auth, (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });
  const { scjId, role } = req.body || {};
  const R = String(role || "").toUpperCase();
  if (!ROLES.has(R)) return res.status(400).json({ error: "invalid role" });

  const wl = read("whitelist.json", []);
  const widx = wl.findIndex(w => String(w.scjId) === String(scjId));
  if (widx < 0) return res.status(404).json({ error: "not in whitelist" });
  wl[widx].role = R; write("whitelist.json", wl);

  audit(req.user.scjId, "ROLE_SET", "whitelist", scjId, { role: R });
  res.json({ ok: true });
});

// Public Support intake (Sign-in/Sign-up help)
app.post("/api/support", async (req, res) => {
  try {
    const { name="", scjId="", phone="", jyk="", dept="", cell="", type="login_help", details="" } = req.body || {};
    if (!name || !scjId || !phone || !jyk || !dept || !cell) {
      return res.status(400).json({ error: "name, scjId, phone, jyk, dept, cell are required" });
    }

    const box = read("support_inbox.json", []);
    const rec = {
      id: `sup_${Date.now()}`,
      type: String(type || "login_help"),
      name: String(name), scjId: String(scjId), phone: String(phone),
      jyk: String(jyk), dept: String(dept), cell: String(cell),
      details: String(details || ""),
      status: "Open",
      ts: new Date().toISOString(),
    };
    box.unshift(rec);
    write("support_inbox.json", box);
    audit(scjId, "SUPPORT_CREATE", "support", rec.id, { type: rec.type });
    res.json({ ok: true, ticket: rec });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});
// Support inbox (help from signup/login)
app.get("/api/admin/support/inbox", auth, async (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });

  if (pool) {
    const { rows } = await pool.query(
      `select * from support_inbox order by ts desc`
    );
    return res.json({ items: rows });
  }

  const list = cleanupSupportInbox(); // JSON fallback
  res.json({ items: list });
});
// Update support ticket status: "Pending" | "Resolved"
app.post("/api/admin/support/status", auth, async (req, res) => {
  const { id, status } = req.body || {};
  if (!id) return res.status(400).json({ error: "missing id" });
  const S = String(status || "Pending");

  try {
    if (pool) {
      const { rowCount } = await pool.query(
        `update support_inbox set status=$1, resolved_at = case when $1='Resolved' then now() else null end
         where id=$2`,
        [S, id]
      );
      if (!rowCount) return res.status(404).json({ error: "not found" });
      audit(req.user.scjId, "SUPPORT_STATUS", "support", id, { status:S });
      return res.json({ ok:true });
    } else {
      const list = read("support_inbox.json", []);
      const i = list.findIndex(x => x.id === id);
      if (i < 0) return res.status(404).json({ error: "not found" });
      list[i].status = S;
      if (S === "Resolved") list[i].resolvedAt = new Date().toISOString();
      write("support_inbox.json", list);
      audit(req.user.scjId, "SUPPORT_STATUS", "support", id, { status:S });
      return res.json({ ok:true });
    }
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

  const list = read("support_inbox.json", []);
  const i = list.findIndex(x => x.id === id);
  if (i < 0) return res.status(404).json({ error: "not found" });
  list[i].status = S;
  if (S === "Resolved") list[i].resolvedAt = new Date().toISOString();
  write("support_inbox.json", list);
  audit(req.user.scjId, "SUPPORT_STATUS", "support", id, { status:S });
  res.json({ ok:true });

// Delete a support ticket now (manual)
app.post("/api/admin/support/delete", auth, async (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: "missing id" });

  try {
    if (pool) {
      const { rows } = await pool.query(
        `delete from support_inbox where id=$1 returning type`, [id]
      );
      if (rows.length === 0) return res.status(404).json({ error: "not found" });
      audit(req.user.scjId, "SUPPORT_DELETE", "support", id, { type: rows[0]?.type });
      return res.json({ ok:true });
    } else {
      const list = read("support_inbox.json", []);
      const i = list.findIndex(x => x.id === id);
      if (i < 0) return res.status(404).json({ error: "not found" });
      const [removed] = list.splice(i, 1);
      write("support_inbox.json", list);
      audit(req.user.scjId, "SUPPORT_DELETE", "support", id, { type: removed?.type });
      return res.json({ ok:true });
    }
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

app.post("/api/admin/support/override", auth,async (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });
  const { scjId, name, phone, jyk, dept, cell, role = "SAINT" } = req.body || {};
  const action = String((req.body||{}).action || "");
  if (!scjId || !name) return res.status(400).json({ error: "scjId & name required" });

  
  // whitelist upsert (DB-first)
if (pool) {
  await pool.query(
    `insert into whitelist (scj_id, name, phone, jyk, dept, cell, role)
     values ($1,$2,$3,$4,$5,$6,$7)
     on conflict (scj_id) do update set
       name = excluded.name,
       phone = excluded.phone,
       jyk = excluded.jyk,
       dept = excluded.dept,
       cell = excluded.cell,
       role = excluded.role`,
    [scjId, name, phone, jyk, dept, cell, String(role).toUpperCase()]
  );
} else {
  const wl = read("whitelist.json", []);
  const idx = wl.findIndex(w => String(w.scjId) === String(scjId));
  const entry = { scjId, name, phone, jyk, dept, cell, role: String(role).toUpperCase() };
  if (idx >= 0) wl[idx] = { ...wl[idx], ...entry }; else wl.push(entry);
  write("whitelist.json", wl);
}

// Optional: force-reset to 0000
if (String((req.body||{}).action || "") === "reset_password") {
  const hash = bcrypt.hashSync("0000", 10);
  if (pool) {
    await pool.query(
      `insert into accounts (id, scj_id, password_hash, password_reset_at)
       values ($1,$2,$3, now())
       on conflict (scj_id) do update set password_hash = excluded.password_hash, password_reset_at = now()`,
      [`acc_${Date.now()}`, scjId, hash]
    );
  } else {
    const accounts = read("accounts.json", []);
    const i = accounts.findIndex(a => a.scjId === scjId);
    if (i >= 0) accounts[i].passwordHash = hash;
    else accounts.push({ id: `acc_${Date.now()}`, scjId, passwordHash: hash });
    write("accounts.json", accounts);
  }
}

// ensure account exists (default 0000 if missing)
if (pool) {
  await pool.query(
    `insert into accounts (id, scj_id, password_hash)
     values ($1,$2,$3)
     on conflict (scj_id) do nothing`,
    [`acc_${Date.now()}`, scjId, bcrypt.hashSync("0000", 10)]
  );
} else {
  const accounts = read("accounts.json", []);
  if (!accounts.some(a => a.scjId === scjId)) {
    accounts.push({ id: `acc_${Date.now()}`, scjId, passwordHash: bcrypt.hashSync("0000", 10) });
    write("accounts.json", accounts);
  }
}

  audit(req.user.scjId, "SUPPORT_OVERRIDE", "whitelist", scjId);
  res.json({ ok: true, entry });
});

// Feature flags
app.get("/api/admin/flags", auth, async (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });

  if (pool) {
    const { rows } = await pool.query(`select name, value from flags`);
    const out = {};
    for (const r of rows) out[r.name] = r.value;
    return res.json(out);
  }
  return res.json(read("flags.json", {})); // JSON fallback
});
app.post("/api/admin/flags", auth, async (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });

  const updates = req.body || {};
  if (pool) {
    const names = Object.keys(updates);
    for (const name of names) {
      await pool.query(
        `insert into flags (name, value) values ($1,$2)
         on conflict (name) do update set value=excluded.value`,
        [name, JSON.stringify(updates[name])]
      );
    }
    audit(req.user.scjId, "FLAGS_SET", "flags", "-", updates);
    // return merged current flags
    const { rows } = await pool.query(`select name, value from flags`);
    const out = {}; for (const r of rows) out[r.name] = r.value;
    return res.json({ ok:true, flags: out });
  }

  // JSON fallback
  const flags = { ...read("flags.json", {}), ...updates };
  write("flags.json", flags);
  audit(req.user.scjId, "FLAGS_SET", "flags", "-", updates);
  res.json({ ok: true, flags });
});

// Audit list
app.get("/api/admin/audit", auth, async (req, res) => {
  if (String(req.user.role || "").toUpperCase() !== "ADMIN")
    return res.status(403).json({ error: "admin only" });
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit) || 100));

  if (pool) {
    const { rows } = await pool.query(
      `select ts, actor_scj_id, action, entity, entity_id, meta
       from audit
       order by ts desc
       limit $1`, [limit]
    );
    return res.json(rows);
  }

  const log = read("audit.json", []);
  return res.json(log.slice(0, limit));
});

// TEMP ADMIN RESET: POST /api/admin/force-reset
// body: { scjId: "0009-006", newPassword: "0000" }
app.post("/api/admin/force-reset", async (req, res) => {
  try {
    const { scjId, newPassword = "0000" } = req.body || {};
    if (!scjId) return res.status(400).json({ error: "scjId required" });

    const hash = bcrypt.hashSync(String(newPassword), 10);

if (pool) {
  const { rowCount } = await pool.query(
    `update accounts set password_hash=$1, password_reset_at=now()
     where scj_id=$2`,
    [hash, scjId]
  );
  if (rowCount === 0) {
    // create if missing
    await pool.query(
      `insert into accounts (id, scj_id, password_hash, password_reset_at)
       values ($1,$2,$3, now())`,
      [`acc_${Date.now()}`, scjId, hash]
    );
  }

  // optional: ensure whitelist entry exists (return warn if missing)
  const { rows: wrows } = await pool.query(`select 1 from whitelist where scj_id=$1`, [scjId]);
  if (wrows.length === 0) {
    return res.status(409).json({
      ok: false,
      warn: "Password reset, but whitelist entry missing for this scjId."
    });
  }
} else {
  const accounts = read("accounts.json", []);
  const acc = accounts.find(a => a.scjId === scjId);
  if (!acc) {
    accounts.push({ id: `acc_${Date.now()}`, scjId, passwordHash: hash });
  } else {
    acc.passwordHash = hash;
    acc.passwordResetAt = new Date().toISOString();
  }
  write("accounts.json", accounts);

  const wl = read("whitelist.json", []);
  if (!wl.find(w => w.scjId === scjId)) {
    return res.status(409).json({ ok:false, warn:"Password reset, but whitelist entry missing for this scjId." });
  }
}

return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: "server error", details: e.message });
  }
});
/* -------------------- Meta lists for UI -------------------- */
app.get("/api/meta/jyks",async (req, res) => {
  const wl = pool ? (await pool.query(`select * from whitelist`)).rows : read("whitelist.json", []);
  const set = new Set();
  for (const w of wl) {
    const v = String(w.jyk || "").trim();
    if (v) set.add(v);
  }
  res.json({ items: Array.from(set).sort((a,b)=>a.localeCompare(b)) });
});

app.get("/api/meta/departments", (req, res) => {
  // Your requested fixed list:
  res.json({ items: ["MEN", "YOUNG ADULTS", "WOMEN"] });
});
// Save a report
app.post('/api/reports', async (req, res) => {
  try {
    const { scjId, type, payload } = req.body || {};
    await pool.query(
      'INSERT INTO reports (scj_id, type, payload) VALUES ($1, $2, $3)',
      [scjId, type, payload || {}]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("Insert error:", e);
    res.status(500).json({ ok: false, error: "Failed to save report" });
  }
});

// List reports
app.get('/api/reports', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM reports ORDER BY created_at DESC LIMIT 200'
    );
    res.json(rows);
  } catch (e) {
    console.error("Fetch error:", e);
    res.status(500).json({ ok: false, error: "Failed to fetch reports" });
  }
});

app.post('/api/reports', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'DB not configured' });
  const { scjId, type, payload } = req.body || {};
  await pool.query(
    'INSERT INTO reports (scj_id, type, payload) VALUES ($1,$2,$3)',
    [scjId, type, payload || {}]
  );
  res.json({ ok: true });
});

app.get('/api/reports', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'DB not configured' });
  const { rows } = await pool.query('SELECT * FROM reports ORDER BY created_at DESC LIMIT 200');
  res.json(rows);
});

/* -------------------------------- SERVER ------------------------------ */

app.get("/", (_req, res) => res.send("KC backend running"));
// --- helpers used by password & recovery routes (place above app.listen) ---
// Verifies the user's current password against accounts.json.
// Also supports migrating any legacy plain "password" fields to bcrypt hash.
// Verifies the user's current password (DB-first), falls back to JSON locally.
async function compareAndMaybeMigratePassword(jwtUser, currentPlain) {
  const cur = String(currentPlain || "");

  if (pool) {
    // Look up by scj_id first, fall back to id
    const { rows } = await pool.query(
      `select * from accounts where scj_id = $1 or id = $2 limit 1`,
      [String(jwtUser.scjId || ""), String(jwtUser.id || "")]
    );
    if (rows.length === 0) return { ok: false };

    const acc = rows[0];
    if (!acc.password_hash) return { ok: false };
    const ok = bcrypt.compareSync(cur, acc.password_hash);
    return { ok, account: { id: acc.id, scjId: acc.scj_id } };
  }

  // ---- JSON fallback (dev/local) ----
  const accounts = read("accounts.json", []);
  const idx = accounts.findIndex(a =>
    String(a.id) === String(jwtUser.id) || String(a.scjId) === String(jwtUser.scjId)
  );
  if (idx < 0) return { ok: false };

  let acc = accounts[idx];

  // Legacy one-time migration for plain password -> hash
  if (acc.password && !acc.passwordHash) {
    if (String(acc.password) !== cur) return { ok: false };
    acc.passwordHash = bcrypt.hashSync(acc.password, 10);
    delete acc.password;
    accounts[idx] = acc;
    write("accounts.json", accounts);
    return { ok: true, account: acc };
  }

  if (!acc.passwordHash) return { ok: false };
  const ok = bcrypt.compareSync(cur, acc.passwordHash);
  return { ok, account: acc };
}

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ ok: true, status: "Backend is running" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT,'0.0.0.0', () => {
  console.log(`KC backend listening on port ${PORT}`);
});