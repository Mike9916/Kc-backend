// routes/auth.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const router = express.Router();

// --- Config ---
const JWT_SECRET = String(process.env.JWT_SECRET);

// --- Data loading (same logic you had) ---
const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const ACCOUNTS_PATHS = [process.env.ACCOUNTS_PATH, path.join(DATA_DIR, 'accounts.json'), path.join(ROOT, 'accounts.json')].filter(Boolean);
const WHITELIST_PATHS = [process.env.WHITELIST_PATH, path.join(DATA_DIR, 'whitelist.json'), path.join(ROOT, 'whitelist.json')].filter(Boolean);

function safeReadArray(prefs){
  for (const p of prefs){
    try {
      if (p && fs.existsSync(p)) {
        const raw = fs.readFileSync(p, 'utf8');
        const data = JSON.parse((raw ?? '').trim() || '[]');
        if (Array.isArray(data)) return data;
      }
    } catch {}
  }
  return [];
}

const DUMMY_HASH = '$2a$10$z7qIYbN5nA6h1cM1wqBqUe0G3rJ8f/7XnV4qk1lYFZf6q7kRr6xXO';
const tscmp = (a = '', b = '') => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

function normalizeId(x) { return String(x || '').trim().normalize('NFKC').toUpperCase(); }

// --- POST /api/auth/login-json ---
router.post('/login-json', async (req, res) => {
  try {
    const { scjId, password } = req.body || {};
    if (typeof scjId !== 'string' || typeof password !== 'string' || !scjId.trim()) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const want = normalizeId(scjId);
    const passN = String(password).normalize('NFKC');

    const accounts = safeReadArray(ACCOUNTS_PATHS);
    const whitelist = safeReadArray(WHITELIST_PATHS);

    // strict first
    let acc = accounts.find(a => a && typeof a.scjId === 'string' && tscmp(normalizeId(a.scjId), want));
    let profile = whitelist.find(w => w && typeof w.scjId === 'string' && tscmp(normalizeId(w.scjId), want));

    // relaxed (if data files aren’t normalized)
    acc ||= accounts.find(a => normalizeId(a?.scjId) === want);
    profile ||= whitelist.find(w => normalizeId(w?.scjId) === want);

    const hash = (acc && typeof acc.passwordHash === 'string') ? acc.passwordHash : DUMMY_HASH;
    let ok = false;
    try { ok = await bcrypt.compare(passN, String(hash)); } catch { ok = false; }

    if (!acc || !profile || !ok) return res.status(401).json({ error: 'Invalid credentials' });
    if (acc.isSuspended || acc.deletedAt) return res.status(403).json({ error: 'Account restricted' });

    const token = jwt.sign({
      id: acc.id, scjId: acc.scjId || want,
      role: String(profile.role || 'SAINT'),
      name: profile.name || '', jyk: profile.jyk || '',
      dept: profile.dept || '', cell: profile.cell || ''
    }, JWT_SECRET, { expiresIn: '10h' });

    return res.json({ token, profile });
  } catch {
    return res.status(400).json({ error: 'Invalid request' });
  }
});

// --- GET /api/auth/me ---
router.get('/me', (req, res) => {
  const raw = String(req.headers.authorization || '');
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  if (!m) return res.status(401).json({ error: 'missing token' });
  try {
    const user = jwt.verify(m[1], JWT_SECRET);
    res.json({ ok: true, user, profile: user });
  } catch (e) {
    res.status(401).json({ error: 'invalid token', details: e.message });
  }
});

module.exports = router;