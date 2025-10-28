// routes/auth_login_json.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const router = express.Router();

// ----- Resolve data files safely (prefers ./data/*.json like your app) -----
const ROOT = path.resolve(__dirname, '..');         // project root
const DATA_DIR = path.join(ROOT, 'data');
const ACCOUNTS_PATHS = [
  process.env.ACCOUNTS_PATH,
  path.join(DATA_DIR, 'accounts.json'),
  path.join(ROOT, 'accounts.json')
].filter(Boolean);

const WHITELIST_PATHS = [
  process.env.WHITELIST_PATH,
  path.join(DATA_DIR, 'whitelist.json'),
  path.join(ROOT, 'whitelist.json')
].filter(Boolean);

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

// Dummy hash to prevent user-existence timing leaks
const DUMMY_HASH = '$2a$10$z7qIYbN5nA6h1cM1wqBqUe0G3rJ8f/7XnV4qk1lYFZf6q7kRr6xXO';

// Constant-time equality for scjId checks
const tscmp = (a = '', b = '') =>
  a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Keep JWT compatible with your existing auth middleware
const JWT_SECRET = (process.env.JWT_SECRET && String(process.env.JWT_SECRET).trim()) || 'dev_secret_change_me';

// POST /api/auth/login-json  (mounted under /api/auth)
router.post('/login-json', async (req, res) => {
  try {
    const { scjId, password } = req.body || {};
    const debug = req.query && req.query.debug === '1';

    // 1) Input validation
    if (typeof scjId !== 'string' || typeof password !== 'string' || !scjId.trim()) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const want = scjId.trim();

    // 2) Load stores safely (no 500 on JSON issues)
    const accounts = safeReadArray(ACCOUNTS_PATHS);
    const whitelist = safeReadArray(WHITELIST_PATHS);

    // 3) Find account & profile (strict → relaxed)
    let acc = accounts.find(a => a && typeof a.scjId === 'string' && tscmp(a.scjId, want));
    let profile = whitelist.find(w => w && typeof w.scjId === 'string' && tscmp(w.scjId, want));

    if (!acc || !profile) {
      const lwant = want.toLowerCase();
      acc ||= accounts.find(a => a && String(a.scjId ?? '').trim().toLowerCase() === lwant);
      profile ||= whitelist.find(w => w && String(w.scjId ?? '').trim().toLowerCase() === lwant);
    }

    // 4) Always do a bcrypt compare on some hash (removes timing leaks)
    const hash = (acc && typeof acc.passwordHash === 'string') ? acc.passwordHash : DUMMY_HASH;
    let passwordOk = false;
    try {
      passwordOk = await require('bcryptjs').compare(String(password), String(hash));
    } catch { passwordOk = false; }

    if (!acc || !profile || !passwordOk) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 5) Optional account flags
    if (acc.isSuspended || acc.deletedAt) {
      return res.status(403).json({ error: 'Account restricted' });
    }

    // 6) Sign JWT (compatible with your /api/me auth verifier)
    let token;
    try {
      token = jwt.sign(
        {
          id: acc.id,
          scjId: acc.scjId || want,
          role: profile.role || 'SAINT',
          name: profile.name || '',
          jyk: profile.jyk || '',
          dept: profile.dept || '',
          cell: profile.cell || ''
        },
        JWT_SECRET,
        { expiresIn: '2h' }
      );
    } catch {
      // treat JWT signer issues as service unavailable, not 500
      return res.status(503).json({ error: 'Auth service unavailable' });
    }

    // 7) Return same shape your frontend expects
    return res.json({ token, profile });
  } catch {
    // absolutely no unhandled 500
    return res.status(400).json({ error: 'Invalid request' });
  }
});

module.exports = router;