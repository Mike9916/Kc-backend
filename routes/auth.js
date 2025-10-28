// routes/auth.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = (app, { read, write }) => {
  const JWT_SECRET = process.env.JWT_SECRET || "devsecret_kcapp";
  function tokenFor(acc, profile) {
    const payload = { id: acc.id, scjId: acc.scjId, role: String(profile?.role||"SAINT"), name: profile?.name||"", jyk: profile?.jyk||"", dept: profile?.dept||"", cell: profile?.cell||"" };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "10h" });
  }

  app.post("/api/auth/signup", (req, res) => {
    const { scjId, name, phone, jyk, dept, cell, password } = req.body || {};
    if (!scjId || !name || !password) return res.status(400).json({ error: "SCJ ID, Full Name and Password are required" });

    const wl = read("whitelist.json", []);
    const whitelist = Array.isArray(wl) ? wl : (wl.items || []);
    const clean = (s)=>String(s||"").toLowerCase().replace(/\s+/g," ").trim();
    const profile = whitelist.find(w => String(w.scjId)===String(scjId));
    if (!profile) return res.status(403).json({ error: "Not found in whitelist. Use Help." });
    if (clean(profile.name) !== clean(name)) return res.status(403).json({ error: "Name does not match whitelist record." });

    const accounts = read("accounts.json", []);
    if (accounts.some(a => a.scjId === scjId)) return res.status(409).json({ error: "Account already exists. Please log in." });

    const acc = { id: "acc_"+Date.now(), scjId, passwordHash: bcrypt.hashSync(String(password),10), createdAt: new Date().toISOString() };
    accounts.push(acc); write("accounts.json", accounts);

    if (phone) profile.phone = phone; if (jyk) profile.jyk = jyk; if (dept) profile.dept = dept; if (cell) profile.cell = cell;

    const token = tokenFor(acc, profile);
    res.json({ ok:true, token, profile });
  });
};