// routes/auth_login.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = (app, { read }) => {
  const JWT_SECRET = process.env.JWT_SECRET || "devsecret_kcapp";
  function tokenFor(acc, profile) {
    const payload = {
      id: acc.id, scjId: acc.scjId,
      role: String(profile?.role || "SAINT"),
      name: profile?.name || "", jyk: profile?.jyk || "", dept: profile?.dept || "", cell: profile?.cell || "",
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "10h" });
  }

  app.post("/api/auth/login-json", (req, res) => {
    const { scjId, password } = req.body || {};
    const accounts = read("accounts.json", []);
    const wl = read("whitelist.json", []);
    const whitelist = Array.isArray(wl) ? wl : (wl.items || []);
    const acc = accounts.find(a => a.scjId === scjId);
    const profile = whitelist.find(w => w.scjId === scjId);
    if (!acc || !profile) return res.status(401).json({ error: "Invalid credentials" });
    if (!bcrypt.compareSync(String(password||""), acc.passwordHash)) return res.status(401).json({ error: "Invalid credentials" });
    const token = tokenFor(acc, profile);
    res.json({ token, profile });
  });

  app.get("/api/me", (req, res) => {
    const raw = String(req.headers.authorization || "");
    const m = /^Bearer\s+(.+)$/i.exec(raw);
    if (!m) return res.status(401).json({ error: "missing token" });
    try {
      const user = jwt.verify(m[1], JWT_SECRET);
      res.json({ ok: true, user, profile: user });
    } catch (e) {
      res.status(401).json({ error: "invalid token", details: e.message });
    }
  });
};