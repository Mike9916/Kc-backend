// routes/support.js
module.exports = (app, { read, write }) => {
  const FILE = "support_inbox.json";
  app.post("/api/support/account/help", (req, res) => {
    const { name, scjId, phone, details } = req.body || {};
    if (!name || !scjId) return res.status(400).json({ error: "Name and SCJ ID are required." });
    const inbox = read(FILE, []);
    const rec = { id:"help_"+Date.now(), type:"account_help", name, scjId, phone: String(phone||""), details: String(details||""), status:"OPEN", createdAt: new Date().toISOString() };
    inbox.push(rec); write(FILE, inbox); res.json({ ok:true, ticket:rec });
  });
};