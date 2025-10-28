// routes/admin.js
module.exports = (app, { read, write, auth }) => {
  function isAdmin(req){ return String(req.user?.role||"").toUpperCase()==="ADMIN"; }

  app.post("/api/admin/whitelist/upsert", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    const { scjId, name, phone, jyk, dept, cell, role } = req.body||{};
    if(!scjId || !name) return res.status(400).json({ error:"scjId & name required" });
    const wl = read("whitelist.json", []); const arr = Array.isArray(wl)?wl:(wl.items||[]);
    const i = arr.findIndex(x=>x.scjId===scjId);
    const rec = { scjId, name, phone, jyk, dept, cell, role: role||"SAINT" };
    if(i>=0) arr[i] = { ...arr[i], ...rec }; else arr.push(rec);
    write("whitelist.json", arr); res.json({ ok:true, record:rec });
  });

  app.post("/api/admin/account/role", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    const { scjId, role } = req.body||{}; if(!scjId||!role) return res.status(400).json({ error:"scjId & role required" });
    const wl = read("whitelist.json", []); const arr = Array.isArray(wl)?wl:(wl.items||[]);
    const i = arr.findIndex(x=>x.scjId===scjId); if(i<0) return res.status(404).json({ error:"not in whitelist" });
    arr[i].role = role; write("whitelist.json", arr); res.json({ ok:true, record:arr[i] });
  });

  app.get("/api/admin/support/inbox", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    res.json({ items: read("support_inbox.json", []) });
  });

  app.post("/api/admin/support/override", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    const { name, scjId, phone, jyk, dept, cell, role } = req.body||{};
    const wl = read("whitelist.json", []); const arr = Array.isArray(wl)?wl:(wl.items||[]);
    const i = arr.findIndex(x=>x.scjId===scjId);
    const rec = { scjId, name, phone, jyk, dept, cell, role: role||"SAINT" };
    if(i>=0) arr[i]={...arr[i],...rec}; else arr.push(rec);
    write("whitelist.json", arr);
    res.json({ ok:true, record: rec, note: "User can now create/login." });
  });

  app.get("/api/admin/flags", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    res.json( read("flags.json", {}) );
  });
  app.post("/api/admin/flags", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    write("flags.json", req.body||{}); res.json({ ok:true });
  });

  app.get("/api/admin/audit", auth, (req,res)=>{
    if(!isAdmin(req)) return res.status(403).json({ error:"admin only" });
    const lim = Number(req.query.limit)||200;
    const arr = read("audit.json", []);
    res.json({ items: arr.slice(-lim) });
  });
};