// routes/media.js
module.exports = (app, { read, write, auth }) => {
  app.get("/api/media", auth, (req, res) => {
    const arr = read("media.json", []);
    res.json({ items: arr });
  });
  app.post("/api/media", auth, (req, res) => {
    const { url, type, size } = req.body || {};
    if (!url) return res.status(400).json({ error: "url required" });
    if (!["image","video"].includes(String(type||""))) return res.status(400).json({ error: "invalid type" });
    const sz = Number(size)||0;
    if (type==="image" && sz>15*1024*1024) return res.status(400).json({ error: "image too large (>15MB)" });
    if (type==="video" && sz>1024*1024*1024) return res.status(400).json({ error: "video too large (>1GB)" });
    const rec = { id:"media_"+Date.now(), url:String(url), type, size:sz, jyk:req.user.jyk||"", userId:req.user.id, createdAt:new Date().toISOString() };
    const arr = read("media.json", []); arr.push(rec); write("media.json", arr);
    res.json({ ok:true, record:rec });
  });
  app.post("/api/media/delete", auth, (req, res) => {
    const { id } = req.body || {}; if (!id) return res.status(400).json({ error: "id required" });
    const arr = read("media.json", []); const idx = arr.findIndex(x=>x.id===id);
    if (idx<0) return res.status(404).json({ error: "not found" });
    if (arr[idx].userId!==req.user.id && String(req.user.role||"")!=="ADMIN") return res.status(403).json({ error: "not allowed" });
    arr.splice(idx,1); write("media.json", arr); res.json({ ok:true });
  });
};