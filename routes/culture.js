const express = require("express");
const router = express.Router();
const { read, write, nowIso, audit } = require("../helpers"); // adjust to your helper path

const TTL_MS = 72 * 60 * 60 * 1000; // 72 hours

function purgeOld(list) {
  const now = Date.now();
  return list.filter(x => now - Date.parse(x.createdAt || 0) < TTL_MS);
}

// Middleware to check culture/admin roles
function requireCulture(req, res, next) {
  const role = String(req.user?.role || "").toUpperCase();
  if (role !== "CULTURE" && role !== "ADMIN")
    return res.status(403).json({ error: "Culture team only" });
  next();
}

// Get announcements (team only)
router.get("/announcements", requireCulture, (req, res) => {
  let items = read("culture_ann.json", []);
  items = purgeOld(items);
  write("culture_ann.json", items);
  res.json({ items });
});

// Create new announcement
router.post("/announcement", requireCulture, (req, res) => {
  const { title = "", body = "", attachmentUrl = "", draft = false } = req.body || {};
  if (!title.trim() && !body.trim() && !attachmentUrl.trim())
    return res.status(400).json({ error: "Empty announcement" });

  let items = read("culture_ann.json", []);
  const rec = {
    id: `ann_${Date.now()}`,
    title, body, attachmentUrl, draft: !!draft,
    createdAt: nowIso(), publishedAt: draft ? null : nowIso(),
  };
  items.unshift(rec);
  write("culture_ann.json", items);
  audit(req.user.scjId, "CULTURE_CREATE", "announcement", rec.id);
  res.json({ ok: true, item: rec });
});

// Publish an existing announcement
router.post("/announcement/publish", requireCulture, (req, res) => {
  const { id = "" } = req.body || {};
  let items = read("culture_ann.json", []);
  const it = items.find(x => x.id === id);
  if (!it) return res.status(404).json({ error: "not found" });
  it.draft = false;
  it.publishedAt = nowIso();
  write("culture_ann.json", items);
  res.json({ ok: true, item: it });
});

// Delete announcement
router.post("/announcement/delete", requireCulture, (req, res) => {
  const { id = "" } = req.body || {};
  let items = read("culture_ann.json", []);
  items = items.filter(x => x.id !== id);
  write("culture_ann.json", items);
  res.json({ ok: true });
});

// Public (saints) view
router.get("/public", (req, res) => {
  let items = read("culture_ann.json", []);
  items = purgeOld(items).filter(x => !x.draft && x.publishedAt);
  write("culture_ann.json", purgeOld(read("culture_ann.json", [])));
  res.json({ items });
});

module.exports = router;