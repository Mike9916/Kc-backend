const express = require("express");
const router = express.Router();
const { read, write, nowIso, audit } = require("../helpers");

const TTL_MS = 72 * 60 * 60 * 1000;

function purgeOld(list) {
  const now = Date.now();
  return list.filter(x => now - Date.parse(x.createdAt || 0) < TTL_MS);
}

// Saints post issue or suggestion (anonymous allowed)
router.post("/", (req, res) => {
  const { kind = "issue", text = "", image = null } = req.body || {};
  if (!String(text).trim()) return res.status(400).json({ error: "text required" });

  let items = read("issues.json", []);
  items = purgeOld(items);

  const rec = {
    id: `iss_${Date.now()}`,
    kind: String(kind).toLowerCase() === "suggestion" ? "suggestion" : "issue",
    text: String(text),
    image: image ? String(image) : null,
    status: "Pending",
    createdAt: nowIso(),
    resolvedAt: null,
  };

  items.unshift(rec);
  write("issues.json", items);
  audit(req.user?.scjId || "-", "ISSUE_CREATE", "issue", rec.id, { kind: rec.kind });
  res.json({ ok: true, item: rec });
});

module.exports = router;