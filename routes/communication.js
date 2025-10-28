const express = require("express");
const router = express.Router();
const { read, write, nowIso, audit } = require("../helpers");

const TTL_MS = 72 * 60 * 60 * 1000;

function purgeOld(list) {
  const now = Date.now();
  return list.filter(x => now - Date.parse(x.createdAt || 0) < TTL_MS);
}

function requireComms(req, res, next) {
  const role = String(req.user?.role || "").toUpperCase();
  if (role !== "COMMS" && role !== "ADMIN")
    return res.status(403).json({ error: "Communication team only" });
  next();
}

// Fetch issues
router.get("/issues", requireComms, (req, res) => {
  let items = read("issues.json", []);
  items = purgeOld(items);
  write("issues.json", items);
  res.json({ items });
});

// Change issue status
router.post("/issue/status", requireComms, (req, res) => {
  const { id = "", status = "" } = req.body || {};
  let items = read("issues.json", []);
  const it = items.find(x => x.id === id);
  if (!it) return res.status(404).json({ error: "Not found" });
  const newStatus = status.toLowerCase() === "resolved" ? "Resolved" : "Pending";
  it.status = newStatus;
  it.resolvedAt = newStatus === "Resolved" ? nowIso() : null;
  write("issues.json", items);
  audit(req.user.scjId, "COMM_STATUS", "issue", id, { status: newStatus });
  res.json({ ok: true, item: it });
});

module.exports = router;