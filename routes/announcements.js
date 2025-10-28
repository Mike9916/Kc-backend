// routes/announcements.js
const express = require("express");
const router = express.Router();

// If you already have helpers in another file, keep these requires exactly
// as you use them elsewhere. Adjust the relative path if needed.
const { read, write, nowIso } = require("../helpers");

// Announcements auto-expire after 72 hours (same rule used by Culture)
const TTL_MS = 72 * 60 * 60 * 1000;

function purgeOld(list) {
  const now = Date.now();
  return list.filter(x => {
    const ts = Date.parse(x.createdAt || 0);
    return Number.isFinite(ts) && now - ts < TTL_MS;
  });
}

/**
 * GET /api/announcements
 * Public endpoint for saints:
 * - Returns only published, non-draft announcements
 * - Auto-purges items older than 72 hours
 * - Reads the same data file used by Culture
 */
router.get("/", (req, res) => {
  // You can rename the file if you used a different one in culture.js
  let items = read("culture_ann.json", []);

  // Purge expired
  items = purgeOld(items);
  write("culture_ann.json", items);

  // Only published announcements
  const visible = items.filter(a => !a.draft && a.publishedAt);

  res.json({ items: visible });
});

module.exports = router;