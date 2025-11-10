// server/routes/reportsService.js (example)
const express = require('express');
const { Pool } = require('pg');
const router = express.Router();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

router.get('/', async (req, res) => {
  const { tribe, center, jyk, cell, from, to } = req.query;

  const where = [];
  const params = [];
  function add(cond, val) { params.push(val); where.push(cond.replace('?', `$${params.length}`)); }

  if (tribe)  add('scope_tribe = ?', tribe);
  if (center) add('scope_center = ?', center);
  if (jyk)    add('scope_jyk = ?', jyk);
  if (cell)   add('scope_cell = ?', cell);
  if (from)   add('period_start >= ?', from);
  if (to)     add('period_end <= ?', to);

  const sql = `
    SELECT report_id, period_start, period_end,
           total, attended_physical, attended_online, attended_other, not_attended,
           metrics
    FROM app.reports
    WHERE type = 'service' ${where.length ? 'AND ' + where.join(' AND ') : ''}
    ORDER BY period_start DESC
    LIMIT 200
  `;

  const { rows } = await pool.query(sql, params);
  res.json(rows);
});

module.exports = router;