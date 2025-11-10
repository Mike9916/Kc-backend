// node scripts/import_json.js
const fs = require('fs'), path = require('path');
const { Client } = require('pg'); require('dotenv').config({ path: path.join(__dirname,'..','.env') });

const client = new Client({ connectionString: process.env.DATABASE_URL });
const load = p => JSON.parse(fs.readFileSync(path.join(__dirname,'..','data',p),'utf8'));

(async () => {
  await client.connect();

  // Example: service reports
  const svc = load('reports_service.json'); // adjust name if different
  for (const r of svc) {
    // derive scope fields (adjust to your keys)
    const scope_jyk   = r.jykId || r.centerId || r.jyk || null;
    const scope_cell  = r.cell || r.cellId || r.gyjnId || null;
    const scope_tribe = r.tribe || null;
    const scope_center= r.center || r.centerName || null;

    await client.query(
      `INSERT INTO app.reports
       (type, leader_id, scope_tribe, scope_center, scope_jyk, scope_cell,
        period_start, period_end, total, attended_physical, attended_online,
        attended_other, not_attended, metrics, payload)
       VALUES ('service', NULL, $1,$2,$3,$4,
               COALESCE($5::date, CURRENT_DATE),
               COALESCE($6::date, CURRENT_DATE),
               COALESCE($7,0), COALESCE($8,0), COALESCE($9,0),
               COALESCE($10,0), COALESCE($11,0),
               COALESCE($12::jsonb,'{}'::jsonb),
               COALESCE($13::jsonb,'{}'::jsonb))`,
      [
        scope_tribe, scope_center, scope_jyk, scope_cell,
        r.periodStart, r.periodEnd,
        r.total, r.attended_physical, r.attended_online,
        r.attended_other, r.not_attended,
        JSON.stringify(r.metrics || {}), JSON.stringify(r)
      ]
    );
  }

  console.log('✅ Imported service reports.');
  await client.end();
})().catch(e => { console.error(e); process.exit(1); });