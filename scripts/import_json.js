// scripts/import_json.js
const fs = require('fs'), path = require('path');
const { Client } = require('pg');
require('dotenv').config({ path: path.join(__dirname,'..','.env') });

const fileMap = {
  service:     'reports_service.json',
  education:   'reports_education.json',
  evangelism:  'reports_evangelism.json',
  offering:    'reports_offering.json',
};

const type = process.argv[2] || 'service';
const file = fileMap[type];
if (!file) { console.error('Usage: node scripts/import_json.js <service|education|evangelism|offering>'); process.exit(1); }

const data = JSON.parse(fs.readFileSync(path.join(__dirname,'..','data',file), 'utf8'));
const client = new Client({ connectionString: process.env.DATABASE_URL });

(async () => {
  await client.connect();
  for (const r of data) {
    const scope_jyk    = r.jykId || r.centerId || r.jyk || null;
    const scope_cell   = r.cell || r.cellId || r.gyjnId || null;
    const scope_tribe  = r.tribe || null;
    const scope_center = r.center || r.centerName || null;

    await client.query(
      `INSERT INTO app.reports
       (type, leader_id, scope_tribe, scope_center, scope_jyk, scope_cell,
        period_start, period_end, total, attended_physical, attended_online,
        attended_other, not_attended, metrics, payload)
       VALUES ($1, null, $2,$3,$4,$5,
               coalesce($6::date,current_date),
               coalesce($7::date,current_date),
               coalesce($8,0), coalesce($9,0), coalesce($10,0),
               coalesce($11,0), coalesce($12,0),
               coalesce($13::jsonb,'{}'::jsonb),
               coalesce($14::jsonb,'{}'::jsonb))`,
      [
        type, scope_tribe, scope_center, scope_jyk, scope_cell,
        r.periodStart, r.periodEnd,
        r.total, r.attended_physical, r.attended_online,
        r.attended_other, r.not_attended,
        JSON.stringify(r.metrics || {}), JSON.stringify(r)
      ]
    );
  }
  console.log(`✅ Imported ${data.length} ${type} records.`);
  await client.end();
})().catch(e=>{ console.error(e); process.exit(1); });