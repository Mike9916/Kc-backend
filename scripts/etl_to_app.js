// scripts/etl_to_app.js
const { Client } = require('pg');
require('dotenv').config();

async function run() {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  // Example: accounts.json → app.accounts
  await client.query(`
    INSERT INTO app.accounts (username, email, phone, status, payload)
    SELECT DISTINCT
      COALESCE(data->>'username', data->>'userName', data->>'name'),
      data->>'email',
      data->>'phone',
      COALESCE(data->>'status','active'),
      data
    FROM raw.files
    WHERE filename = 'accounts.json'
  `);

  // Example: members.json → app.members
  await client.query(`
    INSERT INTO app.members (scj_id, name, gender, phone, email, tribe, center, jyk, cell, status, payload)
    SELECT
      data->>'scjId',
      COALESCE(data->>'name', data->>'fullName'),
      data->>'gender',
      data->>'phone',
      data->>'email',
      data->>'tribe',
      data->>'center',
      data->>'jyk',
      data->>'cell',
      COALESCE(data->>'status','active'),
      data
    FROM raw.files
    WHERE filename = 'members.json'
  `);

  // Example: reports_service.json → app.reports
  await client.query(`
    INSERT INTO app.reports (
      type, leader_id, scope_tribe, scope_center, scope_jyk, scope_cell,
      period_start, period_end,
      total, attended_physical, attended_online, attended_other, not_attended,
      metrics, payload
    )
    SELECT
      'service',
      NULL,                               -- map if you have it in data
      data->>'tribe',
      data->>'center',
      data->>'jyk',
      data->>'cell',
      (data->>'periodStart')::date,
      (data->>'periodEnd')::date,
      NULLIF(data->>'total','')::int,
      NULLIF(data->>'attendedPhysical','')::int,
      NULLIF(data->>'attendedOnline','')::int,
      NULLIF(data->>'attendedOther','')::int,
      NULLIF(data->>'notAttended','')::int,
      data,                               -- metrics
      data                                -- payload backup
    FROM raw.files
    WHERE filename = 'reports_service.json'
  `);

  // Repeat similar INSERT..SELECT blocks for:
  // reports_education.json, reports_evangelism.json, reports_offering.json, audit.json, etc.

  await client.end();
  console.log('✅ ETL complete.');
}

run().catch(e => { console.error(e); process.exit(1); });