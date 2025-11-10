// scripts/import_raw.js
// Usage: node scripts/import_raw.js "C:\\@Lily\\Update2\\Innocent\\data"

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
require('dotenv').config();

async function main() {
  const dataDir = process.argv[2];
  if (!dataDir) {
    console.error('Provide data directory path. Example: node scripts/import_raw.js "C:\\\\@Lily\\\\Update2\\\\Innocent\\\\data"');
    process.exit(1);
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  const entries = fs.readdirSync(dataDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) continue;            // skip "uploads" folder
    if (!entry.name.endsWith('.json')) continue;  // only JSON files

    const filename = entry.name;
    const fullPath = path.join(dataDir, filename);
    const raw = fs.readFileSync(fullPath, 'utf8').trim();
    if (!raw) continue;

    let json;
    try {
      json = JSON.parse(raw);
    } catch (e) {
      console.error(`❌ ${filename}: JSON parse error ->`, e.message);
      continue;
    }

    console.log(`→ Importing ${filename} ...`);

    if (Array.isArray(json)) {
      // array file: many rows
      for (let i = 0; i < json.length; i++) {
        await client.query(
          `INSERT INTO raw.files (filename, record_index, data)
           VALUES ($1, $2, $3)`,
          [filename, i, json[i]]
        );
      }
    } else {
      // object file: single row
      await client.query(
        `INSERT INTO raw.files (filename, record_index, data)
         VALUES ($1, NULL, $2)`,
        [filename, json]
      );
    }
  }

  await client.end();
  console.log('✅ Import complete.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});