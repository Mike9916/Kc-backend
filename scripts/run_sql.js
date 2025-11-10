// C:\@Lily\Update2\Innocent\scripts\run_sql.js
const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

// 1) Load .env from the Innocent folder (your backend root)
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

// 2) Validate DATABASE_URL and derive admin URL safely
const rawUrl = process.env.DATABASE_URL;
if (!rawUrl) {
  throw new Error(
    "Missing DATABASE_URL in .env. Edit C:\\@Lily\\Update2\\Innocent\\.env and add:\n" +
    "DATABASE_URL=postgres://postgres:Mykhan9916!@172.25.152.7:5432/innocent\nPGSSLMODE=disable\n"
  );
}

let adminUrl;
try {
  const u = new URL(rawUrl);
  // connect to the maintenance DB "postgres" to create 'innocent' if needed
  u.pathname = "/postgres";
  adminUrl = u.toString();
} catch (e) {
  throw new Error(`DATABASE_URL is not a valid URL. Current value: ${rawUrl}\n${e.message}`);
}

// 3) Read schema.sql (adjust path if your db folder is elsewhere)
const schemaPath = path.join(__dirname, "..", "db", "schema.sql");
if (!fs.existsSync(schemaPath)) {
  throw new Error(`schema.sql not found at: ${schemaPath}`);
}
const sql = fs.readFileSync(schemaPath, "utf8");

(async () => {
  // 4) Create DB if it doesn't exist
  const bootstrap = new Client({ connectionString: adminUrl });
  await bootstrap.connect();
  await bootstrap.query(`CREATE DATABASE innocent`).catch(() => {}); // ignore "already exists"
  await bootstrap.end();

  // 5) Apply schema to innocent
  const client = new Client({ connectionString: rawUrl });
  await client.connect();
  await client.query(sql);
  await client.end();

  console.log("✅ Schema applied successfully to 'innocent'.");
})().catch((err) => {
  console.error("❌ Failed to apply schema.\n" + err.stack);
  process.exit(1);
});