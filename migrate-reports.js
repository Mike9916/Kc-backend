// migrate-reports.js
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");

const MONGO_URL = process.env.MONGO_URL;
if (!MONGO_URL) {
  console.error("MONGO_URL is not set in .env");
  process.exit(1);
}

const DATA_DIR = path.join(__dirname, "data");

const looseOptions = { strict: false };

const LegacyReports = mongoose.model(
  "LegacyReports",
  new mongoose.Schema({}, { ...looseOptions, collection: "reports" })
);
const LegacyReportsEducation = mongoose.model(
  "LegacyReportsEducation",
  new mongoose.Schema({}, { ...looseOptions, collection: "reports_education" })
);
const LegacyReportsEvangelism = mongoose.model(
  "LegacyReportsEvangelism",
  new mongoose.Schema({}, { ...looseOptions, collection: "reports_evangelism" })
);
const LegacyReportsOffering = mongoose.model(
  "LegacyReportsOffering",
  new mongoose.Schema({}, { ...looseOptions, collection: "reports_offering" })
);
const LegacyReportsService = mongoose.model(
  "LegacyReportsService",
  new mongoose.Schema({}, { ...looseOptions, collection: "reports_service" })
);

function loadJson(name) {
  const p = path.join(DATA_DIR, name);
  if (!fs.existsSync(p)) return [];
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

async function migrateOne(label, fileName, Model) {
  const docs = loadJson(fileName);
  console.log(`${label}: found ${docs.length} entries in ${fileName}`);

  const count = await Model.countDocuments();
  if (count > 0) {
    console.log(`  -> Skipping insert, collection already has ${count} docs`);
    return;
  }

  if (docs.length === 0) {
    console.log("  -> Nothing to insert.");
    return;
  }

  await Model.insertMany(docs);
  console.log(`  -> Inserted ${docs.length} docs into Mongo`);
}

async function main() {
  await mongoose.connect(MONGO_URL);
  console.log("✅ Connected to MongoDB");

  await migrateOne("Reports", "reports.json", LegacyReports);
  await migrateOne("Reports.education", "reports_education.json", LegacyReportsEducation);
  await migrateOne("Reports.evangelism", "reports_evangelism.json", LegacyReportsEvangelism);
  await migrateOne("Reports.offering", "reports_offering.json", LegacyReportsOffering);
  await migrateOne("Reports.service", "reports_service.json", LegacyReportsService);

  await mongoose.disconnect();
  console.log("✅ Migration finished.");
}

main().catch(err => {
  console.error("Migration error:", err);
  process.exit(1);
});