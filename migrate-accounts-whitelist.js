// migrate-accounts-whitelist.js
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

// Same schemas as kc_app.js
const accountSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    scjId: { type: String, required: true, index: true },
  },
  { collection: "accounts", strict: false }
);

const whitelistSchema = new mongoose.Schema(
  {
    scjId: { type: String, required: true, unique: true },
  },
  { collection: "whitelist", strict: false }
);

const Account = mongoose.model("Account", accountSchema);
const Whitelist = mongoose.model("Whitelist", whitelistSchema);

async function main() {
  await mongoose.connect(MONGO_URL);
  console.log("✅ Connected to MongoDB");

  const accountsPath = path.join(DATA_DIR, "accounts.json");
  const whitelistPath = path.join(DATA_DIR, "whitelist.json");

  // Load JSON files (if they exist)
  let accounts = [];
  let whitelist = [];

  if (fs.existsSync(accountsPath)) {
    accounts = JSON.parse(fs.readFileSync(accountsPath, "utf8"));
  }
  if (fs.existsSync(whitelistPath)) {
    whitelist = JSON.parse(fs.readFileSync(whitelistPath, "utf8"));
  }

  console.log(`Found ${accounts.length} accounts, ${whitelist.length} whitelist entries in JSON.`);

  // Only insert if collections are empty
  const accCount = await Account.countDocuments();
  const wlCount = await Whitelist.countDocuments();

  if (accCount === 0 && accounts.length > 0) {
    await Account.insertMany(accounts);
    console.log(`✅ Inserted ${accounts.length} accounts into MongoDB`);
  } else {
    console.log(`ℹ Skipped accounts: collection already has ${accCount} docs`);
  }

  if (wlCount === 0 && whitelist.length > 0) {
    await Whitelist.insertMany(whitelist);
    console.log(`✅ Inserted ${whitelist.length} whitelist entries into MongoDB`);
  } else {
    console.log(`ℹ Skipped whitelist: collection already has ${wlCount} docs`);
  }

  await mongoose.disconnect();
  console.log("✅ Migration finished.");
}

main().catch(err => {
  console.error("Migration error:", err);
  process.exit(1);
});