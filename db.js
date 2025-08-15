const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,   // External (local dev) or Internal (on Render)
  ssl: { rejectUnauthorized: false }            // works for both; keeps SSL on
});

module.exports = { pool };