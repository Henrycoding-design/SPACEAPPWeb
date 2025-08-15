const { Pool } = require('pg');

const conn = process.env.DATABASE_URL || '';
const needsSSL = /render\.com/i.test(conn); // true for your Render URL, false for localhost

const pool = new Pool({
  connectionString: conn,
  ssl: needsSSL ? { rejectUnauthorized: false } : false
});

module.exports = { pool };
