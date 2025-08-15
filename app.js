const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { pool } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'spaceapp_super_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// ---------- One-time table ensure on boot ----------
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
ensureSchema().catch(err => {
  console.error('Failed to ensure schema:', err);
  process.exit(1);
});

// ---------- SIGNUP ----------
app.post('/signup', async (req, res) => {
  const { email = '', password = '' } = req.body;

  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isValidEmail || !password) {
    return res.redirect('/signup.html?error=Invalid email or password');
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    const q = `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      ON CONFLICT (email) DO NOTHING
      RETURNING id, email, created_at
    `;
    const { rows } = await pool.query(q, [email, hash]);

    if (rows.length === 0) {
      // Duplicate email (no new row created)
      return res.redirect('/signup.html?error=Email already exists');
    }

    req.session.user = { id: rows[0].id, email: rows[0].email };
    return res.redirect('/');
  } catch (e) {
    console.error('Signup error:', e);
    return res.redirect('/signup.html?error=Server+error');
  }
});

// ---------- LOGIN ----------
app.post('/login', async (req, res) => {
  const { email = '', password = '' } = req.body;

  try {
    const { rows } = await pool.query(
      'SELECT id, email, password_hash FROM users WHERE email = $1',
      [email]
    );
    if (rows.length === 0) {
      return res.redirect('/login.html?error=Wrong email or password');
    }

    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) {
      return res.redirect('/login.html?error=Wrong email or password');
    }

    req.session.user = { id: rows[0].id, email: rows[0].email };
    return res.redirect('/');
  } catch (e) {
    console.error('Login error:', e);
    return res.redirect('/login.html?error=Server+error');
  }
});

// ---------- Session helpers ----------
app.get('/api/isLoggedIn', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// ---------- Email (unchanged) ----------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  tls: { rejectUnauthorized: false }
});

app.post('/freeregister', (req, res) => {
  const email = req.body.inputEmail || '';
  const firstName = req.body.inputFirstName || '';
  const lastName = req.body.inputLastName || '';
  const name = (firstName || lastName) ? `${firstName} ${lastName}`.trim() : 'User';
  const userType = req.body.flexRadioDefault || 'User';

  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isValidEmail) return res.status(400).send('Invalid email address');

  const mailOptions = {
    from: 'SPACEAPP <tanbinhvo.hcm@gmail.com>',
    to: email,
    subject: '🚀 Your SPACEAPP Package Registration',
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h1 style="color: #4A90E2;">Welcome to SPACEAPP, ${userType} ${name}!</h1>
        <h2>🌌 Thank you for registering with SPACEAPP!</h2>
        <p>You're all set to begin your journey tracking real-time satellites from Earth.</p>
        <p><strong>Download the latest version here:</strong></p>
        <a href="https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v2.5/SPACEAPP.zip" style="font-size: 16px;">
          📦 Click here to download SPACEAPP ZIP
        </a>
        <br><br>
        <p>If you haven’t yet, remember to register your own free API key at 
          <a href="https://www.n2yo.com/api/" target="_blank">n2yo.com/api</a> 
          and paste it inside the <code>.env</code> file. See more instructions in the README.
        </p>
        <p>Feel free to contact us with any questions. Enjoy exploring the stars!</p>
        <hr>
        <small>— SPACEAPP by Henry Vo</small>
      </div>
    `
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('❌ Failed to send registration email:', err);
      return res.status(500).send('Failed to send confirmation email');
    }
    console.log('✅ Registration email sent:', info.response);
    res.redirect('/thankyou.html');
  });
});

// ---------- Health endpoint to verify DB quickly ----------
app.get('/admin/db-ping', async (req, res) => {
  try {
    const r = await pool.query('SELECT NOW() as now');
    res.json({ ok: true, now: r.rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});


