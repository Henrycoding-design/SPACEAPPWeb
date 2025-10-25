require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
// const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const { gmailSend } = require('./gmail');
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS register (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      address TEXT,
      city TEXT,
      country TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
ensureSchema().catch(err => {
  console.error('Failed to ensure schema:', err);
  process.exit(1);
});

// // ---------- Nodemailer setup with SendGrid ----------
// const transporter = nodemailer.createTransport({
//   host: 'smtp.sendgrid.net',
//   port: 2525,
//   secure: false,
//   auth: {
//     user: 'apikey',
//     pass: process.env.SENDGRID_API_KEY
//   },
//   logger: true,
//   debug: true
// });
// // ---------- Nodemailer (SendGrid) ensure on boot ----------
// transporter.verify()
//   .then(() => console.log('📮 SendGrid ready'))
//   .catch(e => console.error('📮 SendGrid not ready:', e?.response?.body || e)); //e.response.body is just in case of switching into SendGrid Web API, for now we are just using SMTP


let otpStore = {};

// ---------- SIGNUP ----------
app.post('/signup', async (req, res) => {
  const { email = '', password = '' } = req.body;

  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isValidEmail || !password) {
    return res.redirect('/signup.html?error=Invalid email or password');
  }

  try {
    // Check if already exists in DB
    const { rows: existing } = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    if (existing.length > 0) {
      return res.redirect('/signup.html?error=Email already exists');
    }

    // Hash password (we’ll store it in memory for now)
    const hash = await bcrypt.hash(password, 12);

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); //range: 100,000 to just under 1,000,000

    // Store in memory (in production, you’d want Redis or DB)
    otpStore[email] = { 
      otp, 
      passwordHash: hash,
      expires: Date.now() + 5 * 60 * 1000 
    };

    const mailOptions = {
      // from: `${process.env.FROM_NAME || 'SPACEAPP'} <${process.env.FROM_EMAIL}>`,
      // from: "SPACEAPP <tanbinhvo.hcm@gmail.com>",
      to: email,
      subject: "🔐 Verify Your SPACEAPP Account",
      html: `
        <div style="font-family: 'Arial', sans-serif; font-size: 16px; color: #333; line-height: 1.6; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          
          <h1 style="color: #4A90E2; font-size: 24px; margin-bottom: 10px;">Verify Your Email</h1>
          <p>Hello,</p>
          <p>Thank you for signing up for <strong>SPACEAPP</strong>! To complete your registration, please use the following One-Time Password (OTP):</p>
          
          <div style="text-align: center; margin: 20px 0;">
            <span style="display: inline-block; font-size: 32px; font-weight: bold; color: #4A90E2; letter-spacing: 4px; padding: 10px 20px; border: 2px dashed #4A90E2; border-radius: 6px;">
              ${otp}
            </span>
          </div>

          <p style="margin-top: 10px;">This OTP will expire in <strong>5 minutes</strong>.</p>
          <p>If you did not initiate this request, you can safely ignore this email.</p>
          
          <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
          <p style="font-size: 12px; color: #888;">— SPACEAPP Team — Vo Tan Binh</p>
          <p style="font-size: 12px; color: #888;">Visit us at <a href="https://spaceappweb.onrender.com/" style="color: #4A90E2;">spaceappweb.onrender.com</a></p>
        </div>
      `,
      replyTo: 'tanbinhvo.hcm@gmail.com'
    };

    try {
      await gmailSend(mailOptions);    // wait for SendGrid
      console.log('✅ OTP email sent');
      req.session.pendingEmail = email;
      return res.redirect('/otp.html');           // respond once
    } catch (err) {
      console.error('❌ OTP Error:', err?.response?.body || err);
      return res.status(500).json({ error: "Failed to send email" }); // single response
    }

  } catch (e) {
    console.error('Signup error:', e);
    return res.redirect('/signup.html?error=Server+error');
  }
});

// ---------- RESEND OTP ----------
app.get('/resend-otp', async (req, res) => {
  const email = req.session.pendingEmail;
  if (!email) return res.redirect('/signup.html?error=No pending email');

  const record = otpStore[email];
  if (!record) return res.redirect('/signup.html?error=Please sign up again');

  // Generate new OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email].otp = otp;
  otpStore[email].expires = Date.now() + 5 * 60 * 1000;
  const mailOptions = {
    // from: `${process.env.FROM_NAME || 'SPACEAPP'} <${process.env.FROM_EMAIL}>`,
    // from: "SPACEAPP <tanbinhvo.hcm@gmail.com>",
    to: email,
    subject: "🔐 Verify Your SPACEAPP Account",
    html: `
      <div style="font-family: 'Arial', sans-serif; font-size: 16px; color: #333; line-height: 1.6; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        
        <h1 style="color: #4A90E2; font-size: 24px; margin-bottom: 10px;">Verify Your Email</h1>
        <p>Hello,</p>
        <p>Thank you for signing up for <strong>SPACEAPP</strong>! To complete your registration, please use the following One-Time Password (OTP):</p>
        
        <div style="text-align: center; margin: 20px 0;">
          <span style="display: inline-block; font-size: 32px; font-weight: bold; color: #4A90E2; letter-spacing: 4px; padding: 10px 20px; border: 2px dashed #4A90E2; border-radius: 6px;">
            ${otp}
          </span>
        </div>

        <p style="margin-top: 10px;">This OTP will expire in <strong>5 minutes</strong>.</p>
        <p>If you did not initiate this request, you can safely ignore this email.</p>
        
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
        <p style="font-size: 12px; color: #888;">— SPACEAPP Team — Vo Tan Binh</p>
        <p style="font-size: 12px; color: #888;">Visit us at <a href="https://spaceappweb.onrender.com/" style="color: #4A90E2;">spaceappweb.onrender.com</a></p>
      </div>
    `,
    replyTo: 'tanbinhvo.hcm@gmail.com'
  };

  try {
    await gmailSend(mailOptions); 
    console.log('✅ OTP email resent');
    return res.json({ success: true });      
  } catch (err) {
    console.error('❌ OTP Resend Error:', err?.errors || err);
    return res.status(500).json({ error: 'Failed to send email' });
  }
});

// ---------- VERIFY ----------
app.post('/verify', async (req, res) => {
  const { otp } = req.body;
  const email = req.session.pendingEmail;

  const record = otpStore[email];
  if (!record) return res.redirect("/otp.html?error=No OTP found, please sign up again.");
  if (Date.now() > record.expires) return res.redirect("/otp.html?error=OTP expired, please sign up again.");
  if (record.otp !== otp) return res.redirect("/otp.html?error=Invalid OTP");

  try {
    // Insert into DB only now
    const q = `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email, created_at
    `;
    const { rows } = await pool.query(q, [email, record.passwordHash]);

    // Mark session as logged in
    req.session.user = { id: rows[0].id, email: rows[0].email };

    // Clean up memory
    delete otpStore[email];

    return res.redirect("/otp.html?success=1");

  } catch (e) {
    console.error('Verify error:', e);
    return res.status(500).send("Server error during verification");
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
    const next = encodeURIComponent('/');
    return res.redirect(`/auth-complete.html?next=${next}`);
    // return res.redirect('/');
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

// ---------- Email ----------
app.post('/freeregister', async(req, res) => {
  const email = req.body.inputEmail || '';
  const firstName = req.body.inputFirstName || '';
  const lastName = req.body.inputLastName || '';
  const name = (firstName || lastName) ? `${firstName} ${lastName}`.trim() : 'User';
  const versionSelected = req.body.flexRadioDefault || 'v4.2';

  const address = req.body.inputAddress || '';
  const city = req.body.inputCity || '';
  const country = req.body.inputCountry || '';

  const downloadLinks = {
    'v3.0': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v3.0/v3.0.noopensrc.zip',
    'v4.0': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v4.0/SPACEAPPv4.0.zip',
    'v4.2': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v4.2/SPACEAPPv4.2.zip',
    'NextGenv1': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/NextGen/SPACEAPPNextGenv1.zip'
  };

  const downloadLink = downloadLinks[versionSelected];


  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isValidEmail) return res.status(400).send('Invalid email address');

  const q = `
      INSERT INTO register (email, name, address, city, country)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (email) DO NOTHING
      RETURNING id, email, name, created_at
    `;

  const { rows } = await pool.query(q, [email, name, address, city, country]);
  if (rows.length === 0) {
    console.log('Email already registered:', email);
  }

  const mailOptions = {
    // from: `${process.env.FROM_NAME || 'SPACEAPP'} <${process.env.FROM_EMAIL}>`,
    // from: "SPACEAPP <tanbinhvo.hcm@gmail.com>",
    to: email,
    subject: '🚀 Welcome to SPACEAPP!',
    html: `
      <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333; line-height: 1.6; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">

        <h1 style="color: #4A90E2; font-size: 24px; margin-bottom: 10px;">
          Welcome to SPACEAPP, ${name}!
        </h1>

        <h2 style="color: #333; font-size: 20px; margin-top: 0;">
          🌌 Thank you for registering!
        </h2>

        <p>You chose SPACEAPP <strong>${versionSelected}</strong>. 
        ${versionSelected === 'NextGenv1' ? "Please note that this is a pre-release of NextGenv1. If there is any issues during use, please contact us through the information provided below." : "You're all set to begin your journey tracking real-time satellites from Earth."}
        </p>

        <div style="text-align: center; margin: 20px 0;">
          <a href="${downloadLink}" target="_blank" rel="noopener noreferrer"
            style="display: inline-block; background-color: #4A90E2; color: #fff; text-decoration: none; font-size: 18px; font-weight: bold; padding: 12px 20px; border-radius: 6px;">
            📦 Download SPACEAPP ZIP (${versionSelected})
          </a>
        </div>

        <p>If you haven’t yet, remember to register your free API key at 
          <a href="https://www.n2yo.com/api/" target="_blank" style="color: #4A90E2;">n2yo.com/api</a> 
          and paste it inside your <code>.env</code> file. See more instructions in the README.
        </p>

        <p>${versionSelected === "v3.0" ? "Please note that SPACEAPP v3.0 is now considered an earlier release, with several components that have not been updated since September 2025. At the time of its publication, a placeholder NASA logo was temporarily used as we had not yet finalized our own branding — we sincerely apologize for this oversight. \nAdditionally, a few known vulnerabilities were later identified in this version. However, since v3.0 does not handle sensitive user data, it remains safe for general use. We plan to continue supporting it until December 2025, after which it will be officially retired in preparation for the upcoming NextGen releases.":""}
        Feel free to contact us with any questions. Enjoy exploring the stars!</p>

        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;" />

        <p style="font-size: 12px; color: #888; margin: 0;">— SPACEAPP Team — Vo Tan Binh</p>
        <p style="font-size: 12px; color: #888;">Visit us at <a href="https://spaceappweb.onrender.com/" style="color: #4A90E2;">spaceappweb.onrender.com</a></p>
        <p style="font-size: 12px; color: #888;">Contact: <a href="mailto:tanbinhvo.hcm@gmail.com" style="color: #4A90E2;">tanbinhvo.hcm@gmail.com</a></p>
    `,
    replyTo: 'tanbinhvo.hcm@gmail.com'
  };

  // transporter.sendMail(mailOptions, (err, info) => {
  //   if (err) {
  //     console.error('❌ Failed to send registration email:', err);
  //     return res.status(500).send('Failed to send confirmation email');
  //   }
  //   console.log('✅ Registration email sent:', info.response);
  //   res.redirect('/thankyou.html');
  // });
  try {
    await gmailSend(mailOptions);
    console.log('✅ Registration email sent');
    res.redirect('/thankyou.html');
  } catch (err) {
    console.error('❌ Failed to send registration email:', err?.errors || err);
    return res.status(500).send('Failed to send confirmation email');
  }
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
