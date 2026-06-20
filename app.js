require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const multer = require("multer");
const upload = multer();
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
// const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const { gmailSend } = require('./gmail');
const { pool } = require('./db');
const passport = require('passport');
require('./passport-setup');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);
app.use(cookieParser());
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  (process.env.NODE_ENV !== 'production'
    ? 'spaceapp_super_secret'
    : null);
if (process.env.NODE_ENV === 'production' && !SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}
// remember to check prod env ensure SESSION_SECRET is there. if not generate locally and then push: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// ---------- Rate Limiter (DDos and DoS attacks best-effort prevent) ----------
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,   // 5 minutes in ms
  max: 10,                    // max 10 attempts per window
  message: 'Too many attempts, please wait a few minutes.'
});

const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: 'Too many OTP requests, please wait a few minutes.'
});

const verifyLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,   // 5 minutes
  max: 5,                    // 5 OTP attempts
  message: 'Too many OTP attempts. Please request a new code.'
});

const downloadLimiter = rateLimit({ // unreasonable traffic
  windowMs: 5 * 60 * 1000,
  max: 10, 
  message: 'Too many download requests. Please wait a few minutes.'
})

const deliveryRequestsLimiter = rateLimit({ // unreasonable traffic
  windowMs: 5 * 60 * 1000,
  max: 10, 
  message: 'Too many download requests. Please wait a few minutes.'
})

// ---------- Casual protection for email queries ----------
const deliveryCooldown = new Map();
// email -> timestamp
const COOLDOWN_MS = 1 * 60 * 1000;

// cleanup Map
function cleanupCooldown() {
  if (deliveryCooldown.size < 100) return;

  const now = Date.now();
  for (const [email, ts] of deliveryCooldown) {
    if (now - ts > COOLDOWN_MS) {
      deliveryCooldown.delete(email);
    }
  }
}


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
      space_knowledge_level TEXT, 
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS delivery_requests (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      module TEXT NOT NULL,
      version TEXT NOT NULL,
      use TEXT,
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
app.post('/signup', authLimiter, async (req, res) => {
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
      await gmailSend(mailOptions);   
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
app.get('/resend-otp', otpLimiter, async (req, res) => {
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
app.post('/verify', verifyLimiter, async (req, res) => {
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
app.post('/login', authLimiter, async (req, res) => {
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
    // const next = encodeURIComponent('/');
    // return res.redirect(`/auth-complete.html?next=${next}`);
    return res.redirect('/community.html');
  } catch (e) {
    console.error('Login error:', e);
    return res.redirect('/login.html?error=Server+error');
  }
});

// ---------- GG AUTH ----------
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/signup?error=login_failed' }),
  (req, res) => {
    res.redirect('/community.html');
  }
);

// ---------- Session helpers ----------
app.get('/api/isLoggedIn', (req, res) => {
  if (req.isAuthenticated()) {
    // Passport login (Google)
    res.json({ loggedIn: true, user: req.user });
  } else if (req.session.user) {
    // Normal email/password login
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => { // for passport
      req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  }); 
});

// ---------- Email ----------
app.post('/freeregister', downloadLimiter, async (req, res) => {
  const email = req.body.inputEmail || '';
  const firstName = req.body.inputFirstName || '';
  const lastName = req.body.inputLastName || '';
  const name = (firstName || lastName) ? `${firstName} ${lastName}`.trim() : 'User';

  // NEW STRUCTURED INPUT
  const platform = req.body.platform || 'Windows';
  const versionSelected = req.body.version || 'v5.5';

  const address = req.body.inputAddress || '';
  const city = req.body.inputCity || '';
  const country = req.body.inputCountry || '';
  const { spaceKnowledgeLevel } = req.body;

  const downloadLinks = {
    'v4.2': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v4.2/SPACEAPPv4.2.zip',
    'v5.0': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v5.0/SPACEAPPv5.0.zip',
    'v5.0-beta-5': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v5.0-beta-5/SPACEAPP-v5.0-beta-5-Installer-x64.exe',
    'v5.5': 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v5.5.4/SPACEAPP-Stable-v5-5-4-Installer-x64.exe',

    // 🧪 PLACEHOLDER FOR FUTURE BUILD
    'v5.6': platform === 'Mac'
      ? 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v5.6/SPACEAPP-macOS.zip'
      : 'https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v5.6/SPACEAPP-Stable-v5-6-Installer-x64.exe'
  };

  const downloadLink = downloadLinks[versionSelected] || downloadLinks['v5.6'];

  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isValidEmail) return res.status(400).send('Invalid email address');

  const now = Date.now();
  const lastRequest = deliveryCooldown.get(email);

  if (lastRequest && now - lastRequest < COOLDOWN_MS) {
    const waitSec = Math.ceil((COOLDOWN_MS - (now - lastRequest)) / 1000);
    return res.redirect(
      `/freeform.html?error=${encodeURIComponent(
        `Please wait ${waitSec}s before requesting again.`
      )}`
    );
  }

  deliveryCooldown.set(email, now);
  cleanupCooldown();

  const q = `
    INSERT INTO register (email, name, address, city, country, space_knowledge_level)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (email) DO NOTHING
    RETURNING id, email, name, created_at
  `;

  const { rows } = await pool.query(q, [
    email,
    name,
    address,
    city,
    country,
    spaceKnowledgeLevel
  ]);


  const isNew = rows.length !== 0;

  if (!isNew) {
    console.log('Email already registered:', email);
  }

  const mailOptions = {
    to: email,
    subject: isNew ? '🚀 Welcome to SPACEAPP!' : '🚀 Hi again, from SPACEAPP!',
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 16px; color: #333333; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 30px 20px; border: 1px solid #e0e0e0; border-radius: 8px;">

        <!-- Header -->
        <h1 style="color: #4A90E2; margin-top: 0; font-size: 26px;">
          ${isNew ? `Welcome to SPACEAPP, ${name}!` : `Your Download Link, ${name}!`}
        </h1>
        <p style="font-size: 18px; color: #555555; margin-bottom: 24px;">🌌 Thank you for downloading!</p>

        <!-- System Details -->
        <ul style="list-style: none; padding: 0; margin: 0 0 20px 0; background-color: #f8fafc; padding: 15px; border-radius: 6px;">
          <li><strong>Platform detected:</strong> ${platform}</li>
          <li><strong>Version chosen:</strong> ${versionSelected}</li>
        </ul>

        <!-- Dynamic Welcome Message -->
        <p style="margin-bottom: 24px;">
          ${versionSelected === 'v5.6'
            ? "SPACEAPP v5.6 is the most advanced and globally scalable version of SPACEAPP yet."
            : "You're all set to begin your journey exploring satellites from Earth."
          }
        </p>

        <!-- Action Buttons -->
        <div style="text-align: center; margin: 30px 0;">
          <a href="${downloadLink}" target="_blank"
            style="display: inline-block; background: #4A90E2; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; box-shadow: 0 2px 4px rgba(74,144,226,0.2);">
            📦 Download SPACEAPP (${versionSelected})
          </a>
          ${platform === "Mac" ? `
            <br />
            <a href="https://github.com/Henrycoding-design/SPACEAPPEXE/releases/download/v5.6/models.zip" target="_blank"
              style="display: inline-block; background: linear-gradient(135deg, #8b5cf6, #6d28d9); color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; margin-top: 12px; box-shadow: 0 2px 4px rgba(109,40,217,0.2);">
              🧊 Download 3D Models (.zip)
            </a>
          ` : ""}
        </div>

        ${platform === "Mac" ? `
          <p style="font-size:14px;color:#666; margin-bottom: 20px;">
            For macOS, download both SPACEAPP and the Models package.
            Extract models.zip and place the models folder beside SPACEAPP before first launch.
          </p>
          ` : ""}
        
        <!-- Deprecation Warning (if applicable) -->
        ${versionSelected === "v4.2" ? `
          <div style="background-color: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
            <p style="margin: 0; color: #b45309; font-size: 14px;">
              <strong>Please note:</strong> SPACEAPP v4.2 & v4.0 are older releases. Several components have not been updated since October 2025. These versions will be retired and unsupported after March 2026.
            </p>
          </div>
        ` : ""}

        <!-- Actionable Instructions -->
        <div style="background-color: #f0f7ff; border-left: 4px solid #4A90E2; padding: 15px; margin-bottom: 24px; border-radius: 4px;">
          <p style="margin: 0; font-size: 15px;">
            🔑 <strong>Next Step:</strong> Remember to get your API/Developer Key from <a href="https://www.n2yo.com/login/edit/" style="color: #4A90E2; text-decoration: underline;">N2YO Login</a> and configure it inside the app.
          </p>
        </div>

        <p style="margin-bottom: 30px;">Feel free to contact us with any questions. Enjoy exploring the stars!</p>

        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 24px 0;" />

        <!-- Footer -->
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="font-size: 12px; color: #888888; line-height: 1.5;">
              <strong style="color: #555555;">— SPACEAPP Team — Vo Tan Binh</strong><br />
              Web: <a href="https://spaceappweb.onrender.com/" style="color: #4A90E2; text-decoration: none;">spaceappweb.onrender.com</a><br />
              Support: <a href="mailto:tanbinhvo.hcm@gmail.com" style="color: #4A90E2; text-decoration: none;">tanbinhvo.hcm@gmail.com</a>
            </td>
          </tr>
        </table>

      </div>
    `,
    replyTo: 'tanbinhvo.hcm@gmail.com'
  };

  try {
    await gmailSend(mailOptions);
    console.log('✅ Registration email sent');
    res.redirect('/thankyou.html');
  } catch (err) {
    console.error('❌ Failed to send registration email:', err?.errors || err);
    return res.status(500).send('Failed to send confirmation email');
  }
});

// ---------- Community Page: Direct Delivery ----------
app.post('/api/delivery', deliveryRequestsLimiter, upload.none(),  async (req, res) => {
  try {
    const { email, module, version, use } = req.body;

    // Basic validation
    const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!isValidEmail) return res.status(400).send('Invalid email address');

    // prevent casual pings on website

    const now = Date.now();

    const lastRequest = deliveryCooldown.get(email);
    if (lastRequest && now - lastRequest < COOLDOWN_MS) {
      const waitSec = Math.ceil((COOLDOWN_MS - (now - lastRequest)) / 1000);
      return res.status(429).json({
        error: `Please wait ${waitSec}s before requesting again.`
      });
    }

    // mark cooldown
    deliveryCooldown.set(email, now);

    cleanupCooldown();

    // Choose the correct download link
    const downloadLinks = { // switched from bmac to ko-fi
      'api_worker': {'v4.0': 'https://ko-fi.com/s/21fd0399f2'},
      'core_engine': {'v4.0': 'https://ko-fi.com/s/3754ba30df', 'v4.2': 'https://ko-fi.com/s/ebb938375c'},
      'map': {'v4.0': 'https://ko-fi.com/s/d8d485986f'},
      'full_stack': {'v3.0':'https://github.com/Henrycoding-design/SpaceappwebOpenSrc'},
    };
    const downloadLink = downloadLinks[module][version] || null;

    if (!downloadLinks[module] || !downloadLinks[module][version]){return res.status(400).send('Invalid module/version selection');}

    // Optional: insert into DB for record keeping
    const q = `
      INSERT INTO delivery_requests (email, module, version, use)
      VALUES ($1, $2, $3, $4)
      RETURNING id, created_at
    `;
    await pool.query(q, [email, module, version, use || 'N/A']);

    // Build email body
    const mailOptions = {
      to: email,
      subject: `🚀 SPACEAPP ${version} – Delivery: ${module} (${version})`,
      html: `
        <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333; line-height: 1.6; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #3274e7;">Your SPACEAPP ${module} ${version} is ready!</h2>
          <p>Thank you for requesting a delivery through the Community Page.</p>

          <p><strong>Module:</strong> ${module}</p>
          ${use ? `<p><strong>Your note:</strong> ${use}</p>` : ''}

          <p style="font-size:14px;color:#555;">
            ${
              version === 'v3.0' 
                ? 'Click on the button below to get to our GitHub open-source repository!' 
                : 'Click on the button below to get to our Ko-fi payment system and finish your premium version purchase!'
            }
          </p>
          
          <div style="text-align:center;margin:20px 0;">
            <a href="${downloadLink}" target="_blank" rel="noopener noreferrer"
               style="display:inline-block;background-color:#3274e7;color:#fff;text-decoration:none;font-weight:bold;padding:12px 20px;border-radius:6px;">
               📦 Go to ${module} version ${version}
            </a>
          </div>

          <p style="font-size:14px;color:#555;">If the button above doesn’t work, use this link: <br>
            <a href="${downloadLink}" style="color:#3274e7;">${downloadLink}</a>
          </p>

          <p style="font-size:14px;color:#555;">
            ${version === 'v3.0' ? `Or you can just clone using Git:<br><code style="background:#f4f4f4;padding:2px 6px;border-radius:4px;display:inline-block;margin-top:5px;">git clone ${downloadLink}.git</code>` : ''}
          </p>

          <hr style="border:none;border-top:1px solid #ccc;margin:20px 0;">
          <p style="font-size:12px;color:#888;margin:0;">— SPACEAPP Team — Vo Tan Binh</p>
          <p style="font-size:12px;color:#888;">Contact: <a href="mailto:tanbinhvo.hcm@gmail.com" style="color:#3274e7;">tanbinhvo.hcm@gmail.com</a></p>
        </div>
      `,
      replyTo: 'tanbinhvo.hcm@gmail.com'
    };

    // Send it (using your same gmailSend() helper)
    await gmailSend(mailOptions);

    console.log(`✅ Direct delivery email sent to ${email}`);
    res.json({ success: true, message: 'Email sent successfully' });
  } catch (err) {
    console.error('❌ Failed to send delivery email:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
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
