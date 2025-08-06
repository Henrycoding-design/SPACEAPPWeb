const express = require('express');
const fs = require('fs');
const bodyParser = require('body-parser');

const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('trust proxy', 1);
app.use(cookieParser());
app.use(session({
  secret: 'spaceapp_super_secret',   // use a secure secret in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' } // this will auto set to false if not on https (localhost) and turn sercure to true when run on render,...
  // cookie: { sercure: false}
}));

// JSON data file
const filePath = path.join(__dirname, 'user_data.json');

// Utility function to load users
function loadUsers() {
  if (!fs.existsSync(filePath)) return [];

  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error("Failed to read user data:", err);
    return [];
  }
}

// ✨ Handle SIGNUP
app.post('/signup', (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();

  const alreadyExists = users.some(u => u.email === email);
  if (alreadyExists) {
    // Email already exists, show error page
    return res.redirect('/signup.html?error=Email already exists');
  }

  users.push({ email, password });
  fs.writeFileSync(filePath, JSON.stringify(users, null, 2), 'utf-8');
  req.session.user = { email };
  res.redirect('/thankyou.html');
});

// ✨ Handle LOGIN
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();

  const match = users.find(u => u.email === email && u.password === password);

  if (!match) {
    // Invalid credentials → back to login with query
    return res.redirect('/login.html?error=Wrong email or password');
  }

  // Successful login → go to thank you or dashboard
  req.session.user = { email };
  res.redirect('/thankyou.html');
});

// check logged in and log out
app.get('/api/isLoggedIn', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        res.clearCookie('connect.sid'); // remove session cookie
        res.redirect('/');
    });
});

require('dotenv').config();
//2. Create transporter (use your real Gmail and App Password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS      
  },
  tls: { rejectUnauthorized: false }
});

// ✅ 3. Add this POST handler below your login/signup routes:
app.post('/register', (req, res) => {
  // ONLY extract the email field safely from body
  const email = req.body.inputEmail || '';

  if (!email || !email.includes('@')) {
    return res.status(400).send('Invalid or missing email address');
  }

  // 📤 Email content
  const mailOptions = {
    from: 'SPACEAPP <tanbinhvo.hcm@gmail.com>',
    to: email,
    subject: '🚀 Your SPACEAPP Package Registration',
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
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


  // 📬 Send the email
  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('❌ Failed to send registration email:', err);
      return res.status(500).send('Failed to send confirmation email');
    }
    console.log('✅ Registration email sent:', info.response);
    res.redirect('/thankyou.html');
  });
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);

});

