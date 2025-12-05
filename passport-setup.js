const passport = require('passport');
const { pool } = require('./db');
const GoogleStrategy = require('passport-google-oauth20').Strategy;



// Your Google OAuth credentials
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID_AUTH;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET_AUTH;

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const user = {
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value
      };
      const password_hash = 'GGAcount: '+ user.googleId; 
      const { rows } = await pool.query(`
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        ON CONFLICT (email) DO NOTHING
        RETURNING id, email, password_hash
      `, [user.email, password_hash]);

      if (rows.length === 0) console.log('User already exists:', user.email);

      // Send the user object to passport
      done(null, { id: rows[0]?.id, email: user.email });
    } catch (err) {
      done(err, null);
    }
  }
));


// For sessions 
passport.serializeUser((user, done) => done(null, user)); 
passport.deserializeUser((user, done) => done(null, user));
