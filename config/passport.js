const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const AppleStrategy = require('passport-apple');
const User = require('../models/User');

// Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.SERVER_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    let user = await User.findOne({ provider: 'google', providerId: profile.id }) || (email ? await User.findOne({ email }) : null);
    if (!user) {
      user = await User.create({
        username: profile.displayName,
        email,
        provider: 'google',
        providerId: profile.id,
        avatar: profile.photos?.[0]?.value
      });
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// Facebook OAuth
passport.use(new FacebookStrategy({
  clientID: process.env.FB_CLIENT_ID,
  clientSecret: process.env.FB_CLIENT_SECRET,
  callbackURL: `${process.env.SERVER_URL}/auth/facebook/callback`,
  profileFields: ['id', 'displayName', 'photos', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    let user = await User.findOne({ provider: 'facebook', providerId: profile.id }) || (email ? await User.findOne({ email }) : null);
    if (!user) {
      user = await User.create({
        username: profile.displayName,
        email,
        provider: 'facebook',
        providerId: profile.id,
        avatar: profile.photos?.[0]?.value
      });
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// Apple OAuth
passport.use(new AppleStrategy({
  clientID: process.env.APPLE_CLIENT_ID, // Service ID
  teamID: process.env.APPLE_TEAM_ID,
  keyID: process.env.APPLE_KEY_ID,
  privateKeyString: process.env.APPLE_PRIVATE_KEY,
  callbackURL: `${process.env.SERVER_URL}/auth/apple/callback`,
  scope: ['name', 'email']
}, async (accessToken, refreshToken, idToken, profile, done) => {
  try {
    const email = idToken.email;
    const name = idToken.name ? `${idToken.name.firstName || ''} ${idToken.name.lastName || ''}`.trim() : 'Utilisateur Apple';

    let user = await User.findOne({ provider: 'apple', providerId: idToken.sub }) || (email ? await User.findOne({ email }) : null);

    if (!user) {
      user = await User.create({
        username: name || 'Utilisateur Apple',
        email,
        provider: 'apple',
        providerId: idToken.sub
      });

    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));