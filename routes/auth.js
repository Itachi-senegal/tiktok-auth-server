const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../models/User');

// Vérifier quels providers sont configurés
const hasGoogleConfig = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;
const hasFacebookConfig = process.env.FB_CLIENT_ID && process.env.FB_CLIENT_SECRET;
const hasAppleConfig = process.env.APPLE_CLIENT_ID && process.env.APPLE_TEAM_ID && process.env.APPLE_KEY_ID && process.env.APPLE_PRIVATE_KEY;

// REGISTER
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email déjà utilisé" });
    }

    // Hash du mot de passe
    //const hashedPassword = await bcrypt.hash(password, 10);
    const passwordToSave = password;

    // Création utilisateur
    const newUser = new User({
      username,
      email,
      password: passwordToSave,
    });

    await newUser.save();

    res.json({ message: "Inscription réussie !" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Vérifier si l'utilisateur existe
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Email ou mot de passe incorrect" });
    }

    // Vérifier le mot de passe
    //const isMatch = await bcrypt.compare(password, user.password);
     const isMatch = (password === user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Email ou mot de passe incorrect" });
    }

    // Générer les tokens JWT
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret',
      { expiresIn: '7d' }
    );

    // Définir les cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
    });

    res.json({
      message: "Connexion réussie",
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// LOGOUT
router.post('/logout', (req, res) => {
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.json({ message: "Déconnexion réussie" });
});

// ===== ROUTES OAUTH GOOGLE =====
router.get('/google', (req, res) => {
  if (!hasGoogleConfig) {
    return res.status(501).json({
      error: 'Google OAuth non configuré',
      message: 'Les variables d\'environnement Google OAuth ne sont pas définies'
    });
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res);
});

router.get('/google/callback', (req, res, next) => {
  if (!hasGoogleConfig) {
    return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=oauth_disabled`);
  }

  passport.authenticate('google', { session: false }, async (err, user) => {
    if (err || !user) {
      console.error('Erreur Google OAuth:', err);
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed`);
    }

    try {
      // Générer les tokens
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret',
        { expiresIn: '7d' }
      );

      // Définir les cookies
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      // Rediriger vers la page d'accueil
      res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}`);
    } catch (error) {
      console.error('Erreur traitement callback Google:', error);
      res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed`);
    }
  })(req, res, next);
});

// ===== ROUTES OAUTH FACEBOOK =====
router.get('/facebook', (req, res) => {
  if (!hasFacebookConfig) {
    return res.status(501).json({
      error: 'Facebook OAuth non configuré',
      message: 'Les variables d\'environnement Facebook OAuth ne sont pas définies'
    });
  }
  passport.authenticate('facebook', { scope: ['email'] })(req, res);
});

router.get('/facebook/callback', (req, res, next) => {
  if (!hasFacebookConfig) {
    return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=oauth_disabled`);
  }

  passport.authenticate('facebook', { session: false }, async (err, user) => {
    if (err || !user) {
      console.error('Erreur Facebook OAuth:', err);
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed`);
    }

    try {
      // Générer les tokens
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret',
        { expiresIn: '7d' }
      );

      // Définir les cookies
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      // Rediriger vers le client
      res.redirect(process.env.CLIENT_URL || 'http://localhost:3000');
    } catch (error) {
      console.error('Erreur traitement callback Facebook:', error);
      res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed`);
    }
  })(req, res, next);
});

// ===== ROUTES OAUTH APPLE =====
router.get('/apple', (req, res) => {
  if (!hasAppleConfig) {
    return res.status(501).json({
      error: 'Apple OAuth non configuré',
      message: 'Les variables d\'environnement Apple OAuth ne sont pas définies'
    });
  }
  passport.authenticate('apple')(req, res);
});

router.post('/apple/callback', (req, res, next) => {
  if (!hasAppleConfig) {
    return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=oauth_disabled`);
  }

  passport.authenticate('apple', { session: false }, async (err, user) => {
    if (err || !user) {
      console.error('Erreur Apple OAuth:', err);
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed`);
    }

    try {
      // Générer les tokens
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret',
        { expiresIn: '7d' }
      );

      // Définir les cookies
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      // Rediriger vers le client
      res.redirect(process.env.CLIENT_URL || 'http://localhost:3000');
    } catch (error) {
      console.error('Erreur traitement callback Apple:', error);
      res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed`);
    }
  })(req, res, next);
});

// REFRESH TOKEN
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(401).json({ error: "Token de rafraîchissement manquant" });
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret');
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    // Générer un nouveau access token
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '15m' }
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000
    });

    res.json({ message: "Token rafraîchi" });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: "Token invalide" });
  }
});

// ROUTE /ME
router.get('/me', async (req, res) => {
  try {
    const { accessToken } = req.cookies;

    if (!accessToken) {
      // Mode développement - utilisateur demo si aucun OAuth configuré
      if (process.env.NODE_ENV === 'development' || (!hasGoogleConfig && !hasFacebookConfig && !hasAppleConfig)) {
        return res.json({
          user: {
            _id: 'demo-user-id',
            username: 'Utilisateur Demo',
            email: 'demo@example.com',
            provider: 'demo',
            avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=100&h=100&fit=crop&crop=face'
          }
        });
      }
      return res.status(401).json({ error: "Token manquant" });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET || 'fallback-secret');
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    res.json({ user });
  } catch (err) {
    console.error(err);
    // En cas d'erreur de token, renvoyer utilisateur demo en mode développement
    if (process.env.NODE_ENV === 'development' || (!hasGoogleConfig && !hasFacebookConfig && !hasAppleConfig)) {
      return res.json({
        user: {
          _id: 'demo-user-id',
          username: 'Utilisateur Demo',
          email: 'demo@example.com',
          provider: 'demo',
          avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=100&h=100&fit=crop&crop=face'
        }
      });
    }
    res.status(401).json({ error: "Token invalide" });
  }
});

// LOGIN DE DÉMONSTRATION (AUTOMATIQUE)
router.post('/demo-login', async (req, res) => {
  try {
    const { email, username, phone, password } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email requis pour la démo" });
    }

    // Chercher l'utilisateur
    let user = await User.findOne({ email });

    // Si l'utilisateur n'existe pas, on le CRÉE AUTOMATIQUEMENT
    if (!user) {
      const generatedUsername = username || email.split('@')[0];

      user = new User({
        username: generatedUsername,
        email: email,
        phone: phone || null,
        password: password || 'demo-password',
      });

      await user.save();
      console.log(`👤 Nouvel utilisateur de démo créé : ${email}`);
    }

    // Générer les tokens JWT
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret',
      { expiresIn: '7d' }
    );

    // Définir les cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000 // 1 heure
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
    });

    res.json({
      message: "Connexion DEMO réussie !",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      },
      securityWarning: "⚠️ MODE DÉMO ACTIVÉ : Aucune vérification d'identité réelle."
    });

  } catch (err) {
    console.error("Erreur lors de la connexion demo:", err);
    res.status(500).json({ error: "Erreur serveur lors de la démo" });
  }
});

// ENVOI CODE SMS TÉLÉPHONE
router.post('/send-phone-code', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ error: "Numéro de téléphone requis" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    let user = await User.findOne({ phone });
    if (user) {
      user.phoneVerificationCode = code;
      user.phoneVerificationExpires = expires;
      await user.save();
    } else {
      console.log(`📱 Code SMS pour ${phone}: ${code}`);
    }

    console.log(`📱 Code envoyé à ${phone}: ${code}`);

    res.json({
      message: "Code envoyé par SMS",
      devCode: code // EN DÉVELOPPEMENT SEULEMENT
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur envoi SMS" });
  }
});

// CONNEXION TÉLÉPHONE
router.post('/login-phone', async (req, res) => {
  try {
    const { phone, code, password } = req.body;

    if (!phone || !code || !password) {
      return res.status(400).json({ error: "Téléphone, code et mot de passe requis" });
    }

    const user = await User.findOne({
      phone,
      phoneVerificationCode: code,
      phoneVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    // Vérifier le mot de passe (commenté pour correspondre à votre logique)
    // const isMatch = await bcrypt.compare(password, user.password);
    const isMatch = (password === user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Mot de passe incorrect" });
    }

    // Nettoyer le code
    user.phoneVerificationCode = undefined;
    user.phoneVerificationExpires = undefined;
    user.isPhoneVerified = true;
    await user.save();

    // Générer tokens
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET || 'fallback-refresh-secret',
      { expiresIn: '7d' }
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      message: "Connexion réussie par téléphone",
      user: {
        id: user._id,
        username: user.username,
        phone: user.phone
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// QR CODE ROUTES
router.post('/generate-qr', (req, res) => {
  try {
    const qrCode = 'QR_' + Math.random().toString(36).substr(2, 9) + Date.now();

    global.qrCodes = global.qrCodes || new Map();
    global.qrCodes.set(qrCode, {
      created: Date.now(),
      authenticated: false,
      userId: null
    });

    setTimeout(() => {
      if (global.qrCodes) {
        global.qrCodes.delete(qrCode);
      }
    }, 120000);

    res.json({ qrCode });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur génération QR" });
  }
});

router.post('/check-qr', (req, res) => {
  try {
    const { qrCode } = req.body;

    if (!global.qrCodes || !global.qrCodes.has(qrCode)) {
      return res.status(400).json({ error: "QR Code invalide" });
    }

    const qrData = global.qrCodes.get(qrCode);

    res.json({
      authenticated: qrData.authenticated,
      userId: qrData.userId
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur vérification QR" });
  }
});

router.post('/confirm-qr', async (req, res) => {
  try {
    const { qrCode } = req.body;
    const { accessToken } = req.cookies;

    if (!accessToken) {
      return res.status(401).json({ error: "Non authentifié" });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET || 'fallback-secret');
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    if (!global.qrCodes || !global.qrCodes.has(qrCode)) {
      return res.status(400).json({ error: "QR Code invalide" });
    }

    global.qrCodes.set(qrCode, {
      ...global.qrCodes.get(qrCode),
      authenticated: true,
      userId: user._id
    });

    res.json({ message: "QR Code confirmé" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur confirmation QR" });
  }
});

// Route de statut pour diagnostiquer
router.get('/status', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    providers: {
      google: hasGoogleConfig ? 'Activé' : 'Désactivé',
      facebook: hasFacebookConfig ? 'Activé' : 'Désactivé',
      apple: hasAppleConfig ? 'Activé' : 'Désactivé'
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

module.exports = router;