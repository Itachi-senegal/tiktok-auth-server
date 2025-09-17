const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../models/User');

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
    const hashedPassword = await bcrypt.hash(password, 10);

    // Création utilisateur
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
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
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Email ou mot de passe incorrect" });
    }

    // Générer les tokens JWT
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
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

// ROUTES OAUTH GOOGLE
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

router.get('/google/callback',
  passport.authenticate('google', { session: false }),
  async (req, res) => {
    try {
      const user = req.user;

      // Générer les tokens
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET,
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
      res.redirect(`${process.env.CLIENT_URL}/home`);
    } catch (err) {
      console.error(err);
      res.redirect(`${process.env.CLIENT_URL}/login?error=auth_failed`);
    }
  }
);

// ROUTES OAUTH FACEBOOK
router.get('/facebook', passport.authenticate('facebook', {
  scope: ['email']
}));

router.get('/facebook/callback',
  passport.authenticate('facebook', { session: false }),
  async (req, res) => {
    try {
      const user = req.user;

      // Générer les tokens
      const accessToken = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SECRET,
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
      res.redirect(process.env.CLIENT_URL);
    } catch (err) {
      console.error(err);
      res.redirect(`${process.env.CLIENT_URL}/login?error=auth_failed`);
    }
  }
);

// REFRESH TOKEN
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(401).json({ error: "Token de rafraîchissement manquant" });
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    // Générer un nouveau access token
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
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

// ENVOI CODE SMS TÉLÉPHONE
router.post('/send-phone-code', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ error: "Numéro de téléphone requis" });
    }

    // Générer un code à 6 chiffres
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Vérifier si l'utilisateur existe
    let user = await User.findOne({ phone });
    if (user) {
      user.phoneVerificationCode = code;
      user.phoneVerificationExpires = expires;
      await user.save();
    } else {
      // Pour le développement, on simule l'envoi
      console.log(`📱 Code SMS pour ${phone}: ${code}`);
    }

    // ICI: Intégrer un service SMS (Twilio, AWS SNS, etc.)
    // await sendSMS(phone, `Votre code TikTok: ${code}`);

    // Pour le développement
    console.log(`📱 Code envoyé à ${phone}: ${code}`);

    res.json({
      message: "Code envoyé par SMS",
      // EN DÉVELOPPEMENT SEULEMENT - À RETIRER EN PRODUCTION
      devCode: code
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

    // Vérifier l'utilisateur et le code
    const user = await User.findOne({
      phone,
      phoneVerificationCode: code,
      phoneVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    // Vérifier le mot de passe
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Mot de passe incorrect" });
    }

    // Nettoyer le code de vérification
    user.phoneVerificationCode = undefined;
    user.phoneVerificationExpires = undefined;
    user.isPhoneVerified = true;
    await user.save();

    // Générer les tokens
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Cookies
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

// GÉNÉRER QR CODE
router.post('/generate-qr', (req, res) => {
  try {
    // Générer un QR code unique
    const qrCode = 'QR_' + Math.random().toString(36).substr(2, 9) + Date.now();

    // Stocker en mémoire (en production, utilisez Redis)
    global.qrCodes = global.qrCodes || new Map();
    global.qrCodes.set(qrCode, {
      created: Date.now(),
      authenticated: false,
      userId: null
    });

    // Nettoyer les anciens QR codes (>2min)
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

// VÉRIFIER QR CODE
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

// CONFIRMER QR CODE (utilisé par l'app mobile)
router.post('/confirm-qr', async (req, res) => {
  try {
    const { qrCode } = req.body;
    const { accessToken } = req.cookies;

    if (!accessToken) {
      return res.status(401).json({ error: "Non authentifié" });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    if (!global.qrCodes || !global.qrCodes.has(qrCode)) {
      return res.status(400).json({ error: "QR Code invalide" });
    }

    // Marquer comme authentifié
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
router.get('/me', async (req, res) => {
  try {
    const { accessToken } = req.cookies;

    if (!accessToken) {
      return res.status(401).json({ error: "Token manquant" });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }

    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: "Token invalide" });
  }
});

module.exports = router;