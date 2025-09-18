require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Configuration pour Render (proxy inverse)
app.set('trust proxy', true);

// Configuration CORS améliorée
const allowedOrigins = [
  'http://localhost:3000',                           // Développement local
  'https://tiktok-auth-client.vercel.app',          // Production Vercel
  process.env.CLIENT_URL                            // Variable d'environnement
].filter(Boolean); // Retire les valeurs undefined

console.log('🌍 Origins autorisées:', allowedOrigins);

app.use(cors({
  origin: function(origin, callback) {
    console.log('🔍 Origin de la requête:', origin);

    // Autoriser les requêtes sans origin (Postman, mobile apps)
    if (!origin) {
      console.log('✅ Requête sans origin autorisée');
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      console.log('✅ Origin autorisée:', origin);
      return callback(null, true);
    }

    console.log('❌ Origin non autorisée:', origin);
    console.log('📋 Origins autorisées:', allowedOrigins);
    return callback(new Error(`CORS: Origin non autorisé (${origin})`), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("✅ MongoDB connecté"))
  .catch(err => console.error("❌ Erreur MongoDB :", err));

// Routes
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);

// Route de base
app.get('/', (req, res) => {
  res.json({ message: 'Backend TikTok Auth OK!' });
});

// Route test
app.get('/auth/test', (req, res) => {
  res.json({
    message: 'Backend opérationnel !',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV
  });
});

// Middleware de gestion d'erreurs CORS
app.use((err, req, res, next) => {
  if (err.message.includes('CORS')) {
    console.log('❌ Erreur CORS:', err.message);
    return res.status(403).json({
      error: 'CORS Error',
      message: err.message,
      origin: req.headers.origin
    });
  }
  next(err);
});

// Lancer serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur backend sur ${process.env.NODE_ENV === 'production' ? process.env.SERVER_URL : `http://localhost:${PORT}`}`);
  console.log(`🌍 NODE_ENV: ${process.env.NODE_ENV}`);
  console.log(`🔗 CLIENT_URL: ${process.env.CLIENT_URL}`);
});