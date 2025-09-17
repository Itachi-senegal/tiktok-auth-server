require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Importer la configuration passport
require('./config/passport');

// Importer les routes
const authRoutes = require('./routes/auth');

const app = express();

// Middleware de sécurité
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limite à 100 requêtes par IP toutes les 15 minutes
});
app.use(limiter);

// Middleware de parsing
app.use(express.json());
app.use(cookieParser());

// CORS
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Passport middleware
app.use(passport.initialize());

// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connecté'))
  .catch(err => console.error('❌ Erreur MongoDB:', err));

// Routes
app.use('/auth', authRoutes);

// Route de test
app.get('/', (req, res) => {
  res.json({ message: 'API TikTok Auth running 🚀' });
});

// Gestion des erreurs 404
app.use((req, res, next) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

// Gestion des erreurs globales
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur backend sur http://localhost:${PORT}`);
});