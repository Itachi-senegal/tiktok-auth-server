require('dotenv').config(); // Charger les variables d'environnement depuis .env
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());

// CORS : accepter localhost pour dev et le front déployé sur Vercel
const allowedOrigins = [
  'http://localhost:3000', // frontend local
  'https://tiktok-auth-client.vercel.app' // frontend Vercel
];

app.use(cors({
  origin: function(origin, callback) {
    // autoriser les requêtes sans origine (ex: Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `L'accès CORS pour ${origin} est refusé`;
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true, // pour envoyer les cookies
}));

app.use(cookieParser());

// Connexion MongoDB
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/tiktok-auth';
mongoose.connect(mongoUri)
  .then(() => console.log("✅ MongoDB connecté"))
  .catch(err => console.error(err));

// Routes
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);

// Lancer serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Serveur backend sur http://localhost:${PORT}`));
