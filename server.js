require('dotenv').config(); // Charger .env
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// CORS - autoriser localhost et frontend déployé
const allowedOrigins = [
  process.env.CLIENT_URL, // Exemple: http://localhost:3000 ou https://tiktok-auth-client.vercel.app
];

app.use(cors({
  origin: function(origin, callback) {
    // Autoriser les requêtes sans origin (Postman, serveur, mobile)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error(`CORS: Origin non autorisé (${origin})`), false);
    }
    return callback(null, true);
  },
  credentials: true, // Important pour les cookies
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

// Route test
app.get('/auth/test', (req, res) => {
  res.json({ message: 'Backend opérationnel !' });
});

// Lancer serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur backend sur ${process.env.NODE_ENV === 'production' ? process.env.SERVER_URL : `http://localhost:${PORT}`}`);
});
