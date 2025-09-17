const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));
app.use(cookieParser());

// Connexion MongoDB
mongoose.connect('mongodb://localhost:27017/tiktok-auth')
  .then(() => console.log("✅ MongoDB connecté"))
  .catch(err => console.error(err));

// Routes
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);

// Lancer serveur
app.listen(5000, () => console.log("🚀 Serveur backend sur http://localhost:5000"));
