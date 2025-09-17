const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  //password: { type: String, required: false }, // Optionnel pour OAuth
  password: { type: String },
  provider: { type: String, default: 'local' }, // 'local', 'google', 'facebook'
  providerId: { type: String }, // ID du provider OAuth
  avatar: { type: String }, // URL de l'avatar
  isPhoneVerified: { type: Boolean, default: false }, // Vérification téléphone
  phoneVerificationCode: { type: String }, // Code de vérification temporaire
  phoneVerificationExpires: { type: Date }, // Expiration du code
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);