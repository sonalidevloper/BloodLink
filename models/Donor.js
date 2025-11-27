const mongoose = require('mongoose');

const donorSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  bloodType: { type: String, required: true },
  available: { type: Boolean, default: true },
  location: { lat: Number, lng: Number }
});

module.exports = mongoose.model('Donor', donorSchema);