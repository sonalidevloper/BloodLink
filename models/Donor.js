const mongoose = require('mongoose');

const donorSchema = new mongoose.Schema({
  userId:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bloodType:      { type: String, required: true },
  available:      { type: Boolean, default: true },
  location:       {
    lat: { type: Number, default: 0 },
    lng: { type: Number, default: 0 }
  },
  donationsCount: { type: Number, default: 0 },
  lastDonation:   { type: Date, default: null },
  nextEligible:   { type: Date, default: null },
  verified:       { type: Boolean, default: false },
  updatedAt:      { type: Date, default: Date.now }
});

module.exports = mongoose.model('Donor', donorSchema);