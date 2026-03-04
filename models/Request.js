const mongoose = require('mongoose');

const requestSchema = new mongoose.Schema({
  requesterId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  bloodType:     { type: String, required: true },
  urgency:       { type: String, enum: ['High', 'Medium', 'Low'], default: 'Medium' },
  location:      {
    lat: { type: Number, default: 0 },
    lng: { type: Number, default: 0 }
  },
  status:        { type: String, enum: ['open', 'matched', 'fulfilled', 'cancelled'], default: 'open' },
  notes:         { type: String, default: '' },
  hospital:      { type: String, default: '' },
  units:         { type: Number, default: 1 },
  matchedDonors: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  fulfilledBy:   { type: String, default: '' },
  createdAt:     { type: Date, default: Date.now },
  updatedAt:     { type: Date, default: Date.now }
});

module.exports = mongoose.model('Request', requestSchema);