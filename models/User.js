const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, trim: true, lowercase: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ['donor', 'requester', 'admin'], required: true },
  email:     { type: String, default: '' },
  phone:     { type: String, default: '' },
  verified:  { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);