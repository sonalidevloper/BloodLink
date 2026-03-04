// routes/api.js
const express = require('express');
const router = express.Router();
const auth = require('../auth'); // We'll create this middleware next

// Import models (for dashboard, etc.)
const User = require('../models/User');
const Donor = require('../models/Donor');
const Request = require('../models/Request');

// Register (public)
router.post('/register', async (req, res) => {
  try {
    console.log('Register attempt:', req.body); // Log for debugging
    const { username, password, role, bloodType } = req.body;
    if (!username || !password || !role) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'Username already exists' });
    }
    const hashedPw = await require('bcryptjs').hash(password, 10);
    const user = new User({ username, password: hashedPw, role });
    await user.save();
    console.log('User registered:', user._id); // Log success
    if (role === 'donor') {
      const donor = new Donor({ userId: user._id, bloodType, available: true, location: { lat: 0, lng: 0 } });
      await donor.save();
      console.log('Donor created:', donor._id);
    }
    res.status(201).json({ message: 'Registered successfully' });
  } catch (err) {
    console.error('Register error:', err); // Log errors
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login (public)
router.post('/login', async (req, res) => {
  try {
    console.log('Login attempt:', req.body.username); // Log for debugging
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !await require('bcryptjs').compare(password, user.password)) {
      console.log('Invalid login for:', username);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = require('jsonwebtoken').sign({ id: user._id, role: user.role }, require('../server').JWT_SECRET); // Use server JWT_SECRET
    console.log('Login success for:', username); // Log success
    res.json({ token, role: user.role });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Auth middleware (protect routes)
router.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    req.user = require('jsonwebtoken').verify(token, require('../server').JWT_SECRET);
    next();
  } catch (err) {
    console.error('Token verify error:', err);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Update donor (protected)
router.post('/update-donor', async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });
    const { available, lat, lng } = req.body;
    const donor = await Donor.findOne({ userId: req.user.id });
    if (!donor) return res.status(404).json({ message: 'Donor not found' });
    donor.available = available;
    donor.location = { lat, lng };
    await donor.save();
    console.log('Donor updated:', req.user.id);
    res.json({ message: 'Updated successfully' });
  } catch (err) {
    console.error('Update donor error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Post blood request (protected)
router.post('/request-blood', async (req, res) => {
  try {
    if (req.user.role !== 'requester') return res.status(403).json({ message: 'Not a requester' });
    const { bloodType, urgency, lat, lng } = req.body;
    const request = new Request({ requesterId: req.user.id, bloodType, urgency, location: { lat, lng }, status: 'open' });
    await request.save();
    console.log('Request posted:', request._id);

    // Simple matching (as in server.js)
    const compatibility = require('../server').compatibility; // Assume exported
    const donors = await Donor.find({ available: true, bloodType: { $in: compatibility[bloodType] || [] } });
    const getDistance = require('../server').getDistance;
    const matches = donors.filter(d => getDistance(lat, lng, d.location.lat, d.location.lng) < 50);
    console.log('Matches found:', matches.length);

    // Emit to Socket.io (server handles)
    res.json({ message: 'Request posted', matches: matches.length });
  } catch (err) {
    console.error('Request error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Dashboard data (protected)
router.get('/dashboard', async (req, res) => {
  try {
    if (req.user.role === 'donor') {
      const donor = await Donor.findOne({ userId: req.user.id }).populate('userId');
      const compatibility = require('../server').compatibility;
      const donorBlood = donor.bloodType;
      const requests = await Request.find({ status: 'open', bloodType: { $in: compatibility[donorBlood] || [] } });
      res.json({ donor, requests });
    } else {
      const requests = await Request.find({ requesterId: req.user.id });
      res.json({ requests });
    }
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;