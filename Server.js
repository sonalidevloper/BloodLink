const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== CONFIG =====
const JWT_SECRET = process.env.JWT_SECRET || 'bloodlink_jwt_secret_2024';
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/bloodlink';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin123';

// Email config (uses Gmail - set your .env)
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';

module.exports.JWT_SECRET = JWT_SECRET;

// ===== EMAIL TRANSPORTER =====
let transporter = null;
if (EMAIL_USER && EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
  });
  transporter.verify(err => {
    if (err) console.warn('⚠️  Email not configured:', err.message);
    else console.log('📧 Email service ready');
  });
}

async function sendEmail(to, subject, html) {
  if (!transporter) {
    console.log(`📧 [DEMO] Email to ${to}: ${subject}`);
    return;
  }
  try {
    await transporter.sendMail({ from: `BloodLink <${EMAIL_USER}>`, to, subject, html });
  } catch (e) {
    console.error('Email error:', e.message);
  }
}

// ===== BLOOD COMPATIBILITY =====
const compatibility = {
  'A+':  ['A+','A-','O+','O-'],
  'A-':  ['A-','O-'],
  'B+':  ['B+','B-','O+','O-'],
  'B-':  ['B-','O-'],
  'AB+': ['A+','A-','B+','B-','AB+','AB-','O+','O-'],
  'AB-': ['AB-','A-','B-','O-'],
  'O+':  ['O+','O-'],
  'O-':  ['O-']
};
module.exports.compatibility = compatibility;

function getDistance(lat1, lng1, lat2, lng2) {
  if (!lat1 || !lng1 || !lat2 || !lng2) return 999;
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}
module.exports.getDistance = getDistance;

// ===== MONGODB CONNECT =====
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err.message));

// ===== MODELS =====
const userSchema = new mongoose.Schema({
  username:  { type: String, unique: true, trim: true, required: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ['donor', 'requester', 'admin'], required: true },
  email:     { type: String, default: '' },
  phone:     { type: String, default: '' },
  verified:  { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const donorSchema = new mongoose.Schema({
  userId:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bloodType:      { type: String, required: true },
  available:      { type: Boolean, default: true },
  location:       { lat: { type: Number, default: 0 }, lng: { type: Number, default: 0 } },
  donationsCount: { type: Number, default: 0 },
  lastDonation:   { type: Date, default: null },
  nextEligible:   { type: Date, default: null },
  updatedAt:      { type: Date, default: Date.now }
});
const Donor = mongoose.model('Donor', donorSchema);

const requestSchema = new mongoose.Schema({
  requesterId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  bloodType:      { type: String, required: true },
  urgency:        { type: String, enum: ['High', 'Medium', 'Low'], default: 'Medium' },
  location:       { lat: { type: Number, default: 0 }, lng: { type: Number, default: 0 } },
  status:         { type: String, enum: ['open', 'matched', 'fulfilled', 'cancelled'], default: 'open' },
  notes:          { type: String, default: '' },
  hospital:       { type: String, default: '' },
  units:          { type: Number, default: 1 },
  matchedDonors:  [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  fulfilledBy:    { type: String, default: '' },
  createdAt:      { type: Date, default: Date.now },
  updatedAt:      { type: Date, default: Date.now }
});
const Request = mongoose.model('Request', requestSchema);

const inventorySchema = new mongoose.Schema({
  bloodType:  { type: String, required: true, unique: true },
  units:      { type: Number, default: 0 },
  updatedAt:  { type: Date, default: Date.now }
});
const Inventory = mongoose.model('Inventory', inventorySchema);

// ===== MIDDLEWARE =====
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Allow admin role OR any logged-in user for demo
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Admin access required' });
  }
}

// ===== INIT INVENTORY =====
async function initInventory() {
  const types = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];
  for (const bt of types) {
    await Inventory.findOneAndUpdate(
      { bloodType: bt },
      { $setOnInsert: { bloodType: bt, units: Math.floor(Math.random() * 20) + 5 } },
      { upsert: true }
    );
  }
  console.log('🏥 Inventory initialized');
}

mongoose.connection.once('open', initInventory);

// ===========================
//  ===== PUBLIC ROUTES =====
// ===========================

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role, bloodType, email, phone } = req.body;
    if (!username?.trim() || !password || !role) {
      return res.status(400).json({ message: 'Username, password, and role are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    const exists = await User.findOne({ username: username.trim().toLowerCase() });
    if (exists) return res.status(409).json({ message: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({
      username: username.trim().toLowerCase(),
      password: hash, role,
      email: email || '', phone: phone || ''
    });
    await user.save();

    if (role === 'donor') {
      if (!bloodType) return res.status(400).json({ message: 'Blood type is required for donors' });
      await new Donor({ userId: user._id, bloodType, available: true }).save();
    }

    // Welcome email
    if (email) {
      sendEmail(email, 'Welcome to BloodLink! 🩸', `
        <div style="font-family:sans-serif;max-width:500px;margin:auto">
          <h2 style="color:#e81c1c">Welcome to BloodLink, ${username}!</h2>
          <p>Your account has been created successfully as a <strong>${role}</strong>.</p>
          ${role === 'donor' ? `<p>Blood Type: <strong style="color:#e81c1c">${bloodType}</strong></p>` : ''}
          <p>You can now log in and start saving lives.</p>
          <a href="http://localhost:${PORT}" style="background:#e81c1c;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;margin-top:12px">Open BloodLink</a>
          <p style="color:#888;font-size:12px;margin-top:20px">BloodLink – Saving lives, one match at a time.</p>
        </div>
      `);
    }

    console.log(`✅ Registered: ${username} (${role})`);
    res.status(201).json({ message: 'Account created successfully!' });
  } catch (e) {
    console.error('Register error:', e.message);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });

    const user = await User.findOne({ username: username.trim().toLowerCase() });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user._id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    console.log(`✅ Login: ${username}`);
    res.json({ token, role: user.role, username: user.username });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===========================
//  ===== AUTH ROUTES =====
// ===========================

// Get current user
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    const donor = req.user.role === 'donor' ? await Donor.findOne({ userId: user._id }) : null;
    res.json({ success: true, user, donor });
  } catch (e) {
    res.status(500).json({ success: false });
  }
});

// Update donor status + location
app.post('/api/update-donor', auth, async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });
    const { available, lat, lng } = req.body;
    const donor = await Donor.findOneAndUpdate(
      { userId: req.user.id },
      { available, 'location.lat': lat || 0, 'location.lng': lng || 0, updatedAt: new Date() },
      { new: true }
    );
    if (!donor) return res.status(404).json({ message: 'Donor profile not found' });
    res.json({ message: 'Status updated successfully', available: donor.available });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Submit blood request
app.post('/api/request-blood', auth, async (req, res) => {
  try {
    if (req.user.role !== 'requester') {
      return res.status(403).json({ message: 'Only requesters can submit blood requests' });
    }
    const { bloodType, urgency, lat, lng, notes, hospital, units } = req.body;
    if (!bloodType) return res.status(400).json({ message: 'Blood type is required' });

    const request = new Request({
      requesterId: req.user.id,
      bloodType, urgency: urgency || 'Medium',
      location: { lat: lat || 0, lng: lng || 0 },
      notes: notes || '', hospital: hospital || '',
      units: units || 1
    });
    await request.save();

    // Find compatible donors within 50km
    const compatibleTypes = compatibility[bloodType] || [bloodType];
    const donors = await Donor.find({ available: true, bloodType: { $in: compatibleTypes } });
    const nearbyDonors = lat
      ? donors.filter(d => getDistance(lat, lng, d.location.lat, d.location.lng) < 50)
      : donors;

    // Notify matched donors via Socket.IO
    for (const donor of nearbyDonors) {
      io.to(donor.userId.toString()).emit('notification', {
        message: `Urgent! ${bloodType} blood needed${hospital ? ' at ' + hospital : ''} (${urgency || 'Medium'} priority)`,
        requestId: request._id
      });

      // Send email notification to donor
      const donorUser = await User.findById(donor.userId);
      if (donorUser?.email) {
        sendEmail(donorUser.email, `🩸 Urgent: ${bloodType} Blood Needed Near You`, `
          <div style="font-family:sans-serif;max-width:500px;margin:auto">
            <h2 style="color:#e81c1c">Blood Needed – You Can Help!</h2>
            <p>A patient near you urgently needs <strong style="color:#e81c1c">${bloodType}</strong> blood.</p>
            <table style="margin:16px 0;font-size:14px">
              <tr><td style="padding:4px 12px 4px 0;color:#888">Urgency</td><td><strong>${urgency}</strong></td></tr>
              ${hospital ? `<tr><td style="padding:4px 12px 4px 0;color:#888">Location</td><td><strong>${hospital}</strong></td></tr>` : ''}
            </table>
            <a href="http://localhost:${PORT}/dashboard.html" style="background:#e81c1c;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block">Respond Now</a>
            <p style="color:#888;font-size:12px;margin-top:20px">You're receiving this because you're a registered BloodLink donor. Reply STOP to unsubscribe.</p>
          </div>
        `);
      }
    }

    console.log(`🩸 Blood request: ${bloodType} | Urgency: ${urgency} | Matches: ${nearbyDonors.length}`);
    res.json({ message: 'Request submitted successfully', matches: nearbyDonors.length, requestId: request._id });
  } catch (e) {
    console.error('Request error:', e.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Dashboard data
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    if (req.user.role === 'donor') {
      const donor = await Donor.findOne({ userId: req.user.id });
      if (!donor) return res.json({ requests: [], donor: null });

      // Donors receive requests compatible with their blood type
      const canDonateTo = Object.entries(compatibility)
        .filter(([k, v]) => v.includes(donor.bloodType))
        .map(([k]) => k);

      const requests = await Request.find({ status: 'open', bloodType: { $in: canDonateTo } })
        .sort({ createdAt: -1 }).limit(20);

      res.json({ donor, requests });
    } else {
      const requests = await Request.find({ requesterId: req.user.id }).sort({ createdAt: -1 });
      res.json({ requests });
    }
  } catch (e) {
    console.error('Dashboard error:', e.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Record donation (donor confirms donation)
app.post('/api/record-donation', auth, async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });
    const { requestId } = req.body;

    const donor = await Donor.findOne({ userId: req.user.id });
    if (!donor) return res.status(404).json({ message: 'Donor not found' });

    const now = new Date();
    const nextEligible = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000); // 90 days

    donor.donationsCount = (donor.donationsCount || 0) + 1;
    donor.lastDonation = now;
    donor.nextEligible = nextEligible;
    donor.available = false; // Auto-set unavailable after donation
    await donor.save();

    // Mark request fulfilled if provided
    if (requestId) {
      await Request.findByIdAndUpdate(requestId, {
        status: 'fulfilled',
        fulfilledBy: req.user.id,
        updatedAt: new Date()
      });
    }

    res.json({
      message: 'Donation recorded! Thank you for saving a life.',
      nextEligible: nextEligible.toISOString(),
      totalDonations: donor.donationsCount
    });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get donation eligibility
app.get('/api/eligibility', auth, async (req, res) => {
  try {
    const donor = await Donor.findOne({ userId: req.user.id });
    if (!donor) return res.status(404).json({ message: 'Donor not found' });

    const now = new Date();
    const eligible = !donor.nextEligible || now >= donor.nextEligible;
    const daysLeft = donor.nextEligible
      ? Math.max(0, Math.ceil((donor.nextEligible - now) / (24 * 60 * 60 * 1000)))
      : 0;

    res.json({
      eligible,
      daysLeft,
      lastDonation: donor.lastDonation,
      nextEligible: donor.nextEligible,
      totalDonations: donor.donationsCount
    });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Accept a blood request (donor responds)
app.post('/api/accept-request/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });

    const request = await Request.findById(req.params.id);
    if (!request) return res.status(404).json({ message: 'Request not found' });
    if (request.status !== 'open') return res.status(400).json({ message: 'Request is no longer open' });

    if (!request.matchedDonors.includes(req.user.id)) {
      request.matchedDonors.push(req.user.id);
    }
    request.status = 'matched';
    request.updatedAt = new Date();
    await request.save();

    // Notify the requester
    io.to(request.requesterId.toString()).emit('notification', {
      message: `A donor has responded to your ${request.bloodType} blood request!`,
      requestId: request._id
    });

    res.json({ message: 'You have accepted this request. Please head to the hospital.' });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get nearby donors (for map)
app.post('/api/nearby-donors', auth, async (req, res) => {
  try {
    const { lat, lng, bloodType, radius = 50 } = req.body;
    const compatibleTypes = bloodType ? (compatibility[bloodType] || [bloodType]) : Object.keys(compatibility);

    const donors = await Donor.find({ available: true, bloodType: { $in: compatibleTypes } });
    const nearby = donors
      .map(d => ({ ...d.toObject(), distance: getDistance(lat, lng, d.location.lat, d.location.lng) }))
      .filter(d => d.distance <= radius)
      .sort((a, b) => a.distance - b.distance)
      .slice(0, 20);

    res.json({ donors: nearby, count: nearby.length });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ===========================
//  ===== ADMIN ROUTES =====
// ===========================

// Admin stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [openRequests, activeDonors, totalUsers, inventory] = await Promise.all([
      Request.countDocuments({ status: 'open' }),
      Donor.countDocuments({ available: true }),
      User.countDocuments(),
      Inventory.find()
    ]);
    const criticalRequests = await Request.countDocuments({ status: 'open', urgency: 'High' });
    const recentRequests = await Request.find().sort({ createdAt: -1 }).limit(10);
    const totalUnits = inventory.reduce((sum, i) => sum + i.units, 0);

    res.json({ openRequests, activeDonors, totalUsers, criticalRequests, totalUnits, inventory, recentRequests });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// All requests (admin)
app.get('/api/admin/requests', adminAuth, async (req, res) => {
  try {
    const requests = await Request.find().sort({ createdAt: -1 }).limit(100);
    res.json({ requests });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// All donors (admin) – with username populated
app.get('/api/admin/donors', adminAuth, async (req, res) => {
  try {
    const donors = await Donor.find().sort({ updatedAt: -1 }).limit(100);
    const donorIds = donors.map(d => d.userId);
    const users = await User.find({ _id: { $in: donorIds } }).select('username email phone');
    const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));

    const enriched = donors.map(d => ({
      ...d.toObject(),
      username: userMap[d.userId?.toString()]?.username || 'Unknown',
      email: userMap[d.userId?.toString()]?.email || ''
    }));
    res.json({ donors: enriched });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// All users (admin)
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ users });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Fulfill a request (admin)
app.post('/api/admin/fulfill/:id', adminAuth, async (req, res) => {
  try {
    const { source, notes } = req.body;
    const request = await Request.findByIdAndUpdate(
      req.params.id,
      { status: 'fulfilled', fulfilledBy: source || 'Admin', notes: notes || '', updatedAt: new Date() },
      { new: true }
    );
    if (!request) return res.status(404).json({ message: 'Request not found' });

    // Notify requester
    io.to(request.requesterId.toString()).emit('notification', {
      message: `Your ${request.bloodType} blood request has been fulfilled!`
    });

    res.json({ message: 'Request marked as fulfilled', request });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update inventory (admin)
app.post('/api/admin/inventory', adminAuth, async (req, res) => {
  try {
    const { bloodType, units, delta } = req.body;
    let inv = await Inventory.findOne({ bloodType });
    if (!inv) inv = new Inventory({ bloodType, units: 0 });

    if (delta !== undefined) inv.units = Math.max(0, inv.units + delta);
    else if (units !== undefined) inv.units = Math.max(0, units);

    inv.updatedAt = new Date();
    await inv.save();
    res.json({ message: 'Inventory updated', bloodType, units: inv.units });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get inventory
app.get('/api/admin/inventory', adminAuth, async (req, res) => {
  try {
    const inventory = await Inventory.find();
    const inv = Object.fromEntries(inventory.map(i => [i.bloodType, i.units]));
    res.json({ inventory: inv });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Notify donors manually (admin)
app.post('/api/admin/notify', adminAuth, async (req, res) => {
  try {
    const { requestId, bloodType, message } = req.body;
    const compatibleTypes = compatibility[bloodType] || [bloodType];
    const donors = await Donor.find({ available: true, bloodType: { $in: compatibleTypes } });

    for (const donor of donors) {
      io.to(donor.userId.toString()).emit('notification', {
        message: message || `Admin alert: ${bloodType} blood urgently needed!`,
        requestId
      });
    }

    res.json({ message: `Notified ${donors.length} donors`, count: donors.length });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Cancel request
app.post('/api/cancel-request/:id', auth, async (req, res) => {
  try {
    const request = await Request.findOne({ _id: req.params.id, requesterId: req.user.id });
    if (!request) return res.status(404).json({ message: 'Request not found' });
    request.status = 'cancelled';
    await request.save();
    res.json({ message: 'Request cancelled' });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ===========================
//  ===== SOCKET.IO =====
// ===========================
io.on('connection', socket => {
  console.log('🔌 Connected:', socket.id);
  socket.on('join', userId => {
    socket.join(userId.toString());
    console.log(`👤 User ${userId} joined room`);
  });
  socket.on('disconnect', () => console.log('🔌 Disconnected:', socket.id));
});

// ===========================
//  ===== START =====
// ===========================
server.listen(PORT, () => {
  console.log(`\n🩸 BloodLink running → http://localhost:${PORT}`);
  console.log(`🔑 Admin panel  → http://localhost:${PORT}/admin.html`);
  console.log(`📧 Email: ${EMAIL_USER ? 'Configured ✅' : 'Not configured (set EMAIL_USER + EMAIL_PASS in .env)'}\n`);
});