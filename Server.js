// ============================================================
//  BloodLink v4.0 – FINAL COMPLETE SERVER
//  Features: Auth, Real-time, Admin, Email, SMS, Verification
// ============================================================

require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');
const nodemailer = require('nodemailer');
const multer     = require('multer');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── CONFIG ──
const PORT         = process.env.PORT         || 3000;
const MONGO_URI    = process.env.MONGO_URI    || 'mongodb://127.0.0.1:27017/bloodlink';
const JWT_SECRET   = process.env.JWT_SECRET   || 'bloodlink_secret_change_in_prod';
const EMAIL_USER   = process.env.EMAIL_USER   || '';
const EMAIL_PASS   = process.env.EMAIL_PASS   || '';
const TWILIO_SID   = process.env.TWILIO_SID   || '';
const TWILIO_TOKEN = process.env.TWILIO_TOKEN || '';
const TWILIO_FROM  = process.env.TWILIO_FROM  || '';

module.exports.JWT_SECRET  = JWT_SECRET;

// ── MULTER (file uploads) ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    require('fs').mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s/g, '_')}`)
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ── EMAIL ──
let mailer = null;
if (EMAIL_USER && EMAIL_PASS) {
  mailer = nodemailer.createTransport({ service: 'gmail', auth: { user: EMAIL_USER, pass: EMAIL_PASS } });
  mailer.verify(err => err ? console.warn('⚠️  Email:', err.message) : console.log('📧 Email ready'));
}
async function sendEmail(to, subject, html) {
  if (!mailer || !to) { console.log(`📧 [DEMO] → ${to}: ${subject}`); return; }
  try { await mailer.sendMail({ from: `BloodLink 🩸 <${EMAIL_USER}>`, to, subject, html }); }
  catch(e) { console.error('Email failed:', e.message); }
}

// ── SMS (Twilio) ──
let twilioClient = null;
if (TWILIO_SID && TWILIO_TOKEN) {
  try {
    twilioClient = require('twilio')(TWILIO_SID, TWILIO_TOKEN);
    console.log('📱 Twilio SMS ready');
  } catch(e) { console.warn('⚠️  Twilio not available. Run: npm install twilio'); }
}
async function sendSMS(to, message) {
  if (!twilioClient || !to) { console.log(`📱 [DEMO SMS] → ${to}: ${message}`); return; }
  try { await twilioClient.messages.create({ body: message, from: TWILIO_FROM, to }); }
  catch(e) { console.error('SMS failed:', e.message); }
}

// ── BLOOD COMPATIBILITY ──
const compatibility = {
  'A+':  ['A+','A-','O+','O-'],   'A-':  ['A-','O-'],
  'B+':  ['B+','B-','O+','O-'],   'B-':  ['B-','O-'],
  'AB+': ['A+','A-','B+','B-','AB+','AB-','O+','O-'], 'AB-': ['AB-','A-','B-','O-'],
  'O+':  ['O+','O-'],             'O-':  ['O-']
};
module.exports.compatibility = compatibility;

function getDistance(lat1, lng1, lat2, lng2) {
  if (!lat1||!lng1||!lat2||!lng2) return 9999;
  const R = 6371, dLat = (lat2-lat1)*Math.PI/180, dLng = (lng2-lng1)*Math.PI/180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}
module.exports.getDistance = getDistance;

// ── MONGODB ──
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err.message));

// ── MODELS ──
const userSchema = new mongoose.Schema({
  username:  { type: String, unique: true, trim: true, lowercase: true, required: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ['donor','requester','admin'], required: true },
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
  lastDonation:   Date,
  nextEligible:   Date,
  verified:       { type: Boolean, default: false },
  updatedAt:      { type: Date, default: Date.now }
});
const Donor = mongoose.model('Donor', donorSchema);

const requestSchema = new mongoose.Schema({
  requesterId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  bloodType:     { type: String, required: true },
  urgency:       { type: String, enum: ['High','Medium','Low'], default: 'Medium' },
  location:      { lat: { type: Number, default: 0 }, lng: { type: Number, default: 0 } },
  status:        { type: String, enum: ['open','matched','fulfilled','cancelled'], default: 'open' },
  notes:         { type: String, default: '' },
  hospital:      { type: String, default: '' },
  units:         { type: Number, default: 1 },
  matchedDonors: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  fulfilledBy:   { type: String, default: '' },
  createdAt:     { type: Date, default: Date.now },
  updatedAt:     { type: Date, default: Date.now }
});
const Request = mongoose.model('Request', requestSchema);

const inventorySchema = new mongoose.Schema({
  bloodType: { type: String, required: true, unique: true },
  units:     { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});
const Inventory = mongoose.model('Inventory', inventorySchema);

const verificationSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  firstName:   String, lastName: String, dob: String,
  phone:       String, email: String,
  docType:     String, docNumber: String,
  idFrontPath: String, idBackPath: String,
  weight:      String,
  status:      { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  adminNotes:  { type: String, default: '' },
  submittedAt: { type: Date, default: Date.now },
  reviewedAt:  Date
});
const Verification = mongoose.model('Verification', verificationSchema);

// ── MIDDLEWARE ──
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ message: 'Invalid or expired token' }); }
}
function adminAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ message: 'Access denied' }); }
}

// ── INIT INVENTORY ──
async function initInventory() {
  const types = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];
  for (const bt of types) {
    await Inventory.findOneAndUpdate({ bloodType: bt },
      { $setOnInsert: { bloodType: bt, units: Math.floor(Math.random()*20)+5 } },
      { upsert: true });
  }
  console.log('🏥 Inventory initialized');
}
mongoose.connection.once('open', initInventory);

// ============================================================
//  PUBLIC ROUTES
// ============================================================

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role, bloodType, email, phone } = req.body;
    if (!username?.trim() || !password || !role)
      return res.status(400).json({ message: 'Username, password and role required' });
    if (password.length < 6)
      return res.status(400).json({ message: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ username: username.trim().toLowerCase() });
    if (exists) return res.status(409).json({ message: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username: username.trim().toLowerCase(), password: hash, role, email: email||'', phone: phone||'' });

    if (role === 'donor') {
      if (!bloodType) return res.status(400).json({ message: 'Blood type required for donors' });
      await Donor.create({ userId: user._id, bloodType, available: true });
    }

    // Welcome email
    if (email) {
      sendEmail(email, 'Welcome to BloodLink! 🩸', `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:20px">
          <div style="background:#e81c1c;color:white;padding:24px;border-radius:12px 12px 0 0;text-align:center">
            <h1 style="margin:0;font-size:28px">🩸 BloodLink</h1>
          </div>
          <div style="background:#f9f9f9;padding:24px;border-radius:0 0 12px 12px">
            <h2>Welcome, ${username}! 👋</h2>
            <p>Your account is ready. You registered as a <strong>${role}</strong>.</p>
            ${role === 'donor' ? `<p>Blood Type: <strong style="color:#e81c1c;font-size:18px">${bloodType}</strong></p>` : ''}
            ${role === 'donor' ? `<p>Complete <a href="http://localhost:${PORT}/verify.html" style="color:#e81c1c">donor verification</a> to unlock all features.</p>` : ''}
            <a href="http://localhost:${PORT}" style="display:inline-block;background:#e81c1c;color:white;padding:12px 28px;border-radius:8px;text-decoration:none;margin-top:12px;font-weight:600">Open App →</a>
          </div>
        </div>
      `);
    }
    if (phone) sendSMS(phone, `Welcome to BloodLink! Your ${role} account is ready. Visit http://localhost:${PORT}`);

    console.log(`✅ Registered: ${username} (${role})`);
    res.status(201).json({ message: 'Account created successfully!' });
  } catch(e) {
    console.error('Register error:', e.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'All fields required' });
    const user = await User.findOne({ username: username.trim().toLowerCase() });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(401).json({ message: 'Invalid username or password' });
    const token = jwt.sign({ id: user._id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    console.log(`✅ Login: ${username}`);
    res.json({ token, role: user.role, username: user.username });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

// ============================================================
//  AUTH ROUTES
// ============================================================

app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    const donor = req.user.role === 'donor' ? await Donor.findOne({ userId: user._id }) : null;
    const verification = await Verification.findOne({ userId: user._id }).select('status submittedAt');
    res.json({ success: true, user, donor, verification });
  } catch(e) { res.status(500).json({ success: false }); }
});

app.post('/api/update-donor', auth, async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });
    const { available, lat, lng } = req.body;
    const donor = await Donor.findOneAndUpdate(
      { userId: req.user.id },
      { available, 'location.lat': lat||0, 'location.lng': lng||0, updatedAt: new Date() },
      { new: true }
    );
    res.json({ message: 'Updated', available: donor.available });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/request-blood', auth, async (req, res) => {
  try {
    if (req.user.role !== 'requester') return res.status(403).json({ message: 'Only requesters can post requests' });
    const { bloodType, urgency, lat, lng, notes, hospital, units } = req.body;
    if (!bloodType) return res.status(400).json({ message: 'Blood type required' });

    const request = await Request.create({
      requesterId: req.user.id, bloodType, urgency: urgency||'Medium',
      location: { lat: lat||0, lng: lng||0 }, notes: notes||'', hospital: hospital||'', units: units||1
    });

    // Find and notify matching donors
    const compatTypes = compatibility[bloodType] || [bloodType];
    const donors = await Donor.find({ available: true, bloodType: { $in: compatTypes } });
    const nearby = lat ? donors.filter(d => getDistance(lat,lng,d.location.lat,d.location.lng) < 50) : donors;

    for (const donor of nearby) {
      // Socket notification
      io.to(donor.userId.toString()).emit('notification', {
        message: `Urgent! ${bloodType} needed${hospital?' at '+hospital:''} · ${urgency||'Medium'} priority`,
        requestId: request._id
      });

      // Get donor user for email/SMS
      const donorUser = await User.findById(donor.userId);
      if (donorUser?.email) {
        sendEmail(donorUser.email, `🩸 Urgent: ${bloodType} Blood Needed`, `
          <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:20px">
            <div style="background:#e81c1c;padding:20px;border-radius:12px 12px 0 0;color:white;text-align:center">
              <h1>🚨 Urgent Blood Request</h1>
            </div>
            <div style="background:#fff;padding:24px;border:1px solid #eee;border-radius:0 0 12px 12px">
              <p>Hi ${donorUser.username},</p>
              <p>A patient urgently needs <strong style="color:#e81c1c;font-size:20px">${bloodType}</strong> blood.</p>
              <table style="font-size:14px;margin:16px 0;border-collapse:collapse;width:100%">
                <tr><td style="padding:8px;color:#888;border-bottom:1px solid #eee">Urgency</td><td style="padding:8px;font-weight:700;border-bottom:1px solid #eee">${urgency||'Medium'}</td></tr>
                ${hospital?`<tr><td style="padding:8px;color:#888;border-bottom:1px solid #eee">Hospital</td><td style="padding:8px;font-weight:700;border-bottom:1px solid #eee">${hospital}</td></tr>`:''}
                ${notes?`<tr><td style="padding:8px;color:#888">Notes</td><td style="padding:8px">${notes}</td></tr>`:''}
              </table>
              <a href="http://localhost:${PORT}/dashboard.html" style="display:inline-block;background:#e81c1c;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:16px">Respond Now →</a>
              <p style="color:#888;font-size:11px;margin-top:20px">You received this because you're a BloodLink donor with compatible blood type.</p>
            </div>
          </div>
        `);
      }
      if (donorUser?.phone) {
        sendSMS(donorUser.phone,
          `🩸 URGENT: ${bloodType} blood needed${hospital?' at '+hospital:''}. Open BloodLink to respond: http://localhost:${PORT}/dashboard.html`
        );
      }
    }

    console.log(`🩸 Request: ${bloodType} | ${urgency} | ${nearby.length} donors notified`);
    res.json({ message: 'Request submitted!', matches: nearby.length, requestId: request._id });
  } catch(e) {
    console.error('Request error:', e.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/dashboard', auth, async (req, res) => {
  try {
    if (req.user.role === 'donor') {
      const donor = await Donor.findOne({ userId: req.user.id });
      if (!donor) return res.json({ requests: [], donor: null });
      const canDonateTo = Object.entries(compatibility).filter(([k,v]) => v.includes(donor.bloodType)).map(([k]) => k);
      const requests = await Request.find({ status:'open', bloodType:{ $in: canDonateTo } }).sort({ createdAt:-1 }).limit(20);
      res.json({ donor, requests });
    } else {
      const requests = await Request.find({ requesterId: req.user.id }).sort({ createdAt:-1 });
      res.json({ requests });
    }
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/accept-request/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });
    const request = await Request.findById(req.params.id);
    if (!request) return res.status(404).json({ message: 'Not found' });
    if (request.status !== 'open') return res.status(400).json({ message: 'Request no longer open' });
    if (!request.matchedDonors.includes(req.user.id)) request.matchedDonors.push(req.user.id);
    request.status = 'matched'; request.updatedAt = new Date();
    await request.save();
    io.to(request.requesterId.toString()).emit('notification', { message: `A donor responded to your ${request.bloodType} request!` });
    res.json({ message: 'Request accepted. Please head to the hospital.' });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/record-donation', auth, async (req, res) => {
  try {
    if (req.user.role !== 'donor') return res.status(403).json({ message: 'Not a donor' });
    const donor = await Donor.findOne({ userId: req.user.id });
    if (!donor) return res.status(404).json({ message: 'Donor not found' });
    const now = new Date();
    const next = new Date(now.getTime() + 90*24*60*60*1000);
    donor.donationsCount = (donor.donationsCount||0) + 1;
    donor.lastDonation = now; donor.nextEligible = next; donor.available = false;
    await donor.save();
    if (req.body.requestId) await Request.findByIdAndUpdate(req.body.requestId, { status:'fulfilled', fulfilledBy: req.user.id, updatedAt:new Date() });
    res.json({ message: 'Donation recorded! Thank you 🩸', nextEligible: next, totalDonations: donor.donationsCount });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/eligibility', auth, async (req, res) => {
  try {
    const donor = await Donor.findOne({ userId: req.user.id });
    if (!donor) return res.status(404).json({ message: 'Not found' });
    const now = new Date();
    const eligible = !donor.nextEligible || now >= donor.nextEligible;
    const daysLeft = donor.nextEligible ? Math.max(0, Math.ceil((donor.nextEligible - now) / (24*60*60*1000))) : 0;
    res.json({ eligible, daysLeft, lastDonation: donor.lastDonation, nextEligible: donor.nextEligible, totalDonations: donor.donationsCount });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/cancel-request/:id', auth, async (req, res) => {
  try {
    const req2 = await Request.findOne({ _id: req.params.id, requesterId: req.user.id });
    if (!req2) return res.status(404).json({ message: 'Not found' });
    req2.status = 'cancelled'; await req2.save();
    res.json({ message: 'Request cancelled' });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/nearby-donors', auth, async (req, res) => {
  try {
    const { lat, lng, bloodType, radius = 50 } = req.body;
    const types = bloodType ? (compatibility[bloodType]||[bloodType]) : Object.keys(compatibility);
    const donors = await Donor.find({ available: true, bloodType: { $in: types } });
    const nearby = donors
      .map(d => ({ ...d.toObject(), distance: getDistance(lat,lng,d.location.lat,d.location.lng) }))
      .filter(d => d.distance <= radius)
      .sort((a,b) => a.distance - b.distance)
      .slice(0, 20);
    res.json({ donors: nearby, count: nearby.length });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

// ============================================================
//  VERIFICATION ROUTES
// ============================================================

app.post('/api/verify/submit', auth, upload.fields([{ name:'idFront', maxCount:1 }, { name:'idBack', maxCount:1 }]), async (req, res) => {
  try {
    const { firstName, lastName, dob, phone, email, docType, docNumber, weight } = req.body;
    const idFrontPath = req.files?.idFront?.[0]?.path || '';
    const idBackPath  = req.files?.idBack?.[0]?.path  || '';

    // Upsert verification record
    await Verification.findOneAndUpdate(
      { userId: req.user.id },
      { userId: req.user.id, firstName, lastName, dob, phone, email, docType, docNumber, weight, idFrontPath, idBackPath, status: 'pending', submittedAt: new Date() },
      { upsert: true, new: true }
    );

    // Notify admin via email
    if (EMAIL_USER) {
      sendEmail(EMAIL_USER, `🆔 New Verification: ${req.user.username}`,
        `<p>New donor verification submitted by <strong>${req.user.username}</strong>.</p>
         <p>Name: ${firstName} ${lastName} | Doc: ${docType} - ${docNumber}</p>
         <p>Review at: <a href="http://localhost:${PORT}/admin.html">Admin Panel</a></p>`
      );
    }

    console.log(`🆔 Verification submitted: ${req.user.username}`);
    res.json({ message: 'Verification submitted successfully' });
  } catch(e) {
    console.error('Verify error:', e.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/verify/status', auth, async (req, res) => {
  try {
    const v = await Verification.findOne({ userId: req.user.id });
    res.json({ verification: v || null });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

// ============================================================
//  ADMIN ROUTES
// ============================================================

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [openRequests, activeDonors, totalUsers, inventory, criticalRequests, pendingVerifications] = await Promise.all([
      Request.countDocuments({ status:'open' }),
      Donor.countDocuments({ available:true }),
      User.countDocuments(),
      Inventory.find(),
      Request.countDocuments({ status:'open', urgency:'High' }),
      Verification.countDocuments({ status:'pending' })
    ]);
    const recentRequests = await Request.find().sort({ createdAt:-1 }).limit(10);
    const totalUnits = inventory.reduce((s,i) => s+i.units, 0);
    const inv = Object.fromEntries(inventory.map(i => [i.bloodType, i.units]));
    res.json({ openRequests, activeDonors, totalUsers, criticalRequests, totalUnits, inventory: inv, recentRequests, pendingVerifications });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/requests', adminAuth, async (req, res) => {
  try {
    const requests = await Request.find().sort({ createdAt:-1 }).limit(100);
    res.json({ requests });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/donors', adminAuth, async (req, res) => {
  try {
    const donors = await Donor.find().sort({ updatedAt:-1 }).limit(100);
    const users = await User.find({ _id: { $in: donors.map(d => d.userId) } }).select('username email phone verified');
    const um = Object.fromEntries(users.map(u => [u._id.toString(), u]));
    const enriched = donors.map(d => ({ ...d.toObject(), ...um[d.userId?.toString()] && { username: um[d.userId.toString()].username, email: um[d.userId.toString()].email, phone: um[d.userId.toString()].phone } }));
    res.json({ donors: enriched });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/fulfill/:id', adminAuth, async (req, res) => {
  try {
    const { source, notes } = req.body;
    const request = await Request.findByIdAndUpdate(req.params.id,
      { status:'fulfilled', fulfilledBy: source||'Admin', notes: notes||'', updatedAt:new Date() },
      { new: true }
    );
    if (!request) return res.status(404).json({ message: 'Not found' });
    io.to(request.requesterId.toString()).emit('notification', { message: `Your ${request.bloodType} blood request has been fulfilled! ✅` });
    res.json({ message: 'Fulfilled', request });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/inventory', adminAuth, async (req, res) => {
  try {
    const inv = await Inventory.find();
    res.json({ inventory: Object.fromEntries(inv.map(i => [i.bloodType, i.units])) });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/inventory', adminAuth, async (req, res) => {
  try {
    const { bloodType, units, delta } = req.body;
    let inv = await Inventory.findOne({ bloodType }) || new Inventory({ bloodType, units: 0 });
    if (delta !== undefined) inv.units = Math.max(0, inv.units + delta);
    else if (units !== undefined) inv.units = Math.max(0, units);
    inv.updatedAt = new Date();
    await inv.save();
    res.json({ message: 'Updated', bloodType, units: inv.units });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/notify', adminAuth, async (req, res) => {
  try {
    const { bloodType, message, requestId } = req.body;
    const types = compatibility[bloodType] || [bloodType];
    const donors = await Donor.find({ available: true, bloodType: { $in: types } });
    for (const d of donors) {
      io.to(d.userId.toString()).emit('notification', { message: message||`Admin alert: ${bloodType} blood needed!`, requestId });
      const u = await User.findById(d.userId);
      if (u?.phone) sendSMS(u.phone, `🩸 BloodLink: ${message || `Urgent ${bloodType} blood needed!`}`);
    }
    res.json({ message: `Notified ${donors.length} donors`, count: donors.length });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

// Admin: get all verifications
app.get('/api/admin/verifications', adminAuth, async (req, res) => {
  try {
    const vs = await Verification.find().sort({ submittedAt:-1 });
    res.json({ verifications: vs });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

// Admin: approve/reject verification
app.post('/api/admin/verify/:id', adminAuth, async (req, res) => {
  try {
    const { action, notes } = req.body; // action: 'approve' | 'reject'
    const v = await Verification.findByIdAndUpdate(req.params.id,
      { status: action === 'approve' ? 'approved' : 'rejected', adminNotes: notes||'', reviewedAt: new Date() },
      { new: true }
    );
    if (!v) return res.status(404).json({ message: 'Not found' });

    if (action === 'approve') {
      await User.findByIdAndUpdate(v.userId, { verified: true });
      await Donor.findOneAndUpdate({ userId: v.userId }, { verified: true });
      const user = await User.findById(v.userId);
      if (user?.email) {
        sendEmail(user.email, '✅ BloodLink Verification Approved!', `
          <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:20px">
            <div style="background:#22c55e;padding:20px;border-radius:12px 12px 0 0;color:white;text-align:center">
              <h1>✅ Verification Approved!</h1>
            </div>
            <div style="background:#fff;padding:24px;border:1px solid #eee;border-radius:0 0 12px 12px">
              <p>Hi ${user.username},</p>
              <p>Your donor account is now <strong>fully verified</strong>. You can now receive urgent blood requests from nearby patients.</p>
              <a href="http://localhost:${PORT}/dashboard.html" style="display:inline-block;background:#e81c1c;color:white;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;margin-top:12px">Go to Dashboard →</a>
            </div>
          </div>
        `);
      }
      if (user?.phone) sendSMS(user.phone, `✅ BloodLink: Your donor verification is approved! You're now visible to patients. http://localhost:${PORT}/dashboard.html`);
    } else {
      const user = await User.findById(v.userId);
      if (user?.email) sendEmail(user.email, 'BloodLink Verification – Action Required', `<p>Your verification was not approved. Reason: ${notes||'Documents unclear'}. Please resubmit at <a href="http://localhost:${PORT}/verify.html">verify.html</a>.</p>`);
    }

    res.json({ message: `Verification ${action}d`, verification: v });
  } catch(e) { res.status(500).json({ message: 'Server error' }); }
});

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', socket => {
  console.log('🔌 Connected:', socket.id);
  socket.on('join', userId => { socket.join(userId.toString()); console.log(`👤 ${userId} joined`); });
  socket.on('disconnect', () => console.log('🔌 Disconnected:', socket.id));
});

// ============================================================
//  START
// ============================================================
server.listen(PORT, () => {
  console.log(`🩸 BloodLink v4.0 is running`);
  console.log(`App   → http://localhost:${PORT}`);
  console.log(`\n📧 Email: ${EMAIL_USER  ? '✅ ' + EMAIL_USER  : '❌ Not configured'}`);
  console.log(`📱 SMS:   ${TWILIO_SID  ? '✅ Twilio ready'   : '❌ Not configured'}`);
  console.log(`\n`);
});