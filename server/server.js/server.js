const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connect
mongoose.connect('mongodb://127.0.0.1:27017/bloodDB')
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  role: String  // donor or requester
});
const User = mongoose.model('User', userSchema);

const donorSchema = new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  bloodType: String,
  available: { type: Boolean, default: true },
  location: { lat: Number, lng: Number }
});
const Donor = mongoose.model('Donor', donorSchema);

// JWT Secret
const SECRET = "supersecret123";

// === ROUTES ===
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role, bloodType } = req.body;
    const exists = await User.findOne({ username });
    if (exists) return res.json({ message: "Username already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash, role });
    await user.save();

    if (role === 'donor') {
      const donor = new Donor({ userId: user._id, bloodType });
      await donor.save();
    }
    res.json({ message: "Registered! Now login." });
  } catch (e) {
    res.status(500).json({ message: "Error: " + e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.json({ message: "Wrong username or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ message: "Wrong username or password" });

    const token = jwt.sign({ id: user._id, role: user.role }, SECRET);
    res.json({ success: true, token, role: user.role });
  } catch (e) {
    res.status(500).json({ message: "Error" });
  }
});

app.get('/api/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.json({ success: false });
  try {
    const decoded = jwt.verify(token, SECRET);
    const user = await User.findById(decoded.id);
    const donor = decoded.role === 'donor' ? await Donor.findOne({ userId: user._id }) : null;
    res.json({ success: true, user, donor });
  } catch { res.json({ success: false }); }
});

// Socket
io.on('connection', socket => {
  socket.on('join', id => socket.join(id));
});

server.listen(3000, () => console.log("Server → http://localhost:3000"));