// server.js  ←←← THIS FILE NAME MUST BE EXACTLY "server.js"
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

mongoose.connect('mongodb://127.0.0.1:27017/bloodDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  role: String
});
const User = mongoose.model('User', userSchema);

const donorSchema = new mongoose.Schema({
  userId: String,
  bloodType: String
});
const Donor = mongoose.model('Donor', donorSchema);

const SECRET = "12345";

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role, bloodType } = req.body;
    const exists = await User.findOne({ username });
    if (exists) return res.json({ message: "Username taken" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash, role });
    await user.save();

    if (role === 'donor') {
      await new Donor({ userId: user._id, bloodType }).save();
    }
    res.json({ message: "Registered! Login now" });
  } catch (e) {
    res.json({ message: "Error" });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.json({ message: "Wrong credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.json({ message: "Wrong credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, SECRET);
    res.json({ success: true, token, role: user.role });
  } catch (e) {
    res.json({ message: "Error" });
  }
});

app.listen(3000, () => {
  console.log("SERVER RUNNING → http://localhost:3000");
});