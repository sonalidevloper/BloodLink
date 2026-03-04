// seed.js – Run once to populate demo data
// Usage: npm run seed

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/bloodlink';

mongoose.connect(MONGO_URI).then(() => console.log('✅ Connected to MongoDB'));

const User    = require('./models/User');
const Donor   = require('./models/Donor');
const Request = require('./models/Request');

const BLOOD_TYPES = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];
const CITIES = [
  { lat: 19.076, lng: 72.877 },  // Mumbai
  { lat: 28.704, lng: 77.102 },  // Delhi
  { lat: 12.971, lng: 77.594 },  // Bangalore
  { lat: 17.385, lng: 78.486 },  // Hyderabad
  { lat: 13.082, lng: 80.271 },  // Chennai
];

async function seed() {
  await User.deleteMany({});
  await Donor.deleteMany({});
  await Request.deleteMany({});
  console.log('🗑️  Cleared existing data');

  const hash = await bcrypt.hash('test123', 10);

  // Create 10 donors
  console.log('👥 Creating donors...');
  for (let i = 1; i <= 10; i++) {
    const user = await User.create({
      username: `donor${i}`,
      password: hash,
      role: 'donor',
      email: `donor${i}@demo.com`,
      phone: `+9190000000${String(i).padStart(2,'0')}`
    });
    const city = CITIES[i % CITIES.length];
    await Donor.create({
      userId:    user._id,
      bloodType: BLOOD_TYPES[i % BLOOD_TYPES.length],
      available: i % 3 !== 0,
      location:  { lat: city.lat + (Math.random()-0.5)*0.2, lng: city.lng + (Math.random()-0.5)*0.2 },
      donationsCount: Math.floor(Math.random() * 5)
    });
  }

  // Create 5 requesters + their requests
  console.log('🏥 Creating requesters...');
  for (let i = 1; i <= 5; i++) {
    const user = await User.create({
      username: `requester${i}`,
      password: hash,
      role: 'requester',
      email: `requester${i}@demo.com`
    });
    const city = CITIES[i % CITIES.length];
    await Request.create({
      requesterId: user._id,
      bloodType:   BLOOD_TYPES[Math.floor(Math.random() * BLOOD_TYPES.length)],
      urgency:     ['High','Medium','Low'][i % 3],
      location:    { lat: city.lat, lng: city.lng },
      status:      i === 1 ? 'fulfilled' : 'open',
      hospital:    `City Hospital ${i}`,
      notes:       `Demo request from requester${i}`,
      createdAt:   new Date(Date.now() - i * 60 * 60 * 1000)
    });
  }

  console.log('\n✅ Seed complete!');
  console.log('─────────────────────────────────────');
  console.log('  Demo accounts (password: test123)');
  console.log('  Donors:     donor1  → donor10');
  console.log('  Requesters: requester1 → requester5');
  console.log('─────────────────────────────────────\n');
  process.exit(0);
}

seed().catch(e => { console.error(e); process.exit(1); });