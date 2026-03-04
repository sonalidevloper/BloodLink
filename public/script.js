const socket = io();

let token = localStorage.getItem('token');
let role = localStorage.getItem('role');
let userId = null;

let lat = 0;
let lng = 0;

// ================= MESSAGE FUNCTION =================
function msg(text) {
  const m1 = document.getElementById('msg');
  const m2 = document.getElementById('message');

  if (m1) m1.innerHTML = text;
  if (m2) m2.textContent = text;
}

// ================= REGISTER =================
async function register() {

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const userRole = document.getElementById('role').value;
  const bloodType = document.getElementById('bloodType').value;

  if (userRole === 'donor' && !bloodType) {
    return msg("Donors must select blood type");
  }

  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      password,
      role: userRole,
      bloodType
    })
  });

  const data = await res.json();
  msg(data.message);
}

// ================= LOGIN =================
async function login() {

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();

  if (res.ok) {

    token = data.token;
    role = data.role;

    localStorage.setItem('token', token);
    localStorage.setItem('role', role);

    userId = JSON.parse(atob(token.split('.')[1])).id;

    // ===== ROLE BASED REDIRECT =====
    if (role === "admin") {
      location.href = "/admin.html";
    } else {
      location.href = "/dashboard.html";
    }

  } else {
    msg(data.message);
  }
}

// ================= DASHBOARD LOAD =================
if (location.pathname.includes('dashboard')) {

  if (!token) {
    location.href = "/";
  }

  userId = JSON.parse(atob(token.split('.')[1])).id;

  socket.emit('join', userId);

  if (role === 'donor') {

    const donorSection = document.getElementById('donor');
    if (donorSection) donorSection.style.display = 'block';

    socket.on('notification', (data) => {
      const alerts = document.getElementById('alerts');
      if (alerts) {
        alerts.innerHTML += `<p style="color:red">URGENT: ${data.message}</p>`;
      }
    });

    loadDashboard();

  } else {

    const requesterSection = document.getElementById('requester');
    if (requesterSection) requesterSection.style.display = 'block';

    loadDashboard();
  }
}

// ================= LOAD DASHBOARD DATA =================
async function loadDashboard() {

  const res = await fetch('/api/dashboard', {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  const data = await res.json();

  if (role === 'donor') {

    const reqList = document.getElementById('requests');

    if (reqList) {
      reqList.innerHTML = data.requests
        .map(r => `<li>${r.bloodType} - ${r.urgency} urgency</li>`)
        .join('');
    }

  } else {

    const myReq = document.getElementById('myreq');

    if (myReq) {
      myReq.innerHTML = data.requests
        .map(r => `<li>${r.bloodType} - ${r.status}</li>`)
        .join('');
    }
  }
}

// ================= LOCATION =================
function updateLocation(isReq = false) {

  navigator.geolocation.getCurrentPosition(

    pos => {

      lat = pos.coords.latitude;
      lng = pos.coords.longitude;

      msg("Location Updated!");

      if (!isReq && role === 'donor') {
        saveDonor();
      }

    },

    () => msg("Location Denied")

  );
}

// ================= UPDATE DONOR =================
function saveDonor() {

  const available = document.getElementById('available').checked;

  fetch('/api/update-donor', {

    method: 'POST',

    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },

    body: JSON.stringify({
      available,
      lat,
      lng
    })

  }).then(() => msg("Status Saved"));
}

// ================= SEND BLOOD REQUEST =================
function sendRequest() {

  const bloodType = document.getElementById('reqBlood').value;
  const urgency = document.getElementById('urgency').value;

  fetch('/api/request-blood', {

    method: 'POST',

    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },

    body: JSON.stringify({
      bloodType,
      urgency,
      lat,
      lng
    })

  })
    .then(r => r.json())
    .then(d => {
      msg(d.message);
      loadDashboard();
    });

}