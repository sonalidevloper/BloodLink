const socket = io();
let token = localStorage.getItem('token');
let role = localStorage.getItem('role');
let userId = null;
let lat = 0, lng = 0;

function msg(text) { document.getElementById('msg') ? document.getElementById('msg').innerHTML = text : document.getElementById('message').textContent = text; }

async function register() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const role = document.getElementById('role').value;
  const bloodType = document.getElementById('bloodType').value;

  if (role === 'donor' && !bloodType) return msg("Donors must select blood type");

  const res = await fetch('/api/register', { method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password, role, bloodType})
  });
  const data = await res.json();
  msg(data.message);
}

async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password})
  });
  const data = await res.json();
  if (res.ok) {
    token = data.token;
    role = data.role;
    localStorage.setItem('token', token);
    localStorage.setItem('role', role);
    userId = JSON.parse(atob(token.split('.')[1])).id;
    location.href = '/dashboard.html';
  } else {
    msg(data.message);
  }
}

// Dashboard Load
if (location.pathname.includes('dashboard')) {
  if (!token) location.href = '/';
  userId = JSON.parse(atob(token.split('.')[1])).id;
  socket.emit('join', userId);

  if (role === 'donor') {
    document.getElementById('donor').style.display = 'block';
    socket.on('notification', (data) => {
      document.getElementById('alerts').innerHTML += `<p style="color:red">URGENT: ${data.message}</p>`;
    });
    loadDashboard();
  } else {
    document.getElementById('requester').style.display = 'block';
    loadDashboard();
  }
}

async function loadDashboard() {
  const res = await fetch('/api/dashboard', { headers: { Authorization: `Bearer ${token}` }});
  const data = await res.json();
  if (role === 'donor') {
    document.getElementById('requests').innerHTML = data.requests.map(r => `<li>${r.bloodType} - ${r.urgency} urgency</li>`).join('');
  } else {
    document.getElementById('myreq').innerHTML = data.requests.map(r => `<li>${r.bloodType} - ${r.status}</li>`).join('');
  }
}

function updateLocation(isReq = false) {
  navigator.geolocation.getCurrentPosition(pos => {
    lat = pos.coords.latitude;
    lng = pos.coords.longitude;
    msg("Location Updated!");
    if (!isReq && role === 'donor') saveDonor();
  }, () => msg("Location Denied"));
}

function saveDonor() {
  const available = document.getElementById('available').checked;
  fetch('/api/update-donor', { method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`},
    body: JSON.stringify({available, lat, lng})
  }).then(() => msg("Status Saved"));
}

function sendRequest() {
  const bloodType = document.getElementById('reqBlood').value;
  const urgency = document.getElementById('urgency').value;
  fetch('/api/request-blood', { method: 'POST', headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`},
    body: JSON.stringify({bloodType, urgency, lat, lng})
  }).then(r => r.json()).then(d => { msg(d.message); loadDashboard(); });
}