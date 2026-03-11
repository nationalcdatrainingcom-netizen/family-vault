const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bcrypt = require('bcryptjs');
const CryptoJS = require('crypto-js');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── PERSISTENT DATA PATHS ────────────────────────────────────────
// On Render, use /opt/render/project/data for persistence (mount a disk)
// Locally, use ./data
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'vault.json');
const SESSIONS_DIR = path.join(DATA_DIR, 'sessions');

// Ensure data dirs exist
[DATA_DIR, SESSIONS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ─── ENCRYPTION KEY ───────────────────────────────────────────────
// Set VAULT_SECRET in Render environment variables. If not set, uses fallback (not recommended for production).
const VAULT_SECRET = process.env.VAULT_SECRET || 'FamilyVault_ChangeThis_InRenderEnvVars';

// ─── DATABASE ─────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      familyCode: process.env.FAMILY_CODE || 'FamilyVault2024',
      users: [],
      entries: []
    };
    saveDB(initial);
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ─── ENCRYPTION HELPERS ───────────────────────────────────────────
function encryptEntry(data) {
  return CryptoJS.AES.encrypt(JSON.stringify(data), VAULT_SECRET).toString();
}

function decryptEntry(cipher) {
  try {
    const bytes = CryptoJS.AES.decrypt(cipher, VAULT_SECRET);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
  } catch {
    return null;
  }
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────
// Render sits behind a reverse proxy - this is required for secure cookies to work
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
  store: new FileStore({
    path: SESSIONS_DIR,
    ttl: 86400 * 7,
    retries: 1,
    reapInterval: 3600
  }),
  secret: VAULT_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'fv.sid',
  cookie: {
    secure: isProduction,
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days - survives Render restarts
  }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function requireAdmin(req, res, next) {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Admin required' });
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { name, username, password, familyCode } = req.body;
  const db = loadDB();

  if (!name || !username || !password || !familyCode)
    return res.json({ error: 'All fields required.' });

  if (familyCode !== db.familyCode)
    return res.json({ error: 'Incorrect family access code.' });

  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.json({ error: 'Username already taken.' });

  const hashed = await bcrypt.hash(password, 12);
  const isFirst = db.users.length === 0;
  const newUser = {
    id: uuidv4(),
    name: name.trim(),
    username: username.trim(),
    password: hashed,
    role: isFirst ? 'admin' : 'member',
    created: new Date().toISOString()
  };
  db.users.push(newUser);
  saveDB(db);

  req.session.userId = newUser.id;
  res.json({ success: true, user: { id: newUser.id, name: newUser.name, username: newUser.username, role: newUser.role } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();

  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.json({ error: 'Incorrect username or password.' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ error: 'Incorrect username or password.' });

  req.session.userId = user.id;
  res.json({ success: true, user: { id: user.id, name: user.name, username: user.username, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not found' });
  res.json({ id: user.id, name: user.name, username: user.username, role: user.role });
});

// ─── MASTER PASSWORD VERIFIER (stores encrypted proof, never the password) ────
app.post('/api/verifier', requireAuth, (req, res) => {
  const { verifier } = req.body;
  if (!verifier) return res.json({ error: 'Verifier required.' });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.verifier = verifier;
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/verifier', requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ verifier: user.verifier || null });
});

// ─── ENTRY ROUTES ─────────────────────────────────────────────────
// Entries are pre-encrypted by the browser (zero-knowledge)
app.get('/api/entries', requireAuth, (req, res) => {
  const db = loadDB();
  const entries = db.entries.filter(e => e.userId === req.session.userId);
  res.json(entries); // send encrypted blobs — browser decrypts
});

app.post('/api/entries', requireAuth, (req, res) => {
  const db = loadDB();
  const { data } = req.body; // pre-encrypted by browser
  if (!data) return res.json({ error: 'Entry data required.' });
  const entry = { id: uuidv4(), userId: req.session.userId, data };
  db.entries.push(entry);
  saveDB(db);
  res.json({ success: true, id: entry.id });
});

app.put('/api/entries/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.entries.findIndex(e => e.id === req.params.id && e.userId === req.session.userId);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.entries[idx].data = req.body.data;
  saveDB(db);
  res.json({ success: true });
});

app.delete('/api/entries/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const entry = db.entries.find(e => e.id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'Not found' });
  const user = db.users.find(u => u.id === req.session.userId);
  if (entry.userId !== req.session.userId && user.role !== 'admin')
    return res.status(403).json({ error: 'Not allowed' });
  db.entries = db.entries.filter(e => e.id !== req.params.id);
  saveDB(db);
  res.json({ success: true });
});

// Admin: get all encrypted blobs — browser tries to decrypt with admin key
app.get('/api/admin/entries', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const all = db.entries.map(e => {
    const owner = db.users.find(u => u.id === e.userId);
    return { id: e.id, userId: e.userId, ownerName: owner ? owner.name : 'Unknown', data: e.data };
  });
  res.json(all);
});

// ─── USER MANAGEMENT ROUTES (admin) ───────────────────────────────
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const users = db.users.map(u => ({
    id: u.id, name: u.name, username: u.username, role: u.role, created: u.created,
    entryCount: db.entries.filter(e => e.userId === u.id).length
  }));
  res.json(users);
});

app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { name, username, password, role } = req.body;
  const db = loadDB();

  if (!name || !username || !password) return res.json({ error: 'All fields required.' });
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.json({ error: 'Username already exists.' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = { id: uuidv4(), name, username, password: hashed, role: role || 'member', created: new Date().toISOString() };
  db.users.push(newUser);
  saveDB(db);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  if (req.params.id === req.session.userId) return res.json({ error: 'Cannot delete yourself.' });
  db.users = db.users.filter(u => u.id !== req.params.id);
  db.entries = db.entries.filter(e => e.userId !== req.params.id);
  saveDB(db);
  res.json({ success: true });
});

app.put('/api/admin/users/:id/password', requireAuth, requireAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.json({ error: 'Password required.' });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.password = await bcrypt.hash(password, 12);
  saveDB(db);
  res.json({ success: true });
});

app.put('/api/admin/familycode', requireAuth, requireAdmin, (req, res) => {
  const { familyCode } = req.body;
  if (!familyCode) return res.json({ error: 'Code required.' });
  const db = loadDB();
  db.familyCode = familyCode;
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/admin/familycode', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ familyCode: db.familyCode });
});

// Export backup (admin only)
app.get('/api/admin/export', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  // Decrypt all entries for export
  const exportData = {
    exportDate: new Date().toISOString(),
    users: db.users.map(u => ({ id: u.id, name: u.name, username: u.username, role: u.role })),
    entries: db.entries.map(e => {
      const data = decryptEntry(e.data);
      return { id: e.id, userId: e.userId, ...data };
    })
  };
  res.setHeader('Content-Disposition', `attachment; filename="family-vault-backup-${new Date().toISOString().split('T')[0]}.json"`);
  res.json(exportData);
});

// ─── SERVE APP ────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Family Vault running on port ${PORT}`));
