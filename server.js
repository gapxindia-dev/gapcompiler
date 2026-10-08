const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const VAULTS_FILE = path.join(DATA_DIR, 'vaults.json');
const BEAMS_FILE = path.join(DATA_DIR, 'beams.json');
const COMMUNITY_FILE = path.join(DATA_DIR, 'community.json');

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Helpers for safe file I/O
function loadJson(filepath, fallback) {
  try {
    if (!fs.existsSync(filepath)) {
      fs.writeFileSync(filepath, JSON.stringify(fallback, null, 2), 'utf8');
      return fallback;
    }
    const raw = fs.readFileSync(filepath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error(`Error loading ${filepath}:`, err);
    return fallback;
  }
}

function saveJson(filepath, data) {
  try {
    const tempFile = `${filepath}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tempFile, filepath);
  } catch (err) {
    console.error(`Error saving ${filepath}:`, err);
  }
}

// In-memory data store with disk persistence
let vaults = loadJson(VAULTS_FILE, {});
let beams = loadJson(BEAMS_FILE, {});
let community = loadJson(COMMUNITY_FILE, []);

// Initial community seed if empty
if (community.length === 0) {
  community = [
    {
      id: 'comm_1',
      title: 'University DB: Top 3 Students Per Department by GPA',
      author: 'Aarav (DBMS TA)',
      subject: 'Database Systems',
      tags: ['window-functions', 'rank', 'advanced'],
      sql: `-- Window function query to find top rankers per department
SELECT 
    d.dept_name,
    s.student_name,
    s.gpa,
    DENSE_RANK() OVER (
        PARTITION BY s.dept_id 
        ORDER BY s.gpa DESC
    ) AS rank_in_dept
FROM students s
JOIN departments d ON s.dept_id = d.dept_id
QUALIFY rank_in_dept <= 3;`,
      description: 'Useful for practical lab exams covering analytical & window functions (DENSE_RANK / PARTITION BY).',
      upvotes: 42,
      createdAt: new Date(Date.now() - 3600000 * 24 * 2).toISOString()
    },
    {
      id: 'comm_2',
      title: 'Employee-Manager Hierarchy (Self Join)',
      author: 'Priya_CS',
      subject: 'DBMS Lab 3',
      tags: ['joins', 'self-join', 'classic-lab'],
      sql: `-- Self-Join: Finding employee names alongside their manager's name
SELECT 
    e.emp_id AS "Employee ID",
    e.emp_name AS "Employee Name",
    COALESCE(m.emp_name, 'TOP EXECUTIVE / NO MANAGER') AS "Manager Name",
    e.salary AS "Salary"
FROM employees e
LEFT JOIN employees m ON e.manager_id = m.emp_id
ORDER BY m.emp_name ASC, e.emp_name ASC;`,
      description: 'Standard question in Lab Viva: handles root nodes/CEOs with COALESCE to avoid NULL display.',
      upvotes: 38,
      createdAt: new Date(Date.now() - 3600000 * 24).toISOString()
    },
    {
      id: 'comm_3',
      title: 'Complete Student-Course-Grade Schema with Sample Data',
      author: 'Lab Instructor',
      subject: 'DBMS Lab Practical',
      tags: ['ddl', 'schema', 'starter-kit'],
      sql: `-- Create core tables for academic records
CREATE TABLE IF NOT EXISTS departments (
    dept_id INTEGER PRIMARY KEY,
    dept_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
    student_id INTEGER PRIMARY KEY,
    student_name TEXT NOT NULL,
    dept_id INTEGER REFERENCES departments(dept_id),
    email TEXT UNIQUE,
    gpa REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS courses (
    course_id TEXT PRIMARY KEY,
    course_name TEXT NOT NULL,
    credits INTEGER DEFAULT 3
);

CREATE TABLE IF NOT EXISTS enrollments (
    enroll_id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER REFERENCES students(student_id),
    course_id TEXT REFERENCES courses(course_id),
    grade TEXT CHECK(grade IN ('A+', 'A', 'B', 'C', 'D', 'F'))
);`,
      description: 'Copy-paste ready DDL with foreign keys and constraints for university DBMS assignments.',
      upvotes: 65,
      createdAt: new Date(Date.now() - 3600000 * 12).toISOString()
    },
    {
      id: 'comm_4',
      title: 'Banking System: Customers with Overdue Balance & No Recent Deposits',
      author: 'Rohan_SQL',
      subject: 'Data Management',
      tags: ['subqueries', 'aggregation', 'having'],
      sql: `-- Aggregate customer balances and filter using HAVING
SELECT 
    c.account_no,
    c.customer_name,
    SUM(CASE WHEN t.tx_type = 'DEPOSIT' THEN t.amount ELSE -t.amount END) AS net_balance
FROM customers c
JOIN transactions t ON c.account_no = t.account_no
GROUP BY c.account_no, c.customer_name
HAVING net_balance < 500
ORDER BY net_balance ASC;`,
      description: 'Practical exam favorite demonstrating conditional SUM and HAVING clause filtering.',
      upvotes: 27,
      createdAt: new Date(Date.now() - 3600000 * 5).toISOString()
    }
  ];
  saveJson(COMMUNITY_FILE, community);
}

// Security & Password hashing helpers
function hashPin(pin, salt) {
  return crypto.pbkdf2Sync(pin, salt, 1000, 32, 'sha256').toString('hex');
}

function generateToken(studentId) {
  const payload = `${studentId}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`;
  const signature = crypto.createHmac('sha256', 'edusql-secret-key-2026').update(payload).digest('hex');
  return Buffer.from(`${payload}:${signature}`).toString('base64');
}

function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length < 4) return null;
    const studentId = parts[0];
    const timestamp = parseInt(parts[1], 10);
    const nonce = parts[2];
    const signature = parts[3];
    const expected = crypto.createHmac('sha256', 'edusql-secret-key-2026').update(`${studentId}:${timestamp}:${nonce}`).digest('hex');
    if (expected !== signature) return null;
    return studentId;
  } catch (e) {
    return null;
  }
}

// Middleware: Authenticate student vault
function requireAuth(req, res, next) {
  let token = null;
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please unlock your student vault.' });
  }
  const studentId = verifyToken(token);
  if (!studentId || !vaults[studentId]) {
    return res.status(401).json({ error: 'Session expired or invalid. Please unlock again.' });
  }
  req.studentId = studentId;
  req.vault = vaults[studentId];
  next();
}

// ----------------------------------------------------
// AUTH & VAULT ROUTES
// ----------------------------------------------------

// Login or auto-create student vault with Student ID + PIN
app.post('/api/auth/vault', (req, res) => {
  const { studentId, pin, studentName } = req.body;
  if (!studentId || !pin) {
    return res.status(400).json({ error: 'Student ID and Passcode PIN are required.' });
  }

  const cleanId = studentId.trim().toUpperCase();
  const cleanPin = String(pin).trim();

  if (cleanId.length < 2 || cleanId.length > 30) {
    return res.status(400).json({ error: 'Student ID must be between 2 and 30 characters.' });
  }
  if (cleanPin.length < 3) {
    return res.status(400).json({ error: 'PIN must be at least 3 digits/characters.' });
  }

  if (vaults[cleanId]) {
    // Check PIN
    const existing = vaults[cleanId];
    const inputHash = hashPin(cleanPin, existing.salt);
    if (inputHash !== existing.pinHash) {
      return res.status(401).json({ error: 'Incorrect PIN for this Student ID. Check your passcode or try a different ID.' });
    }
    existing.lastActive = new Date().toISOString();
    if (studentName && studentName.trim()) existing.studentName = studentName.trim();
    saveJson(VAULTS_FILE, vaults);

    const token = generateToken(cleanId);
    return res.json({
      message: 'Vault unlocked successfully!',
      token,
      isNew: false,
      studentId: cleanId,
      studentName: existing.studentName || cleanId,
      vault: {
        studentId: existing.studentId,
        studentName: existing.studentName || cleanId,
        queriesCount: (existing.queries || []).length,
        notesCount: (existing.notes || []).length,
        lastActive: existing.lastActive
      }
    });
  } else {
    // Create new student vault
    const salt = crypto.randomBytes(16).toString('hex');
    const pinHash = hashPin(cleanPin, salt);
    
    // Seed initial welcome query and note
    const newVault = {
      studentId: cleanId,
      studentName: studentName && studentName.trim() ? studentName.trim() : cleanId,
      salt,
      pinHash,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString(),
      queries: [
        {
          id: 'q_' + Date.now(),
          title: 'My First Lab Query: University Enrollments',
          sql: `-- Welcome to your SQL Vault!
-- You can write and test queries directly here or at home.
SELECT 
    s.student_id,
    s.student_name,
    c.course_name,
    e.grade
FROM students s
JOIN enrollments e ON s.student_id = e.student_id
JOIN courses c ON e.course_id = c.course_id
WHERE e.grade = 'A'
ORDER BY s.student_name;`,
          subject: 'Database Systems',
          tags: ['joins', 'welcome', 'lab1'],
          notes: 'Saved from lab computer. Tested with University DB sample dataset.',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      ],
      notes: [
        {
          id: 'n_' + Date.now(),
          title: 'DBMS Lab Practical Cheat Sheet & Viva Tips',
          content: `# DBMS Lab Practical Notes & Tips

## 1. Key SQL Clauses Order
1. \`FROM\` & \`JOIN\`
2. \`WHERE\` (filters rows before aggregation)
3. \`GROUP BY\` (groups rows)
4. \`HAVING\` (filters groups after aggregation)
5. \`SELECT\` (computes expressions)
6. \`ORDER BY\` (sorts result)
7. \`LIMIT\` / \`OFFSET\`

## 2. Common Lab Mistakes to Avoid
- **WHERE vs HAVING**: Never put aggregate functions like \`AVG()\` in \`WHERE\`! Use \`HAVING AVG(...) > 75\`.
- **Primary vs Foreign Keys**: Remember foreign keys must reference existing primary keys.
- **SQL NULL comparisons**: Use \`IS NULL\` or \`IS NOT NULL\`, NOT \`= NULL\`!`,
          subject: 'Lab Notes',
          tags: ['viva', 'theory', 'cheatsheet'],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      ]
    };

    vaults[cleanId] = newVault;
    saveJson(VAULTS_FILE, vaults);

    const token = generateToken(cleanId);
    return res.json({
      message: 'New student vault created and securely locked!',
      token,
      isNew: true,
      studentId: cleanId,
      studentName: newVault.studentName,
      vault: {
        studentId: newVault.studentId,
        studentName: newVault.studentName,
        queriesCount: newVault.queries.length,
        notesCount: newVault.notes.length,
        lastActive: newVault.lastActive
      }
    });
  }
});

// Get current vault content (all queries and notes)
app.get('/api/vault', requireAuth, (req, res) => {
  const v = req.vault;
  res.json({
    studentId: v.studentId,
    studentName: v.studentName || v.studentId,
    createdAt: v.createdAt,
    lastActive: v.lastActive,
    queries: v.queries || [],
    notes: v.notes || []
  });
});

// Update profile / student name
app.post('/api/vault/profile', requireAuth, (req, res) => {
  const { studentName, currentPin, newPin } = req.body;
  const v = req.vault;

  if (studentName && studentName.trim()) {
    v.studentName = studentName.trim();
  }

  if (newPin) {
    if (!currentPin) {
      return res.status(400).json({ error: 'Current PIN is required to set a new PIN.' });
    }
    const checkHash = hashPin(String(currentPin).trim(), v.salt);
    if (checkHash !== v.pinHash) {
      return res.status(400).json({ error: 'Current PIN is incorrect.' });
    }
    if (String(newPin).trim().length < 3) {
      return res.status(400).json({ error: 'New PIN must be at least 3 digits/characters.' });
    }
    v.salt = crypto.randomBytes(16).toString('hex');
    v.pinHash = hashPin(String(newPin).trim(), v.salt);
  }

  saveJson(VAULTS_FILE, vaults);
  res.json({ message: 'Profile updated successfully!', studentName: v.studentName });
});

// ----------------------------------------------------
// SQL QUERIES CRUD
// ----------------------------------------------------

// Add or update query
app.post('/api/vault/query', requireAuth, (req, res) => {
  const { id, title, sql, subject, tags, notes } = req.body;
  if (!title || !sql) {
    return res.status(400).json({ error: 'Title and SQL query code are required.' });
  }

  const v = req.vault;
  if (!v.queries) v.queries = [];

  const existingIndex = id ? v.queries.findIndex(q => q.id === id) : -1;

  if (existingIndex >= 0) {
    // Update existing
    v.queries[existingIndex] = {
      ...v.queries[existingIndex],
      title: title.trim(),
      sql: sql.trim(),
      subject: (subject || 'General SQL').trim(),
      tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
      notes: (notes || '').trim(),
      updatedAt: new Date().toISOString()
    };
    saveJson(VAULTS_FILE, vaults);
    return res.json({ message: 'Query updated!', query: v.queries[existingIndex] });
  } else {
    // Create new
    const newQuery = {
      id: 'q_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
      title: title.trim(),
      sql: sql.trim(),
      subject: (subject || 'General SQL').trim(),
      tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
      notes: (notes || '').trim(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    v.queries.unshift(newQuery);
    saveJson(VAULTS_FILE, vaults);
    return res.json({ message: 'Query saved to vault!', query: newQuery });
  }
});

// Delete query
app.delete('/api/vault/query/:id', requireAuth, (req, res) => {
  const v = req.vault;
  const initialLen = (v.queries || []).length;
  v.queries = (v.queries || []).filter(q => q.id !== req.params.id);
  if (v.queries.length === initialLen) {
    return res.status(404).json({ error: 'Query not found.' });
  }
  saveJson(VAULTS_FILE, vaults);
  res.json({ message: 'Query removed from vault.' });
});

// ----------------------------------------------------
// NOTES CRUD
// ----------------------------------------------------

// Add or update note
app.post('/api/vault/note', requireAuth, (req, res) => {
  const { id, title, content, subject, tags } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and Note content are required.' });
  }

  const v = req.vault;
  if (!v.notes) v.notes = [];

  const existingIndex = id ? v.notes.findIndex(n => n.id === id) : -1;

  if (existingIndex >= 0) {
    v.notes[existingIndex] = {
      ...v.notes[existingIndex],
      title: title.trim(),
      content: content.trim(),
      subject: (subject || 'Personal Notes').trim(),
      tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
      updatedAt: new Date().toISOString()
    };
    saveJson(VAULTS_FILE, vaults);
    return res.json({ message: 'Note updated!', note: v.notes[existingIndex] });
  } else {
    const newNote = {
      id: 'n_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
      title: title.trim(),
      content: content.trim(),
      subject: (subject || 'Personal Notes').trim(),
      tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    v.notes.unshift(newNote);
    saveJson(VAULTS_FILE, vaults);
    return res.json({ message: 'Note saved to vault!', note: newNote });
  }
});

// Delete note
app.delete('/api/vault/note/:id', requireAuth, (req, res) => {
  const v = req.vault;
  const initialLen = (v.notes || []).length;
  v.notes = (v.notes || []).filter(n => n.id !== req.params.id);
  if (v.notes.length === initialLen) {
    return res.status(404).json({ error: 'Note not found.' });
  }
  saveJson(VAULTS_FILE, vaults);
  res.json({ message: 'Note removed from vault.' });
});

// ----------------------------------------------------
// QUICK BEAM (Direct 6-Char Transfer Code)
// ----------------------------------------------------

// Clean expired beams periodically
function cleanupBeams() {
  const now = Date.now();
  let changed = false;
  for (const code in beams) {
    if (beams[code].expiresAt && beams[code].expiresAt < now) {
      delete beams[code];
      changed = true;
    }
  }
  if (changed) saveJson(BEAMS_FILE, beams);
}
setInterval(cleanupBeams, 60000 * 15); // every 15 min

// Generate friendly 6-digit code e.g. SQL-4819 or LAB-3921
function generateBeamCode() {
  const prefixes = ['SQL', 'LAB', 'CODE', 'NOTE', 'SYNC', 'DB'];
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  const num = Math.floor(1000 + Math.random() * 9000);
  return `${prefix}-${num}`;
}

// Create a Quick Beam
app.post('/api/beam', (req, res) => {
  const { title, content, type, subject, tags, expiryHours, senderName } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'Content is required to generate a transfer code.' });
  }

  let code = generateBeamCode();
  let attempts = 0;
  while (beams[code] && attempts < 10) {
    code = generateBeamCode();
    attempts++;
  }

  const hours = Math.min(Math.max(parseInt(expiryHours, 10) || 24, 1), 168); // 1 hr to 7 days
  const now = Date.now();

  const beamData = {
    code,
    type: type || 'sql', // 'sql' or 'note' or 'bundle'
    title: (title || 'School Lab Snippet').trim(),
    content: content.trim(),
    subject: (subject || 'Lab Sharing').trim(),
    tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
    senderName: senderName ? senderName.trim() : 'Anonymous Student',
    createdAt: now,
    expiresAt: now + hours * 3600 * 1000,
    claimCount: 0
  };

  beams[code] = beamData;
  saveJson(BEAMS_FILE, beams);

  res.json({
    message: 'Quick Beam code created! Enter this code from your home computer or mobile to open your snippet.',
    code,
    expiresAt: new Date(beamData.expiresAt).toISOString(),
    beam: beamData
  });
});

// Retrieve a Quick Beam by code
app.get('/api/beam/:code', (req, res) => {
  const code = req.params.code.trim().toUpperCase();
  const beam = beams[code];

  if (!beam) {
    return res.status(404).json({ error: 'Beam code not found or has expired. Please check the code.' });
  }

  if (beam.expiresAt && beam.expiresAt < Date.now()) {
    delete beams[code];
    saveJson(BEAMS_FILE, beams);
    return res.status(410).json({ error: 'This Beam code has expired.' });
  }

  beam.claimCount = (beam.claimCount || 0) + 1;
  saveJson(BEAMS_FILE, beams);

  res.json({
    message: 'Beam found!',
    beam
  });
});

// ----------------------------------------------------
// COMMUNITY / CLASS HUB
// ----------------------------------------------------

// Get community queries with search and tag filters
app.get('/api/community', (req, res) => {
  const { query, tag, subject } = req.query;
  let results = [...community];

  if (query) {
    const q = query.toLowerCase();
    results = results.filter(item =>
      item.title.toLowerCase().includes(q) ||
      item.sql.toLowerCase().includes(q) ||
      (item.description && item.description.toLowerCase().includes(q))
    );
  }

  if (tag) {
    const t = tag.toLowerCase();
    results = results.filter(item =>
      item.tags && item.tags.some(tagItem => tagItem.toLowerCase() === t)
    );
  }

  if (subject) {
    const s = subject.toLowerCase();
    results = results.filter(item =>
      item.subject && item.subject.toLowerCase() === s
    );
  }

  // Sort by upvotes descending, then recency
  results.sort((a, b) => (b.upvotes || 0) - (a.upvotes || 0));

  res.json({ community: results });
});

// Share query to community board
app.post('/api/community', (req, res) => {
  const { title, sql, description, subject, tags, author } = req.body;
  if (!title || !sql) {
    return res.status(400).json({ error: 'Title and SQL query code are required to share.' });
  }

  const newItem = {
    id: 'comm_' + Date.now() + '_' + Math.random().toString(36).substring(2, 5),
    title: title.trim(),
    sql: sql.trim(),
    description: (description || '').trim(),
    subject: (subject || 'Computer Science').trim(),
    tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []),
    author: (author || 'Student').trim(),
    upvotes: 1,
    createdAt: new Date().toISOString()
  };

  community.unshift(newItem);
  saveJson(COMMUNITY_FILE, community);

  res.json({ message: 'Query shared to Class Board for all students!', item: newItem });
});

// Upvote a community query
app.post('/api/community/:id/like', (req, res) => {
  const item = community.find(c => c.id === req.params.id);
  if (!item) {
    return res.status(404).json({ error: 'Query not found in community board.' });
  }

  item.upvotes = (item.upvotes || 0) + 1;
  saveJson(COMMUNITY_FILE, community);
  res.json({ upvotes: item.upvotes });
});

// ----------------------------------------------------
// EXPORT & STATS
// ----------------------------------------------------

// Export entire vault as formatted SQL script or JSON
app.get('/api/vault/export/:format', requireAuth, (req, res) => {
  const v = req.vault;
  const format = req.params.format.toLowerCase();

  if (format === 'sql') {
    let script = `-- ==========================================================\n`;
    script += `-- EduSQL Vault Export for Student: ${v.studentId}\n`;
    script += `-- Generated: ${new Date().toISOString()}\n`;
    script += `-- Total Queries: ${(v.queries || []).length}\n`;
    script += `-- ==========================================================\n\n`;

    (v.queries || []).forEach((q, idx) => {
      script += `-- ----------------------------------------------------------\n`;
      script += `-- [${idx + 1}] ${q.title} (${q.subject || 'General'})\n`;
      if (q.notes) script += `-- Notes: ${q.notes.replace(/\n/g, '\n-- ')}\n`;
      if (q.tags && q.tags.length) script += `-- Tags: ${q.tags.join(', ')}\n`;
      script += `-- ----------------------------------------------------------\n`;
      script += `${q.sql}\n\n`;
    });

    res.setHeader('Content-Type', 'application/sql');
    res.setHeader('Content-Disposition', `attachment; filename="${v.studentId}_queries.sql"`);
    return res.send(script);
  }

  if (format === 'json') {
    const exportData = {
      studentId: v.studentId,
      studentName: v.studentName,
      exportedAt: new Date().toISOString(),
      queries: v.queries || [],
      notes: v.notes || []
    };
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${v.studentId}_vault_backup.json"`);
    return res.json(exportData);
  }

  res.status(400).json({ error: 'Unsupported format. Choose "sql" or "json".' });
});

// Fallback to index.html for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`EduSQL & Notes Vault Server running at http://localhost:${PORT}`);
});
