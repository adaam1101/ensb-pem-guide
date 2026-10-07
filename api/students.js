const fs = require('fs');
const path = require('path');

const TEACHER_KEY = process.env.TEACHER_ACCESS_KEY || 'ensb2026';

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Teacher-Key');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const key = (req.query && req.query.key) || req.headers['x-teacher-key'] || '';
  if (key !== TEACHER_KEY) {
    return res.status(403).json({
      error: 'Access restricted. The student directory is reserved for faculty and administration.',
      authenticated: false
    });
  }

  const studentsPath = path.join(process.cwd(), 'api', 'students-store.json');
  try {
    let students = [];
    if (fs.existsSync(studentsPath)) {
      students = JSON.parse(fs.readFileSync(studentsPath, 'utf8'));
    }
    return res.status(200).json({ students, total: students.length, authenticated: true });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to read student data' });
  }
};
