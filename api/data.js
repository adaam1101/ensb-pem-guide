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

  const filePath = path.join(process.cwd(), 'data.json');
  const studentsPath = path.join(process.cwd(), 'api', 'students-store.json');

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);

    const key = (req.query && req.query.key) || req.headers['x-teacher-key'] || '';
    const isTeacher = (key === TEACHER_KEY);

    if (isTeacher) {
      if (fs.existsSync(studentsPath)) {
        try {
          data.students = JSON.parse(fs.readFileSync(studentsPath, 'utf8'));
        } catch(e) {
          data.students = [];
        }
      }
    } else {
      // OWASP Pen-test requirement: strip student directory for public queries
      data.students = [];
    }

    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to read data' });
  }
};
