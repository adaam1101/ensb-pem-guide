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
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(raw);

    const key = (req.query && req.query.key) || req.headers['x-teacher-key'] || '';
    const isTeacher = (key === TEACHER_KEY);

    // OWASP Data Privacy: Hide student directory from unauthorized public requests
    if (!isTeacher && data.students) {
      data.students = [];
    }

    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to read data' });
  }
};
