const fs = require('fs');
const path = require('path');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=300');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const studentsPath = path.join(process.cwd(), 'api', 'students-store.json');
  try {
    let count = 0;
    if (fs.existsSync(studentsPath)) {
      const arr = JSON.parse(fs.readFileSync(studentsPath, 'utf8'));
      count = arr.length;
    }
    return res.status(200).json({ total: count });
  } catch (err) {
    return res.status(500).json({ total: 0 });
  }
};
