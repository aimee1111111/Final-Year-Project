// Handles: File upload, scan processing, and returning scan history/statistics.

const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const fetch = require('node-fetch');
const FormData = require('form-data');
const crypto = require('crypto');
const pool = require('../databaseConnection');

// Multer temporary upload destination
const upload = multer({ dest: 'uploads/' });

/*
   Uploads a file, sends it to the Flask AV
   scanner, saves scan results to Postgres.*/
router.post('/upload', upload.single('file'), async (req, res) => {

  // Cleans up temporary uploaded file
  const cleanup = () =>
    req.file && fs.unlink(req.file.path, () => {});

  try {
    // Validate and parse user_id 
    const userId = req.body.user_id ? parseInt(req.body.user_id, 10) : null;

    if (!userId || isNaN(userId)) {
      cleanup();
      return res.status(400).json({ message: 'Missing or invalid user_id' });
    }

    // Ensure user exists (foreign key safety)
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [userId]
    );

    if (userCheck.rows.length === 0) {
      cleanup();
      return res.status(404).json({ message: 'User not found' });
    }

    // Require a file to be uploaded
    if (!req.file) {
      cleanup();
      return res.status(400).json({ message: 'No file provided' });
    }

    //Read uploaded file and compute SHA-256 hash 
    const fileBuffer = fs.readFileSync(req.file.path);
    const sha256 = crypto.createHash('sha256')
      .update(fileBuffer)
      .digest('hex');

    //Prepare file for Flask scanner
    const f = new FormData();
    f.append('file', fs.createReadStream(req.file.path), req.file.originalname);

    // Send file to Python scanner API
    const flaskResp = await fetch('http://127.0.0.1:5000/upload', {
      method: 'POST',
      body: f
    });

    // Parse scanner response only if JSON
    const contentType = flaskResp.headers.get('content-type') || '';
    const scan = contentType.includes('application/json')
      ? await flaskResp.json()
      : { safe: false, message: 'Scanner returned non-JSON response' };

    // Remove temp file
    cleanup();

    //Normalize scanner response
    const safe = Boolean(scan.safe);
    const message = scan.message ?? null;
    const threats = Array.isArray(scan.threats) ? scan.threats : [];
    const scanResults = scan.scan_results ?? {};

    //Save scan entry into database
    const insertSQL = `
      INSERT INTO scans (
        user_id,
        filename,
        size_bytes,
        mime_type,
        sha256,
        scanned_at,
        safe,
        message,
        threats,
        scan_results,
        source_ip
      )
      VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8::jsonb, $9::jsonb, $10)
      RETURNING id, scanned_at;
    `;

    const values = [
      userId,                          // $1 - integer user_id
      req.file.originalname,           // $2 - filename
      Number(req.file.size),           // $3 - size_bytes
      req.file.mimetype || null,       // $4 - mime_type
      sha256,                          // $5 - sha256
      safe,                            // $6 - safe
      message,                         // $7 - message
      JSON.stringify(threats),         // $8 - threats (jsonb)
      JSON.stringify(scanResults),     // $9 - scan_results (jsonb)
      req.ip || null,                  // $10 - source_ip
    ];

    const { rows } = await pool.query(insertSQL, values);
    const scanId = rows[0].id;
    const scannedAt = rows[0].scanned_at;

    // Return merged response (scanner + DB info)
    return res.status(flaskResp.ok ? 200 : 500).json({
      ...scan,
      scan_id: scanId,
      scanned_at: scannedAt,
      user_id: userId
    });

  } catch (err) {
    cleanup();
    console.error('Upload/Insert error:', err.stack || err);

    // Handle foreign key constraint violations
    if (err.code === '23503') {
      return res.status(404).json({
        message: 'User not found',
        error: 'Invalid user_id'
      });
    }

    return res.status(500).json({
      message: 'Scan or save failed',
      error: err.message
    });
  }
});


//Returns scan history for the given user.

router.get('/api/scans', async (req, res) => {
  try {
    const userId = req.query.user_id ? parseInt(req.query.user_id, 10) : null;

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ message: 'Missing or invalid user_id' });
    }

    const { rows } = await pool.query(
      `SELECT
        id,
        user_id,
        filename,
        size_bytes,
        mime_type,
        sha256,
        scanned_at,
        safe,
        message,
        threats,
        scan_results,
        source_ip
       FROM scans
       WHERE user_id = $1
       ORDER BY scanned_at DESC
       LIMIT 100`,
      [userId]
    );

    res.json(rows);

  } catch (err) {
    console.error('Error fetching scans:', err);
    res.status(500).json({
      message: 'Error fetching scans',
      error: err.message
    });
  }
});


   //Fetch a single scan 
router.get('/api/scans/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.query.user_id ? parseInt(req.query.user_id, 10) : null;

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ message: 'Missing or invalid user_id' });
    }

    const { rows } = await pool.query(
      `SELECT * FROM scans WHERE id = $1 AND user_id = $2`,
      [scanId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error('Error fetching scan:', err);
    res.status(500).json({
      message: 'Error fetching scan',
      error: err.message
    });
  }
});

//Returns statistics about a user's scans.
router.get('/api/scans/stats/:userId', async (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);

    if (isNaN(userId)) {
      return res.status(400).json({ message: 'Invalid user_id' });
    }

    const { rows } = await pool.query(
      `SELECT 
        COUNT(*) as total_scans,
        COUNT(*) FILTER (WHERE safe = true) as safe_count,
        COUNT(*) FILTER (WHERE safe = false) as threat_count,
        SUM(size_bytes) as total_bytes_scanned,
        MAX(scanned_at) as last_scan_date
       FROM scans
       WHERE user_id = $1`,
      [userId]
    );

    res.json(rows[0]);

  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).json({
      message: 'Error fetching statistics',
      error: err.message
    });
  }
});

module.exports = router;
