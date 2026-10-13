const express = require('express');
const router = express.Router();
const MessageLog = require('../models/MessageLog');
const { authenticateToken, requireAdmin } = require('../middleware/auth');

// GET /api/history - Scoped by role and organization
router.get('/', authenticateToken, async (req, res) => {
  try {
    let filter = {};
    if (req.user.role === 'admin') {
      // Admin sees all logs for their authorized organization
      filter = { organizationId: req.user.organizationId };
    } else {
      // Employee sees only their own activity within their organization
      filter = {
        organizationId: req.user.organizationId,
        userId: req.user._id
      };
    }

    const logs = await MessageLog.find(filter).sort({ timestamp: 1 });
    res.json(logs);
  } catch (err) {
    console.error('History fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch history: ' + err.message });
  }
});

// DELETE /api/history - Strictly Admin-only, scoped to the admin's organization
router.delete('/', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await MessageLog.deleteMany({ organizationId: req.user.organizationId });
    res.json({ message: 'Organization chat history cleared successfully.' });
  } catch (err) {
    console.error('History clear error:', err);
    res.status(500).json({ error: 'Failed to clear history: ' + err.message });
  }
});

module.exports = router;
