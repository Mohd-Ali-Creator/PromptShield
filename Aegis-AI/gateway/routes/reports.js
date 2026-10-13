const express = require('express');
const router = express.Router();
const PromptShieldIncident = require('../models/PromptShieldIncident');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');

// GET /api/reports/employee - Retrieve sanitized incidents for authenticated employee only
router.get('/employee', authenticateToken, async (req, res) => {
  try {
    const { severity, action, search, page = 1, limit = 20, startDate, endDate, ruleId } = req.query;

    // Base scope for authenticated employee
    const baseScope = {
      employeeId: req.user._id,
      organizationId: req.user.organizationId
    };

    const filter = { ...baseScope };

    if (severity && severity !== 'ALL') {
      filter.severity = severity;
    }
    if (action && action !== 'ALL') {
      filter.action = action;
    }
    if (ruleId && ruleId !== 'ALL') {
      filter.ruleId = ruleId;
    }
    if (startDate || endDate) {
      filter.occurredAt = {};
      if (startDate) filter.occurredAt.$gte = new Date(startDate);
      if (endDate) filter.occurredAt.$lte = new Date(endDate);
    }
    if (search) {
      filter.$or = [
        { ruleId: new RegExp(search, 'i') },
        { ruleName: new RegExp(search, 'i') },
        { sourcePlatform: new RegExp(search, 'i') }
      ];
    }

    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const skip = (pageNum - 1) * limitNum;

    const [
      incidents,
      total,
      totalCount,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      blockedCount,
      warnedCount,
      redactedCount,
      allowedCount,
      employeeDoc
    ] = await Promise.all([
      PromptShieldIncident.find(filter)
        .sort({ occurredAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .select('-__v'),
      PromptShieldIncident.countDocuments(filter),
      PromptShieldIncident.countDocuments(baseScope),
      PromptShieldIncident.countDocuments({ ...baseScope, severity: 'CRITICAL' }),
      PromptShieldIncident.countDocuments({ ...baseScope, severity: 'HIGH' }),
      PromptShieldIncident.countDocuments({ ...baseScope, severity: 'MEDIUM' }),
      PromptShieldIncident.countDocuments({ ...baseScope, severity: 'LOW' }),
      PromptShieldIncident.countDocuments({ ...baseScope, action: 'BLOCKED' }),
      PromptShieldIncident.countDocuments({ ...baseScope, action: 'WARNED' }),
      PromptShieldIncident.countDocuments({ ...baseScope, action: 'REDACTED' }),
      PromptShieldIncident.countDocuments({ ...baseScope, action: 'ALLOWED' }),
      User.findById(req.user._id).select('extensionEnrolled lastEnrolledAt')
    ]);

    res.json({
      incidents,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum) || 1,
      summary: {
        total: totalCount,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        blocked: blockedCount,
        warned: warnedCount,
        redacted: redactedCount,
        allowed: allowedCount
      },
      extensionEnrolled: Boolean(employeeDoc?.extensionEnrolled || totalCount > 0),
      lastEnrolledAt: employeeDoc?.lastEnrolledAt || null
    });
  } catch (err) {
    console.error('Employee reports error:', err);
    res.status(500).json({ error: 'Failed to retrieve employee reports.' });
  }
});

// GET /api/reports/employee/:id - Single incident detail
router.get('/employee/:id', authenticateToken, async (req, res) => {
  try {
    const incident = await PromptShieldIncident.findOne({
      _id: req.params.id,
      employeeId: req.user._id,
      organizationId: req.user.organizationId
    });

    if (!incident) {
      return res.status(404).json({ error: 'Incident not found or unauthorized.' });
    }

    res.json(incident);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve incident details.' });
  }
});

module.exports = router;
