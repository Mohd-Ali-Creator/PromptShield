const express = require('express');
const router = express.Router();
const PromptShieldIncident = require('../models/PromptShieldIncident');
const User = require('../models/User');
const PolicyAuditLog = require('../models/PolicyAuditLog');
const CompanyRule = require('../models/CompanyRule');
const { authenticateToken, requireAdmin } = require('../middleware/auth');

// All endpoints in this router require authentication and admin role
router.use(authenticateToken, requireAdmin);

// GET /api/admin/metrics - Organization-wide incident aggregates
router.get('/metrics', async (req, res) => {
  try {
    const orgId = req.user.organizationId;

    const [
      totalIncidents,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      blockedCount,
      warnedCount,
      redactedCount,
      allowedCount,
      activeRulesCount,
      employeesCount,
      enrolledUsersCount
    ] = await Promise.all([
      PromptShieldIncident.countDocuments({ organizationId: orgId }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, severity: 'CRITICAL' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, severity: 'HIGH' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, severity: 'MEDIUM' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, severity: 'LOW' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, action: 'BLOCKED' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, action: 'WARNED' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, action: 'REDACTED' }),
      PromptShieldIncident.countDocuments({ organizationId: orgId, action: 'ALLOWED' }),
      CompanyRule.countDocuments({ organizationId: orgId, enabled: true }),
      User.countDocuments({ organizationId: orgId }),
      User.countDocuments({ organizationId: orgId, extensionEnrolled: true })
    ]);

    // Top triggered rules aggregation
    const topRules = await PromptShieldIncident.aggregate([
      { $match: { organizationId: orgId } },
      { $group: { _id: { ruleId: '$ruleId', ruleName: '$ruleName' }, count: { $sum: 1 }, lastSeverity: { $last: '$severity' } } },
      { $sort: { count: -1 } },
      { $limit: 8 }
    ]);

    // Incident trends over time (by date)
    const rawTrends = await PromptShieldIncident.aggregate([
      { $match: { organizationId: orgId } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$occurredAt' } },
          total: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'BLOCKED'] }, 1, 0] } },
          warned: { $sum: { $cond: [{ $eq: ['$action', 'WARNED'] }, 1, 0] } }
        }
      },
      { $sort: { _id: 1 } },
      { $limit: 14 }
    ]);

    const incidentTrends = rawTrends.map(t => ({
      date: t._id,
      total: t.total,
      blocked: t.blocked,
      warned: t.warned
    }));

    // Employee-wise incident totals & severity breakdown
    const employeeBreakdown = await PromptShieldIncident.aggregate([
      { $match: { organizationId: orgId } },
      {
        $group: {
          _id: '$employeeId',
          employeeName: { $first: '$employeeName' },
          employeeEmail: { $first: '$employeeEmail' },
          total: { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity', 'CRITICAL'] }, 1, 0] } },
          high: { $sum: { $cond: [{ $eq: ['$severity', 'HIGH'] }, 1, 0] } },
          medium: { $sum: { $cond: [{ $eq: ['$severity', 'MEDIUM'] }, 1, 0] } },
          low: { $sum: { $cond: [{ $eq: ['$severity', 'LOW'] }, 1, 0] } },
          blocked: { $sum: { $cond: [{ $eq: ['$action', 'BLOCKED'] }, 1, 0] } },
          lastIncidentAt: { $max: '$occurredAt' }
        }
      },
      { $sort: { total: -1 } },
      { $limit: 10 }
    ]);

    // Severity distribution
    const severityData = [
      { name: 'Critical', value: criticalCount, color: '#dc2626' },
      { name: 'High', value: highCount, color: '#ea580c' },
      { name: 'Medium', value: mediumCount, color: '#d97706' },
      { name: 'Low', value: lowCount, color: '#059669' }
    ];

    // Action distribution
    const actionData = [
      { name: 'Blocked', value: blockedCount, color: '#ef4444' },
      { name: 'Warned', value: warnedCount, color: '#f59e0b' },
      { name: 'Redacted', value: redactedCount, color: '#3b82f6' },
      { name: 'Allowed', value: allowedCount, color: '#10b981' }
    ];

    res.json({
      summary: {
        totalIncidents,
        blockedCount,
        warnedCount,
        redactedCount,
        allowedCount,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        activeRulesCount,
        employeesCount,
        enrolledUsersCount
      },
      severityData,
      actionData,
      incidentTrends,
      employeeBreakdown,
      topRules: topRules.map(r => ({
        ruleId: r._id.ruleId,
        ruleName: r._id.ruleName || r._id.ruleId,
        count: r.count,
        severity: r.lastSeverity
      }))
    });
  } catch (err) {
    console.error('Admin metrics error:', err);
    res.status(500).json({ error: 'Failed to compute admin metrics.' });
  }
});

// GET /api/admin/incidents - List organization incidents with multi-facet filters
router.get('/incidents', async (req, res) => {
  try {
    const orgId = req.user.organizationId;
    const {
      severity,
      action,
      employeeId,
      ruleId,
      sourcePlatform,
      search,
      page = 1,
      limit = 25,
      startDate,
      endDate
    } = req.query;

    const filter = { organizationId: orgId };

    if (severity && severity !== 'ALL') filter.severity = severity;
    if (action && action !== 'ALL') filter.action = action;
    if (employeeId && employeeId !== 'ALL') filter.employeeId = employeeId;
    if (ruleId && ruleId !== 'ALL') filter.ruleId = ruleId;
    if (sourcePlatform && sourcePlatform !== 'ALL') {
      filter.sourcePlatform = new RegExp(sourcePlatform, 'i');
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
        { employeeName: new RegExp(search, 'i') },
        { employeeEmail: new RegExp(search, 'i') },
        { sourcePlatform: new RegExp(search, 'i') }
      ];
    }

    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const skip = (pageNum - 1) * limitNum;

    const [incidents, total] = await Promise.all([
      PromptShieldIncident.find(filter)
        .sort({ occurredAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .select('-__v'),
      PromptShieldIncident.countDocuments(filter)
    ]);

    res.json({
      incidents,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum) || 1
    });
  } catch (err) {
    console.error('Admin incidents error:', err);
    res.status(500).json({ error: 'Failed to retrieve incidents.' });
  }
});

// GET /api/admin/employees - List employees with aggregated incident stats
router.get('/employees', async (req, res) => {
  try {
    const orgId = req.user.organizationId;
    const employees = await User.find({ organizationId: orgId })
      .select('_id name email role createdAt extensionEnrolled lastEnrolledAt')
      .sort({ name: 1 });

    // Aggregate incident statistics per employee
    const incidentStats = await PromptShieldIncident.aggregate([
      { $match: { organizationId: orgId } },
      {
        $group: {
          _id: '$employeeId',
          totalIncidents: { $sum: 1 },
          criticalHighCount: {
            $sum: {
              $cond: [{ $in: ['$severity', ['CRITICAL', 'HIGH']] }, 1, 0]
            }
          },
          lastIncidentAt: { $max: '$occurredAt' }
        }
      }
    ]);

    const statsMap = new Map();
    for (const stat of incidentStats) {
      statsMap.set(stat._id.toString(), stat);
    }

    const enrichedEmployees = employees.map(emp => {
      const stats = statsMap.get(emp._id.toString()) || {};
      const totalIncidents = stats.totalIncidents || 0;
      const criticalHighCount = stats.criticalHighCount || 0;
      const isEnrolled = Boolean(emp.extensionEnrolled || totalIncidents > 0);

      return {
        _id: emp._id,
        name: emp.name,
        email: emp.email,
        role: emp.role,
        createdAt: emp.createdAt,
        extensionStatus: isEnrolled ? 'Enrolled' : 'Disconnected',
        extensionEnrolled: isEnrolled,
        lastEnrolledAt: emp.lastEnrolledAt || null,
        totalIncidents,
        criticalHighCount,
        lastIncidentAt: stats.lastIncidentAt || null
      };
    });

    res.json(enrichedEmployees);
  } catch (err) {
    console.error('Admin employees fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve employees.' });
  }
});

// GET /api/admin/audit-logs - Administrative audit trail
router.get('/audit-logs', async (req, res) => {
  try {
    const logs = await PolicyAuditLog.find({ organizationId: req.user.organizationId })
      .sort({ timestamp: -1 })
      .limit(50);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve audit logs.' });
  }
});

module.exports = router;
