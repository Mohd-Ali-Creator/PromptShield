const express = require('express');
const router = express.Router();
const PromptShieldIncident = require('../models/PromptShieldIncident');
const MessageLog = require('../models/MessageLog');
const { authenticateToken } = require('../middleware/auth');

/**
 * Normalizes action strings to standard categories:
 * - BLOCKED: 'BLOCK', 'BLOCKED', 'blocked', 'block'
 * - SANITIZED: 'REDACT', 'REDACTED', 'SANITIZE', 'SANITIZED', 'redacted', 'sanitized'
 * - ALLOWED: 'ALLOW', 'ALLOWED', 'allowed', 'allow', 'WARN', 'WARNED', 'warned'
 */
function normalizeAction(rawAction) {
  if (!rawAction) return 'ALLOWED';
  const a = String(rawAction).toUpperCase().trim();
  if (a === 'BLOCK' || a === 'BLOCKED') return 'BLOCKED';
  if (a === 'REDACT' || a === 'REDACTED' || a === 'SANITIZE' || a === 'SANITIZED') return 'SANITIZED';
  if (a === 'ALLOW' || a === 'ALLOWED') return 'ALLOWED';
  if (a === 'WARN' || a === 'WARNED') return 'ALLOWED'; // Warned prompts are permitted through without blocking/redaction
  return 'ALLOWED';
}

function severityToScore(severity, metadata) {
  if (metadata && typeof metadata.promptLengthChars === 'number' && typeof metadata.risk_score === 'number') {
    return metadata.risk_score <= 1 ? metadata.risk_score * 100 : metadata.risk_score;
  }
  const s = String(severity || '').toUpperCase().trim();
  if (s === 'CRITICAL') return 95;
  if (s === 'HIGH') return 80;
  if (s === 'MEDIUM') return 50;
  if (s === 'LOW') return 20;
  return 0;
}

// GET /api/analytics - Unified security analytics from PromptShield incidents & protected scans
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const orgId = req.user.organizationId;
    const userId = req.user._id;
    const isAdmin = req.user.role === 'admin';

    // 1. Build query filters with strict organization & role isolation (no mock/null fallback)
    const incidentFilter = { organizationId: orgId };
    const messageFilter = {
      organizationId: orgId,
      isProtected: true,
      security: { $ne: null },
      role: { $in: ['assistant', 'system'] }
    };

    if (!isAdmin) {
      // Employees see only their own scan events
      incidentFilter.employeeId = userId;
      messageFilter.userId = userId;
    }

    // 2. Apply Date Range Filters
    if (startDate) {
      const start = new Date(startDate.includes('T') ? startDate : `${startDate}T00:00:00.000Z`);
      if (!isNaN(start.getTime())) {
        incidentFilter.occurredAt = { ...(incidentFilter.occurredAt || {}), $gte: start };
        messageFilter.timestamp = { ...(messageFilter.timestamp || {}), $gte: start };
      }
    }

    if (endDate) {
      const end = new Date(endDate.includes('T') ? endDate : `${endDate}T23:59:59.999Z`);
      if (!isNaN(end.getTime())) {
        incidentFilter.occurredAt = { ...(incidentFilter.occurredAt || {}), $lte: end };
        messageFilter.timestamp = { ...(messageFilter.timestamp || {}), $lte: end };
      }
    }

    // 3. Query both persistent data sources in parallel
    const [incidents, messageLogs] = await Promise.all([
      PromptShieldIncident.find(incidentFilter).sort({ occurredAt: 1 }).select('-__v'),
      MessageLog.find(messageFilter).sort({ timestamp: 1 }).select('-__v')
    ]);

    // 4. Deduplicate and normalize events using unique event IDs
    const eventMap = new Map();

    // Ingest PromptShield Incidents
    for (const inc of incidents) {
      const eventId = inc.eventId || inc._id.toString();
      const normAction = normalizeAction(inc.action);
      const score = severityToScore(inc.severity, inc.sanitizedMetadata);
      const time = new Date(inc.occurredAt || inc.createdAt);

      eventMap.set(eventId, {
        eventId,
        finalAction: normAction,
        rawAction: inc.action,
        severity: inc.severity || 'MEDIUM',
        riskScore: score,
        timestamp: time,
        source: 'promptshield',
        platform: inc.sourcePlatform || 'chatgpt',
        ruleId: inc.ruleId || 'SEC-001',
        ruleName: inc.ruleName || inc.ruleId
      });
    }

    // Ingest Web Console / Gateway scans
    for (const log of messageLogs) {
      const eventId = log.security?.eventId || log.security?.event_id || log._id.toString();
      const normAction = normalizeAction(log.security?.action);
      const rawScore = typeof log.security?.risk_score === 'number'
        ? (log.security.risk_score <= 1 ? log.security.risk_score * 100 : log.security.risk_score)
        : severityToScore(log.security?.risk_level);
      const time = new Date(log.timestamp);

      if (eventMap.has(eventId)) {
        // If event already recorded from extension, prioritize BLOCKED if either blocked
        const existing = eventMap.get(eventId);
        if (existing.finalAction !== 'BLOCKED' && normAction === 'BLOCKED') {
          existing.finalAction = 'BLOCKED';
          existing.rawAction = log.security?.action || existing.rawAction;
        }
      } else {
        eventMap.set(eventId, {
          eventId,
          finalAction: normAction,
          rawAction: log.security?.action || 'ALLOWED',
          severity: log.security?.risk_level || 'SAFE',
          riskScore: rawScore,
          timestamp: time,
          source: 'gateway_console',
          platform: 'console',
          ruleId: log.security?.threat_reasons?.[0]?.type || 'GATEWAY_RULE',
          ruleName: 'Console Guardrail'
        });
      }
    }

    // 5. Calculate Metrics with clear semantics:
    // - Scanned = unique scan events
    // - Blocked = unique events whose final action was block
    // - Sanitized = unique events whose final action was redact/sanitize
    // - Allowed = unique events whose final action was allow
    // Each unique event is counted once and only once: scanned = blocked + sanitized + allowed
    const allEvents = Array.from(eventMap.values()).sort((a, b) => a.timestamp - b.timestamp);

    let blocked = 0;
    let sanitized = 0;
    let allowed = 0;

    for (const evt of allEvents) {
      if (evt.finalAction === 'BLOCKED') {
        blocked++;
      } else if (evt.finalAction === 'SANITIZED') {
        sanitized++;
      } else {
        allowed++;
      }
    }

    const scanned = blocked + sanitized + allowed;

    // 6. Action Distribution Pie Chart Data (strictly matching KPI counts)
    const actionDistribution = [
      { name: 'Blocked', value: blocked, color: '#ef4444' },
      { name: 'Sanitized', value: sanitized, color: '#3b82f6' },
      { name: 'Allowed', value: allowed, color: '#10b981' }
    ];

    // 7. Recent Risk Volume Bar Chart Data (chronological last 10 scan events)
    const recentSlice = allEvents.slice(-10);
    const recentRiskVolume = recentSlice.map((evt, idx) => ({
      id: evt.eventId,
      name: `Req ${idx + 1}`,
      score: Math.round(evt.riskScore),
      action: evt.finalAction,
      severity: evt.severity,
      timestamp: evt.timestamp.toISOString(),
      platform: evt.platform
    }));

    res.json({
      summary: {
        scanned,
        blocked,
        sanitized,
        allowed
      },
      actionDistribution,
      recentRiskVolume,
      totalEvents: scanned,
      filters: {
        startDate: startDate || null,
        endDate: endDate || null,
        role: req.user.role,
        organizationId: orgId
      }
    });
  } catch (err) {
    console.error('Analytics aggregation error:', err);
    res.status(500).json({ error: 'Failed to aggregate security analytics: ' + err.message });
  }
});

module.exports = {
  router,
  normalizeAction,
  severityToScore
};
