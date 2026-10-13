const express = require('express');
const router = express.Router();
const PromptShieldIncident = require('../models/PromptShieldIncident');
const CompanyRule = require('../models/CompanyRule');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');

function createExtensionRouter(io) {
  // GET /api/extension/status - Verify extension connectivity and enroll user
  router.get('/status', authenticateToken, async (req, res) => {
    try {
      await User.findByIdAndUpdate(req.user._id, {
        extensionEnrolled: true,
        lastEnrolledAt: new Date()
      });

      res.json({
        status: 'online',
        authenticated: true,
        user: {
          id: req.user._id,
          name: req.user.name,
          role: req.user.role,
          organizationId: req.user.organizationId,
          organizationName: req.user.organizationName,
          extensionEnrolled: true
        }
      });
    } catch (err) {
      res.status(500).json({ error: 'Failed to verify extension status.' });
    }
  });

  // GET /api/extension/rules - Sync active company rules for user's organization
  router.get('/rules', authenticateToken, async (req, res) => {
    try {
      const activeRules = await CompanyRule.find({
        organizationId: req.user.organizationId,
        enabled: true
      }).select('id name description patternType pattern severity action enabled version');

      res.json({
        rules: activeRules,
        version: activeRules.length > 0 ? Math.max(...activeRules.map(r => r.version || 1)) : 1,
        count: activeRules.length
      });
    } catch (err) {
      console.error('Extension rules sync error:', err.message);
      res.status(500).json({ error: 'Failed to retrieve company rules.' });
    }
  });

  // POST /api/extension/incidents - Ingest sanitized security event
  router.post('/incidents', authenticateToken, async (req, res) => {
    try {
      const {
        eventId,
        occurredAt,
        sourcePlatform,
        ruleId,
        ruleName,
        severity,
        action,
        detectorVersion,
        policyVersion,
        eventType,
        sanitizedMetadata
      } = req.body;

      // 1. Mandatory Field Validation
      if (!eventId || typeof eventId !== 'string') {
        return res.status(400).json({ error: 'Valid eventId is required.' });
      }
      if (!ruleId || typeof ruleId !== 'string') {
        return res.status(400).json({ error: 'Valid ruleId is required.' });
      }

      const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      const validActions = ['BLOCKED', 'WARNED', 'REDACTED', 'ALLOWED'];
      const safeSeverity = validSeverities.includes(severity) ? severity : 'MEDIUM';
      const safeAction = validActions.includes(action) ? action : 'BLOCKED';

      // 2. Strict Privacy Checks: Reject any payload containing suspicious prompt fields
      const forbiddenKeys = ['rawPrompt', 'prompt', 'secret', 'password', 'key', 'fullMatch', 'clipboard', 'cookie', 'token'];
      const topLevelKeys = Object.keys(req.body);
      for (const k of forbiddenKeys) {
        if (topLevelKeys.includes(k) && req.body[k]) {
          return res.status(400).json({ error: `Privacy violation: Payload contains prohibited field "${k}". Raw prompts and secrets are never permitted.` });
        }
      }

      // 3. Authoritative Identity Assignment (Never trust client-submitted userId/orgId)
      const authoritativeEmployeeId = req.user._id;
      const authoritativeOrgId = req.user.organizationId;
      const authoritativeEmployeeName = req.user.name;
      const authoritativeEmployeeEmail = req.user.email;

      // 4. Idempotent Ingestion Check
      const existing = await PromptShieldIncident.findOne({ eventId });
      if (existing) {
        return res.json({
          status: 'acknowledged',
          duplicate: true,
          incidentId: existing._id,
          message: 'Event was already ingested (idempotent duplicate).'
        });
      }

      // 5. Sanitize Metadata
      const cleanMetadata = {
        promptLengthChars: typeof sanitizedMetadata?.promptLengthChars === 'number' ? sanitizedMetadata.promptLengthChars : 0,
        matchCount: typeof sanitizedMetadata?.matchCount === 'number' ? sanitizedMetadata.matchCount : 1,
        isCompanyRule: Boolean(sanitizedMetadata?.isCompanyRule),
        companyAction: typeof sanitizedMetadata?.companyAction === 'string' ? sanitizedMetadata.companyAction : null,
        explanation: typeof sanitizedMetadata?.explanation === 'string' ? sanitizedMetadata.explanation.slice(0, 300) : ''
      };

      // 6. Save Incident
      const incident = await new PromptShieldIncident({
        eventId,
        organizationId: authoritativeOrgId,
        employeeId: authoritativeEmployeeId,
        employeeName: authoritativeEmployeeName,
        employeeEmail: authoritativeEmployeeEmail,
        occurredAt: occurredAt ? new Date(occurredAt) : new Date(),
        receivedAt: new Date(),
        sourcePlatform: (sourcePlatform && typeof sourcePlatform === 'string') ? sourcePlatform.slice(0, 50) : 'chatgpt',
        ruleId: ruleId.slice(0, 50),
        ruleName: (ruleName && typeof ruleName === 'string') ? ruleName.slice(0, 100) : ruleId,
        severity: safeSeverity,
        action: safeAction,
        detectorVersion: detectorVersion || '1.0.0',
        policyVersion: policyVersion || '1.0.0',
        eventType: eventType || 'detection',
        sanitizedMetadata: cleanMetadata
      }).save();

      // Ensure employee is tracked as enrolled
      User.findByIdAndUpdate(authoritativeEmployeeId, {
        extensionEnrolled: true,
        lastEnrolledAt: new Date()
      }).catch(() => {});

      // 7. Real-time Organization-Scoped Notification
      if (io) {
        const orgRoom = `org_${authoritativeOrgId.toString()}`;
        io.to(orgRoom).emit('promptshield_incident', {
          id: incident._id,
          eventId: incident.eventId,
          occurredAt: incident.occurredAt,
          employeeName: incident.employeeName,
          ruleId: incident.ruleId,
          ruleName: incident.ruleName,
          severity: incident.severity,
          action: incident.action,
          sourcePlatform: incident.sourcePlatform
        });
      }

      res.status(201).json({
        status: 'recorded',
        incidentId: incident._id,
        eventId: incident.eventId
      });
    } catch (err) {
      console.error('Incident ingestion error:', err.message);
      res.status(500).json({ error: 'Incident ingestion error: ' + err.message });
    }
  });

  return router;
}

module.exports = createExtensionRouter;
