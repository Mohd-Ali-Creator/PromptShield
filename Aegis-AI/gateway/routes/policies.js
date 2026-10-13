const express = require('express');
const router = express.Router();
const CompanyRule = require('../models/CompanyRule');
const PolicyAuditLog = require('../models/PolicyAuditLog');
const { authenticateToken, requireAdmin } = require('../middleware/auth');

// Require authentication and admin role for all policy management endpoints
router.use(authenticateToken, requireAdmin);

// Structural ReDoS heuristics from PromptShield AI Company Data DNA Engine
const REDOS_PATTERNS = [
  /(\(([^)]+)\)[\+\*]){1,}[\+\*]/,     // nested quantifiers like (a+)+
  /\([^)]*[\+\*][^)]*\)[\+\*]/,        // group with quantifier, then quantifier
  /(\.\+|\.\*)\){0,1}[\+\*]/,          // .+ or .* followed by quantifier
  /\{[2-9]\d*,\d*\}[\+\*]/,            // {2,}+ patterns
  /\|[^)]{0,20}\|/,                    // nested alternation (a|a)
];

const MAX_EXACT_LENGTH = 512;
const MAX_REGEX_LENGTH = 256;

function validateRuleInput(rule) {
  if (!rule || typeof rule !== 'object') {
    return { valid: false, error: 'Rule must be a plain object.' };
  }
  if (!rule.id || typeof rule.id !== 'string' || !/^[A-Za-z0-9_\-]+$/.test(rule.id)) {
    return { valid: false, error: 'Rule ID must contain only alphanumeric characters, underscores, or hyphens.' };
  }
  if (!rule.name || typeof rule.name !== 'string' || rule.name.trim().length === 0) {
    return { valid: false, error: 'Rule name is required.' };
  }
  if (!['exact', 'regex'].includes(rule.patternType)) {
    return { valid: false, error: 'Pattern type must be "exact" or "regex".' };
  }
  if (!rule.pattern || typeof rule.pattern !== 'string' || rule.pattern.trim().length === 0) {
    return { valid: false, error: 'Pattern string is required.' };
  }
  if (rule.patternType === 'exact' && rule.pattern.length > MAX_EXACT_LENGTH) {
    return { valid: false, error: `Exact pattern exceeds max length of ${MAX_EXACT_LENGTH}.` };
  }
  if (rule.patternType === 'regex') {
    if (rule.pattern.length > MAX_REGEX_LENGTH) {
      return { valid: false, error: `Regex pattern exceeds max length of ${MAX_REGEX_LENGTH}.` };
    }
    for (const rp of REDOS_PATTERNS) {
      if (rp.test(rule.pattern)) {
        return { valid: false, error: 'Regex pattern rejected due to catastrophic backtracking (ReDoS) vulnerability.' };
      }
    }
    try {
      new RegExp(rule.pattern, 'gi');
    } catch (e) {
      return { valid: false, error: `Invalid RegExp syntax: ${e.message}` };
    }
  }
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(rule.severity)) {
    return { valid: false, error: 'Severity must be CRITICAL, HIGH, MEDIUM, or LOW.' };
  }
  if (!['block', 'warn', 'redact'].includes(rule.action)) {
    return { valid: false, error: 'Action must be block, warn, or redact.' };
  }
  return { valid: true };
}

// GET /api/policies/rules - List all rules for admin's organization
router.get('/rules', async (req, res) => {
  try {
    const rules = await CompanyRule.find({ organizationId: req.user.organizationId }).sort({ updatedAt: -1 });
    res.json(rules);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve company rules.' });
  }
});

// POST /api/policies/rules - Create a new rule
router.post('/rules', async (req, res) => {
  try {
    const validation = validateRuleInput(req.body);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const { id, name, description, patternType, pattern, severity, action, enabled } = req.body;
    const orgId = req.user.organizationId;

    const existing = await CompanyRule.findOne({ organizationId: orgId, id });
    if (existing) {
      return res.status(400).json({ error: `Rule with ID "${id}" already exists in your organization.` });
    }

    const newRule = await new CompanyRule({
      organizationId: orgId,
      id,
      name: name.trim(),
      description: (description || '').trim(),
      patternType,
      pattern: pattern.trim(),
      severity,
      action,
      enabled: enabled !== false,
      version: 1,
      updatedBy: req.user._id,
      updatedAt: new Date()
    }).save();

    // Audit log
    await new PolicyAuditLog({
      organizationId: orgId,
      actorId: req.user._id,
      actorEmail: req.user.email,
      actionType: 'CREATE_RULE',
      ruleId: id,
      ruleName: name,
      details: `Created ${patternType} rule "${name}" with severity ${severity} and action ${action}.`
    }).save();

    res.status(201).json(newRule);
  } catch (err) {
    console.error('Create rule error:', err);
    res.status(500).json({ error: 'Failed to create rule: ' + err.message });
  }
});

// PUT /api/policies/rules/:id - Update existing rule
router.put('/rules/:id', async (req, res) => {
  try {
    const rule = await CompanyRule.findOne({ organizationId: req.user.organizationId, id: req.params.id });
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found.' });
    }

    const validation = validateRuleInput({ ...rule.toObject(), ...req.body, id: rule.id });
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const { name, description, patternType, pattern, severity, action, enabled } = req.body;
    if (name) rule.name = name.trim();
    if (description !== undefined) rule.description = description.trim();
    if (patternType) rule.patternType = patternType;
    if (pattern) rule.pattern = pattern.trim();
    if (severity) rule.severity = severity;
    if (action) rule.action = action;
    if (enabled !== undefined) rule.enabled = Boolean(enabled);
    rule.version += 1;
    rule.updatedBy = req.user._id;
    rule.updatedAt = new Date();

    await rule.save();

    // Audit log
    await new PolicyAuditLog({
      organizationId: req.user.organizationId,
      actorId: req.user._id,
      actorEmail: req.user.email,
      actionType: 'UPDATE_RULE',
      ruleId: rule.id,
      ruleName: rule.name,
      details: `Updated rule configuration to version ${rule.version}.`
    }).save();

    res.json(rule);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update rule: ' + err.message });
  }
});

// DELETE /api/policies/rules/:id - Delete rule
router.delete('/rules/:id', async (req, res) => {
  try {
    const rule = await CompanyRule.findOneAndDelete({ organizationId: req.user.organizationId, id: req.params.id });
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found.' });
    }

    // Audit log
    await new PolicyAuditLog({
      organizationId: req.user.organizationId,
      actorId: req.user._id,
      actorEmail: req.user.email,
      actionType: 'DELETE_RULE',
      ruleId: rule.id,
      ruleName: rule.name,
      details: `Permanently removed rule "${rule.name}".`
    }).save();

    res.json({ message: `Rule "${rule.id}" deleted successfully.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete rule: ' + err.message });
  }
});

// POST /api/policies/test - Test a pattern against synthetic text (safe test sandbox)
router.post('/test', (req, res) => {
  try {
    const { patternType, pattern, sampleText } = req.body;
    if (!pattern || typeof pattern !== 'string') {
      return res.status(400).json({ error: 'Pattern is required.' });
    }
    if (!sampleText || typeof sampleText !== 'string') {
      return res.status(400).json({ error: 'Sample test text is required.' });
    }

    const validation = validateRuleInput({
      id: 'TEST-001',
      name: 'Test Rule',
      patternType,
      pattern,
      severity: 'HIGH',
      action: 'block'
    });
    if (!validation.valid) {
      return res.status(400).json({ valid: false, error: validation.error });
    }

    let regex;
    if (patternType === 'exact') {
      const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      regex = new RegExp('(?<![\\w-])' + escaped + '(?![\\w-])', 'gi');
    } else {
      regex = new RegExp(pattern, 'gi');
    }

    const matches = sampleText.match(regex) || [];
    res.json({
      valid: true,
      matched: matches.length > 0,
      matchCount: matches.length,
      // Sanitized feedback: show match count and masked indicator, never raw text
      matchesMasked: matches.map(m => m.slice(0, 2) + '*'.repeat(Math.max(2, m.length - 2)))
    });
  } catch (err) {
    res.status(500).json({ error: 'Test execution error: ' + err.message });
  }
});

module.exports = router;
