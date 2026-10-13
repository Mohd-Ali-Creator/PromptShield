/**
 * Aegis-AI + PromptShield AI - Analytics Dashboard Test Suite
 *
 * Verifies:
 * 1. Metric semantics: Scanned = unique scan events.
 * 2. Blocked = unique events whose final action was block.
 * 3. Sanitized = unique events whose final action was redact/sanitize.
 * 4. Allowed = unique events whose final action was allow.
 * 5. Each event is counted once and only once: Scanned = Blocked + Sanitized + Allowed.
 * 6. Action normalization: 'BLOCKED', 'blocked', 'block', 'REDACTED', 'redact', 'SANITIZED', 'sanitize', 'ALLOWED', 'allow', 'WARNED', 'warn'.
 * 7. Duplicate event IDs and retries are deduplicated idempotently (no double counting).
 * 8. Action Distribution graph and Recent Risk Volume chart match KPI card values.
 * 9. Date range filtering (startDate, endDate).
 * 10. Role and tenant scoping: employees see only their own events; admins see only their own organization's events.
 * 11. Mock / unassociated data (userId: null) is never leaked to authenticated users.
 * 12. Empty state when no events exist.
 *
 * Run via: node --test tests/analytics-dashboard.test.js
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('../gateway/node_modules/mongoose');

const { app } = require('../gateway/server');
const User = require('../gateway/models/User');
const Organization = require('../gateway/models/Organization');
const PromptShieldIncident = require('../gateway/models/PromptShieldIncident');
const MessageLog = require('../gateway/models/MessageLog');
const { normalizeAction, severityToScore } = require('../gateway/routes/analytics');

const TEST_PORT = 4102;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

describe('Analytics Dashboard Comprehensive Test Suite', () => {
  let testServer;
  let orgA;
  let orgB;
  let empAToken;
  let empAUser;
  let empA2Token;
  let empA2User;
  let adminAToken;
  let adminAUser;
  let empBToken;
  let empBUser;

  before(async () => {
    await new Promise((resolve) => {
      testServer = app.listen(TEST_PORT, resolve);
    });

    const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/aegis_analytics_test';
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(MONGO_URI);
    } else if (mongoose.connection.readyState === 2) {
      await new Promise(resolve => mongoose.connection.once('connected', resolve));
    }

    const ts = Date.now();

    // 1. Setup Org A
    orgA = await new Organization({
      name: `Analytics Test Org A ${ts}`,
      slug: `test-org-a-${ts}`
    }).save();

    // 2. Setup Org B
    orgB = await new Organization({
      name: `Analytics Test Org B ${ts}`,
      slug: `test-org-b-${ts}`
    }).save();

    // 3. Register Employee 1 in Org A
    const regEmpA = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Employee Alice',
        email: `alice-${ts}@org-a.com`,
        password: 'Password123!',
        organizationName: orgA.name
      })
    });
    const dataEmpA = await regEmpA.json();
    empAToken = dataEmpA.token;
    empAUser = dataEmpA.user;

    // 4. Register Employee 2 in Org A
    const regEmpA2 = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Employee Charlie',
        email: `charlie-${ts}@org-a.com`,
        password: 'Password123!',
        organizationName: orgA.name
      })
    });
    const dataEmpA2 = await regEmpA2.json();
    empA2Token = dataEmpA2.token;
    empA2User = dataEmpA2.user;

    // 5. Register Admin in Org A
    const regAdminA = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Admin Dave',
        email: `admin-dave-${ts}@org-a.com`,
        password: 'Password123!',
        organizationName: orgA.name,
        adminSecret: 'aegis-admin-provision-2026'
      })
    });
    const dataAdminA = await regAdminA.json();
    adminAToken = dataAdminA.token;
    adminAUser = dataAdminA.user;

    // 6. Register Employee in Org B (for multi-tenant isolation)
    const regEmpB = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Employee Bob',
        email: `bob-${ts}@org-b.com`,
        password: 'Password123!',
        organizationName: orgB.name
      })
    });
    const dataEmpB = await regEmpB.json();
    empBToken = dataEmpB.token;
    empBUser = dataEmpB.user;
  });

  after(async () => {
    if (orgA) {
      await User.deleteMany({ organizationId: orgA._id });
      await PromptShieldIncident.deleteMany({ organizationId: orgA._id });
      await MessageLog.deleteMany({ organizationId: orgA._id });
      await Organization.findByIdAndDelete(orgA._id);
    }
    if (orgB) {
      await User.deleteMany({ organizationId: orgB._id });
      await PromptShieldIncident.deleteMany({ organizationId: orgB._id });
      await MessageLog.deleteMany({ organizationId: orgB._id });
      await Organization.findByIdAndDelete(orgB._id);
    }
    if (testServer) {
      await new Promise((resolve) => testServer.close(resolve));
    }
    await mongoose.disconnect();
  });

  // ─── 1. Unit Normalization Tests ──────────────────────────────────────────

  describe('1. Action Normalization & Scoring Logic', () => {
    it('normalizes action variants correctly', () => {
      assert.equal(normalizeAction('BLOCK'), 'BLOCKED');
      assert.equal(normalizeAction('blocked'), 'BLOCKED');
      assert.equal(normalizeAction('BLOCKED'), 'BLOCKED');
      assert.equal(normalizeAction('block'), 'BLOCKED');

      assert.equal(normalizeAction('REDACT'), 'SANITIZED');
      assert.equal(normalizeAction('redacted'), 'SANITIZED');
      assert.equal(normalizeAction('SANITIZE'), 'SANITIZED');
      assert.equal(normalizeAction('sanitized'), 'SANITIZED');

      assert.equal(normalizeAction('ALLOW'), 'ALLOWED');
      assert.equal(normalizeAction('allowed'), 'ALLOWED');
      assert.equal(normalizeAction('ALLOWED'), 'ALLOWED');
      assert.equal(normalizeAction('WARN'), 'ALLOWED');
      assert.equal(normalizeAction('warned'), 'ALLOWED');
      assert.equal(normalizeAction(null), 'ALLOWED');
      assert.equal(normalizeAction(undefined), 'ALLOWED');
    });

    it('maps severity to numerical risk score', () => {
      assert.equal(severityToScore('CRITICAL'), 95);
      assert.equal(severityToScore('HIGH'), 80);
      assert.equal(severityToScore('MEDIUM'), 50);
      assert.equal(severityToScore('LOW'), 20);
      assert.equal(severityToScore('SAFE'), 0);
      assert.equal(severityToScore('unknown'), 0);
    });
  });

  // ─── 2. Empty State ───────────────────────────────────────────────────────

  describe('2. Empty State Verification', () => {
    it('returns zero counts and empty arrays when no scan events exist for employee', async () => {
      const res = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${empAToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.deepEqual(data.summary, {
        scanned: 0,
        blocked: 0,
        sanitized: 0,
        allowed: 0
      });
      assert.equal(data.totalEvents, 0);
      assert.equal(data.recentRiskVolume.length, 0);

      // Action distribution must have 0 values
      for (const item of data.actionDistribution) {
        assert.equal(item.value, 0);
      }
    });

    it('rejects unauthenticated requests with 401', async () => {
      const res = await fetch(`${BASE_URL}/api/analytics`);
      assert.equal(res.status, 401);
    });
  });

  // ─── 3. Ingestion & Semantics: Blocked, Sanitized, Allowed ─────────────────

  describe('3. Ingestion & Category Semantics', () => {
    it('accurately counts unique Blocked, Sanitized, and Allowed events', async () => {
      const now = Date.now();

      // Event 1: BLOCKED incident (e.g. OpenAI key intercepted by PromptShield)
      await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${empAToken}`
        },
        body: JSON.stringify({
          eventId: `evt-blocked-${now}`,
          ruleId: 'SEC-002',
          ruleName: 'Synthetic API Key',
          severity: 'HIGH',
          action: 'BLOCKED',
          sourcePlatform: 'chatgpt'
        })
      });

      // Event 2: REDACTED / SANITIZED incident (e.g. Company Data DNA redaction rule)
      await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${empAToken}`
        },
        body: JSON.stringify({
          eventId: `evt-redacted-${now}`,
          ruleId: 'CDR-001',
          ruleName: 'Confidential Codename',
          severity: 'MEDIUM',
          action: 'REDACTED',
          sourcePlatform: 'chatgpt'
        })
      });

      // Event 3: ALLOWED incident (e.g. clean prompt evaluated)
      await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${empAToken}`
        },
        body: JSON.stringify({
          eventId: `evt-allowed-${now}`,
          ruleId: 'SEC-000',
          ruleName: 'Clean Prompt',
          severity: 'LOW',
          action: 'ALLOWED',
          sourcePlatform: 'chatgpt'
        })
      });

      // Query Analytics Dashboard
      const res = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${empAToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      // Semantics:
      // Scanned = 3
      // Blocked = 1
      // Sanitized = 1
      // Allowed = 1
      assert.equal(data.summary.scanned, 3);
      assert.equal(data.summary.blocked, 1);
      assert.equal(data.summary.sanitized, 1);
      assert.equal(data.summary.allowed, 1);

      // Invariant: Scanned must equal Blocked + Sanitized + Allowed
      assert.equal(
        data.summary.scanned,
        data.summary.blocked + data.summary.sanitized + data.summary.allowed
      );

      // Verify Action Distribution chart matches KPI counts exactly
      const blockedPie = data.actionDistribution.find(d => d.name === 'Blocked');
      const sanitizedPie = data.actionDistribution.find(d => d.name === 'Sanitized');
      const allowedPie = data.actionDistribution.find(d => d.name === 'Allowed');

      assert.equal(blockedPie.value, 1);
      assert.equal(sanitizedPie.value, 1);
      assert.equal(allowedPie.value, 1);

      // Verify Recent Risk Volume chart contains exactly 3 entries matching verified data
      assert.equal(data.recentRiskVolume.length, 3);
      const blockedBar = data.recentRiskVolume.find(r => r.action === 'BLOCKED');
      assert.ok(blockedBar);
      assert.equal(blockedBar.score, 80); // HIGH severity -> 80
    });
  });

  // ─── 4. Idempotency & Duplicate Protection ────────────────────────────────

  describe('4. Deduplication & Idempotency', () => {
    it('prevents double-counting retries with the same eventId', async () => {
      const stableEventId = `evt-idemp-${Date.now()}`;

      // First submission
      const res1 = await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${empAToken}`
        },
        body: JSON.stringify({
          eventId: stableEventId,
          ruleId: 'SEC-007',
          ruleName: 'Private Key Block',
          severity: 'CRITICAL',
          action: 'BLOCKED'
        })
      });
      assert.equal(res1.status, 201);

      // Second identical submission (e.g. extension retry or multi-event trigger)
      const res2 = await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${empAToken}`
        },
        body: JSON.stringify({
          eventId: stableEventId,
          ruleId: 'SEC-007',
          ruleName: 'Private Key Block',
          severity: 'CRITICAL',
          action: 'BLOCKED'
        })
      });
      assert.equal(res2.status, 200);
      const data2 = await res2.json();
      assert.equal(data2.duplicate, true);

      // Verify Analytics counts stableEventId only ONCE
      const resAnalytics = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${empAToken}` }
      });
      const analytics = await resAnalytics.json();

      // Prior was 3 + 1 new = 4 total, NOT 5
      assert.equal(analytics.summary.scanned, 4);
      assert.equal(analytics.summary.blocked, 2); // 1 prior + 1 new
    });
  });

  // ─── 5. Date Range Filtering ──────────────────────────────────────────────

  describe('5. Date Range Filtering', () => {
    it('filters incidents accurately by startDate and endDate', async () => {
      // Query with a past date range that has NO incidents
      const resEmptyRange = await fetch(
        `${BASE_URL}/api/analytics?startDate=2020-01-01&endDate=2020-01-31`,
        { headers: { 'Authorization': `Bearer ${empAToken}` } }
      );
      assert.equal(resEmptyRange.status, 200);
      const emptyData = await resEmptyRange.json();
      assert.equal(emptyData.summary.scanned, 0);
      assert.equal(emptyData.summary.blocked, 0);

      // Query with today's date range (should find our 4 events)
      const todayStr = new Date().toISOString().slice(0, 10);
      const resToday = await fetch(
        `${BASE_URL}/api/analytics?startDate=${todayStr}&endDate=${todayStr}`,
        { headers: { 'Authorization': `Bearer ${empAToken}` } }
      );
      assert.equal(resToday.status, 200);
      const todayData = await resToday.json();
      assert.equal(todayData.summary.scanned, 4);
      assert.equal(todayData.summary.blocked, 2);
    });
  });

  // ─── 6. Multi-Tenant & Role Isolation ─────────────────────────────────────

  describe('6. Role & Multi-Tenant Isolation', () => {
    it('employee CANNOT see other employees scan events in Org A', async () => {
      // Employee Charlie (empA2) has 0 incidents
      const resCharlie = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${empA2Token}` }
      });
      assert.equal(resCharlie.status, 200);
      const charlieData = await resCharlie.json();

      // Alice's 4 incidents must NOT be visible to Charlie
      assert.equal(charlieData.summary.scanned, 0);
      assert.equal(charlieData.summary.blocked, 0);
    });

    it('admin in Org A sees all incidents across all Org A employees', async () => {
      const resAdmin = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${adminAToken}` }
      });
      assert.equal(resAdmin.status, 200);
      const adminData = await resAdmin.json();

      // Admin sees Alice's 4 events in Org A
      assert.equal(adminData.summary.scanned, 4);
      assert.equal(adminData.summary.blocked, 2);
    });

    it('admin in Org A CANNOT see Org B incidents (Cross-Tenant Isolation)', async () => {
      // Ingest 1 BLOCKED incident for Bob in Org B
      await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${empBToken}`
        },
        body: JSON.stringify({
          eventId: `evt-org-b-${Date.now()}`,
          ruleId: 'SEC-999',
          ruleName: 'Org B Secret',
          severity: 'CRITICAL',
          action: 'BLOCKED'
        })
      });

      // Org B employee sees 1 event
      const resBob = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${empBToken}` }
      });
      const bobData = await resBob.json();
      assert.equal(bobData.summary.scanned, 1);
      assert.equal(bobData.summary.blocked, 1);

      // Org A admin still sees only 4 events (Bob's incident in Org B is NOT visible)
      const resAdminA = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${adminAToken}` }
      });
      const adminAData = await resAdminA.json();
      assert.equal(adminAData.summary.scanned, 4);
    });

    it('mock unassociated data (userId: null) is never leaked into analytics', async () => {
      // Verify Alice only sees her 4 events, never unassociated mock logs
      const resAlice = await fetch(`${BASE_URL}/api/analytics`, {
        headers: { 'Authorization': `Bearer ${empAToken}` }
      });
      const aliceData = await resAlice.json();
      assert.equal(aliceData.summary.scanned, 4);
    });
  });
});
