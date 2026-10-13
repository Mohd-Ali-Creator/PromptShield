/**
 * Aegis-AI + PromptShield AI - Gateway Security & RBAC Test Suite
 *
 * Verifies:
 * 1. Public registration cannot grant admin privileges.
 * 2. Unauthenticated access to /api/history is rejected (401).
 * 3. Employee cannot delete history (403).
 * 4. Authenticated PromptShield incident ingestion works.
 * 5. Incident ingestion rejects payloads with raw prompts/secrets (Privacy Guarantee).
 * 6. Duplicate incident eventId is handled idempotently.
 * 7. Employee can view only their own incidents.
 * 8. Employee cannot access Admin Security Dashboard endpoints (403).
 * 9. Admin can access their organization's metrics and incidents.
 * 10. Admin cannot view another organization's incidents (Tenant Isolation).
 * 11. Company Data DNA rules CRUD and ReDoS pattern rejection.
 *
 * Run via: node --test tests/gateway-security.test.js
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const mongoose = require('../gateway/node_modules/mongoose');

// Gateway modules
const { app, server } = require('../gateway/server');
const User = require('../gateway/models/User');
const Organization = require('../gateway/models/Organization');
const PromptShieldIncident = require('../gateway/models/PromptShieldIncident');
const CompanyRule = require('../gateway/models/CompanyRule');
const MessageLog = require('../gateway/models/MessageLog');

const TEST_PORT = 4101;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

describe('Aegis-AI Gateway Security & Multi-Tenant Access Control', () => {
  let testServer;
  let employeeToken;
  let employeeUser;
  let employee2Token;
  let employee2User;
  let adminToken;
  let adminUser;
  let org1;
  let org2;

  before(async () => {
    // Start test server on unique port
    await new Promise((resolve) => {
      testServer = app.listen(TEST_PORT, resolve);
    });

    // Connect to Mongo if needed
    const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/aegis_analytics_test';
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(MONGO_URI);
    }

    // Clean test collections
    await User.deleteMany({ email: /@test-aegis\.local$/ });
    await Organization.deleteMany({ slug: /test-org/ });
    await PromptShieldIncident.deleteMany({ eventId: /^test-evt-/ });
    await CompanyRule.deleteMany({ id: /^TEST-/ });

    // Setup Organization 1 and Organization 2
    org1 = await new Organization({ name: 'Alpha Security Corp', slug: 'test-org-alpha' }).save();
    org2 = await new Organization({ name: 'Beta Analytics Corp', slug: 'test-org-beta' }).save();
  });

  after(async () => {
    // Cleanup
    await User.deleteMany({ email: /@test-aegis\.local$/ });
    await Organization.deleteMany({ slug: /test-org/ });
    await PromptShieldIncident.deleteMany({ eventId: /^test-evt-/ });
    await CompanyRule.deleteMany({ id: /^TEST-/ });

    if (testServer) {
      await new Promise(resolve => testServer.close(resolve));
    }
    await mongoose.disconnect();
  });

  // ─── 1. Authentication & Registration Security ───────────────────────────

  describe('1. Authentication & Role-Based Registration', () => {
    it('public registration CANNOT self-escalate to admin (must default to employee)', async () => {
      const res = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Eve Malicious',
          email: 'eve@test-aegis.local',
          password: 'Password123!',
          role: 'admin' // Attempting privilege escalation
        })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.user.role, 'employee', 'User must NOT be granted admin privileges via public registration');
      employeeUser = data.user;
      employeeToken = data.token;
    });

    it('registration with valid adminSecret grants admin role', async () => {
      const res = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Alice Admin',
          email: 'alice@test-aegis.local',
          password: 'Password123!',
          adminSecret: 'aegis-admin-provision-2026',
          organizationName: 'Alpha Security Corp'
        })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.user.role, 'admin');
      adminUser = data.user;
      adminToken = data.token;

      // Update org association to ensure org1
      await User.updateOne({ _id: adminUser.id }, { organizationId: org1._id });
      await User.updateOne({ _id: employeeUser.id }, { organizationId: org1._id });
    });

    it('register second employee in Org 2 for tenant isolation checks', async () => {
      const res = await fetch(`${BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Bob Employee 2',
          email: 'bob@test-aegis.local',
          password: 'Password123!',
          organizationName: 'Beta Analytics Corp'
        })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      employee2User = data.user;
      employee2Token = data.token;
      await User.updateOne({ _id: employee2User.id }, { organizationId: org2._id });
    });
  });

  // ─── 2. History Endpoint Scoping & Authorization ─────────────────────────

  describe('2. History Authorization & Tenant Scoping', () => {
    it('unauthenticated GET /api/history is rejected with 401', async () => {
      const res = await fetch(`${BASE_URL}/api/history`);
      assert.equal(res.status, 401, 'Unauthenticated history requests must be rejected');
    });

    it('employee CANNOT clear history (DELETE /api/history rejected with 403)', async () => {
      const res = await fetch(`${BASE_URL}/api/history`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(res.status, 403, 'Employees must not be permitted to wipe chat history');
    });

    it('admin can access GET /api/history', async () => {
      const res = await fetch(`${BASE_URL}/api/history`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data));
    });
  });

  // ─── 3. Incident Ingestion & Strict Privacy Verification ─────────────────

  describe('3. Incident Ingestion & Privacy Guarantees', () => {
    it('unauthenticated POST /api/extension/incidents is rejected with 401', async () => {
      const res = await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId: 'test-evt-unauth-001',
          ruleId: 'SEC-002',
          severity: 'CRITICAL',
          action: 'BLOCKED'
        })
      });
      assert.equal(res.status, 401);
    });

    it('REJECTS payload containing raw prompt or secret fields (Privacy Enforcement)', async () => {
      const res = await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${employeeToken}`
        },
        body: JSON.stringify({
          eventId: 'test-evt-leak-001',
          ruleId: 'SEC-002',
          severity: 'CRITICAL',
          action: 'BLOCKED',
          rawPrompt: 'Here is my OpenAI Key: sk-proj-1234567890...' // Prohibited field
        })
      });

      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Privacy violation/i);
    });

    it('successfully ingests clean sanitized incident metadata with authoritative identity', async () => {
      const res = await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${employeeToken}`
        },
        body: JSON.stringify({
          eventId: 'test-evt-clean-001',
          ruleId: 'SEC-002',
          ruleName: 'Synthetic OpenAI API Key',
          severity: 'CRITICAL',
          action: 'BLOCKED',
          sourcePlatform: 'chatgpt',
          detectorVersion: '1.0.0',
          sanitizedMetadata: {
            promptLengthChars: 85,
            matchCount: 1,
            isCompanyRule: false,
            explanation: 'Blocked high-risk synthetic API key pattern.'
          }
        })
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.status, 'recorded');
      assert.equal(data.eventId, 'test-evt-clean-001');

      // Verify stored record in database contains authoritative employee and org ID
      const stored = await PromptShieldIncident.findOne({ eventId: 'test-evt-clean-001' });
      assert.ok(stored);
      assert.equal(stored.employeeEmail, 'eve@test-aegis.local');
      assert.equal(stored.organizationId.toString(), org1._id.toString());
      assert.equal(stored.severity, 'CRITICAL');
      assert.equal(stored.action, 'BLOCKED');
      // Verify raw prompt does not exist
      assert.equal(stored.content, undefined);
      assert.equal(stored.rawPrompt, undefined);
    });

    it('handles duplicate eventId idempotently without double-counting', async () => {
      const res = await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${employeeToken}`
        },
        body: JSON.stringify({
          eventId: 'test-evt-clean-001', // Exact same eventId
          ruleId: 'SEC-002',
          severity: 'CRITICAL',
          action: 'BLOCKED'
        })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.duplicate, true);
    });
  });

  // ─── 4. Employee Reports Scoping & Isolation ─────────────────────────────

  describe('4. Employee Reports Scoping', () => {
    it('employee sees only their own incidents', async () => {
      // Ingest incident for Employee 2 (Org 2)
      await fetch(`${BASE_URL}/api/extension/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${employee2Token}`
        },
        body: JSON.stringify({
          eventId: 'test-evt-emp2-001',
          ruleId: 'CDR-001',
          ruleName: 'Project Falcon Codename',
          severity: 'HIGH',
          action: 'BLOCKED',
          sourcePlatform: 'chatgpt'
        })
      });

      // Employee 1 queries reports
      const res1 = await fetch(`${BASE_URL}/api/reports/employee`, {
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(res1.status, 200);
      const data1 = await res1.json();
      assert.ok(data1.incidents.length >= 1);
      // All incidents must belong to Employee 1
      for (const inc of data1.incidents) {
        assert.equal(inc.employeeEmail, 'eve@test-aegis.local');
      }

      // Employee 2 queries reports
      const res2 = await fetch(`${BASE_URL}/api/reports/employee`, {
        headers: { 'Authorization': `Bearer ${employee2Token}` }
      });
      assert.equal(res2.status, 200);
      const data2 = await res2.json();
      assert.ok(data2.incidents.length >= 1);
      for (const inc of data2.incidents) {
        assert.equal(inc.employeeEmail, 'bob@test-aegis.local');
      }
    });

    it('employee CANNOT access Admin Dashboard endpoints (403)', async () => {
      const resMetrics = await fetch(`${BASE_URL}/api/admin/metrics`, {
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(resMetrics.status, 403, 'Employee must be rejected from /api/admin/metrics');

      const resIncidents = await fetch(`${BASE_URL}/api/admin/incidents`, {
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(resIncidents.status, 403, 'Employee must be rejected from /api/admin/incidents');
    });
  });

  // ─── 5. Admin Security Dashboard & Multi-Tenant Isolation ────────────────

  describe('5. Admin Security Dashboard & Multi-Tenant Isolation', () => {
    it('admin retrieves metrics scoped to their organization with trends and breakdown', async () => {
      const res = await fetch(`${BASE_URL}/api/admin/metrics`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.summary.totalIncidents >= 1);
      assert.ok(data.summary.criticalCount >= 1);
      assert.ok(data.summary.employeesCount >= 1);
      assert.ok(data.severityData.length > 0);
      assert.ok(data.actionData.length > 0);
      assert.ok(Array.isArray(data.incidentTrends));
      assert.ok(Array.isArray(data.employeeBreakdown));
      assert.ok(typeof data.summary.enrolledUsersCount === 'number');
    });

    it('admin in Org 1 CANNOT see Org 2 incidents (Multi-Tenant Isolation)', async () => {
      const res = await fetch(`${BASE_URL}/api/admin/incidents`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      // Must not contain Bob's incident (which is in Org 2)
      for (const inc of data.incidents) {
        assert.notEqual(inc.employeeEmail, 'bob@test-aegis.local');
      }
    });

    it('admin retrieves enriched employee directory with incident counts and status', async () => {
      const res = await fetch(`${BASE_URL}/api/admin/employees`, {
        headers: { 'Authorization': `Bearer ${adminToken}` }
      });
      assert.equal(res.status, 200);
      const employees = await res.json();
      assert.ok(Array.isArray(employees));
      assert.ok(employees.length >= 1);

      // Must be scoped to Org 1 only
      for (const emp of employees) {
        assert.notEqual(emp.email, 'bob@test-aegis.local', 'Org 2 employee Bob must not appear in Org 1 directory');
      }

      const eve = employees.find(e => e.email === 'eve@test-aegis.local');
      assert.ok(eve, 'Eve must be in employee directory');
      assert.ok(eve.totalIncidents >= 1, 'Eve must have incident count recorded');
      assert.equal(eve.extensionStatus, 'Enrolled', 'Eve must have enrolled status');
    });

    it('verifies extension status endpoint tracks enrollment correctly', async () => {
      const res = await fetch(`${BASE_URL}/api/extension/status`, {
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'online');
      assert.equal(data.authenticated, true);
      assert.equal(data.user.extensionEnrolled, true);
    });

    it('verifies employee reports summary contains accurate aggregates', async () => {
      const res = await fetch(`${BASE_URL}/api/reports/employee`, {
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.summary);
      assert.ok(data.summary.total >= 1);
      assert.ok(data.summary.critical >= 1);
      assert.ok(data.summary.blocked >= 1);
      assert.equal(data.extensionEnrolled, true);
    });
  });

  // ─── 6. Company Data DNA Management & ReDoS Defense ──────────────────────

  describe('6. Company Data DNA Policies & ReDoS Defense', () => {
    it('employee CANNOT create company rules (403)', async () => {
      const res = await fetch(`${BASE_URL}/api/policies/rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${employeeToken}`
        },
        body: JSON.stringify({
          id: 'TEST-CDR-001',
          name: 'Unauthorized Rule',
          patternType: 'exact',
          pattern: 'CONFIDENTIAL',
          severity: 'HIGH',
          action: 'block'
        })
      });
      assert.equal(res.status, 403);
    });

    it('admin creates valid exact marker rule and logs audit entry', async () => {
      const res = await fetch(`${BASE_URL}/api/policies/rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          id: 'TEST-CDR-001',
          name: 'Project Falcon Codename',
          description: 'Guards project falcon internal codeword',
          patternType: 'exact',
          pattern: 'PROJECT-FALCON-7Q',
          severity: 'CRITICAL',
          action: 'block',
          enabled: true
        })
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.id, 'TEST-CDR-001');
      assert.equal(data.version, 1);
    });

    it('REJECTS regex pattern vulnerable to catastrophic backtracking (ReDoS Protection)', async () => {
      const res = await fetch(`${BASE_URL}/api/policies/rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          id: 'TEST-CDR-REDOS',
          name: 'Malicious ReDoS Rule',
          patternType: 'regex',
          pattern: '(a+)+$', // Catastrophic backtracking pattern
          severity: 'HIGH',
          action: 'block'
        })
      });

      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /catastrophic backtracking/i);
    });

    it('admin can test pattern against synthetic text safely', async () => {
      const res = await fetch(`${BASE_URL}/api/policies/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`
        },
        body: JSON.stringify({
          patternType: 'exact',
          pattern: 'PROJECT-FALCON-7Q',
          sampleText: 'Reviewing Q3 roadmap for PROJECT-FALCON-7Q codename.'
        })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.valid, true);
      assert.equal(data.matched, true);
      assert.equal(data.matchCount, 1);
      // Ensure match is masked
      assert.match(data.matchesMasked[0], /\*/);
    });

    it('extension can sync organization company rules', async () => {
      const res = await fetch(`${BASE_URL}/api/extension/rules`, {
        headers: { 'Authorization': `Bearer ${employeeToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.rules));
      assert.ok(data.rules.some(r => r.id === 'TEST-CDR-001'));
    });
  });
});
