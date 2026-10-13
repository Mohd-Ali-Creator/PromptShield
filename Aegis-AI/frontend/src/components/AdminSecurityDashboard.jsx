import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Activity,
  Search,
  RefreshCw,
  Plus,
  Trash2,
  Lock,
  FileText,
  Sliders,
  ChevronRight,
  ChevronLeft,
  X,
  Play,
  History,
  Users,
  Calendar,
  Layers,
  Filter,
  Eye
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis
} from 'recharts';

export default function AdminSecurityDashboard({ token, user, socket }) {
  const [activeSubTab, setActiveSubTab] = useState('telemetry'); // 'telemetry' | 'employees' | 'dna_policies' | 'audit_trail'
  const [metrics, setMetrics] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [employees, setEmployees] = useState([]);
  const [rules, setRules] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Pagination
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalIncidentsCount, setTotalIncidentsCount] = useState(0);

  // Multi-facet Filters
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [employeeFilter, setEmployeeFilter] = useState('ALL');
  const [ruleFilter, setRuleFilter] = useState('ALL');
  const [platformFilter, setPlatformFilter] = useState('ALL');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [search, setSearch] = useState('');

  // Modals & Forms
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newRule, setNewRule] = useState({
    id: '',
    name: '',
    description: '',
    patternType: 'exact',
    pattern: '',
    severity: 'CRITICAL',
    action: 'block',
    enabled: true
  });
  const [ruleFormError, setRuleFormError] = useState('');

  // Pattern Tester
  const [testSample, setTestSample] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testingPattern, setTestingPattern] = useState(false);

  const fetchAllData = async (targetPage = page) => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [metricsRes, incRes, empRes, rulesRes, auditRes] = await Promise.all([
        axios.get('http://localhost:4000/api/admin/metrics', { headers }),
        axios.get('http://localhost:4000/api/admin/incidents', {
          headers,
          params: {
            severity: severityFilter,
            action: actionFilter,
            employeeId: employeeFilter,
            ruleId: ruleFilter,
            sourcePlatform: platformFilter,
            startDate: startDate || undefined,
            endDate: endDate || undefined,
            search: search.trim() || undefined,
            page: targetPage,
            limit: 15
          }
        }),
        axios.get('http://localhost:4000/api/admin/employees', { headers }),
        axios.get('http://localhost:4000/api/policies/rules', { headers }),
        axios.get('http://localhost:4000/api/admin/audit-logs', { headers })
      ]);

      setMetrics(metricsRes.data);
      setIncidents(incRes.data.incidents || []);
      setTotalIncidentsCount(incRes.data.total || 0);
      setPage(incRes.data.page || 1);
      setTotalPages(incRes.data.totalPages || 1);
      setEmployees(empRes.data || []);
      setRules(rulesRes.data || []);
      setAuditLogs(auditRes.data || []);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch admin security dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData(1);
  }, [token, severityFilter, actionFilter, employeeFilter, ruleFilter, platformFilter, startDate, endDate]);

  // Real-time live updates from Socket.IO
  useEffect(() => {
    if (!socket) return;
    const handleNewIncident = () => {
      fetchAllData(page);
    };
    socket.on('promptshield_incident', handleNewIncident);
    return () => socket.off('promptshield_incident', handleNewIncident);
  }, [socket, page]);

  // Create Rule Handler
  const handleCreateRule = async (e) => {
    e.preventDefault();
    setRuleFormError('');
    try {
      await axios.post('http://localhost:4000/api/policies/rules', newRule, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setShowCreateModal(false);
      setNewRule({
        id: '',
        name: '',
        description: '',
        patternType: 'exact',
        pattern: '',
        severity: 'CRITICAL',
        action: 'block',
        enabled: true
      });
      fetchAllData(page);
    } catch (err) {
      setRuleFormError(err.response?.data?.error || 'Failed to create rule.');
    }
  };

  // Delete Rule Handler
  const handleDeleteRule = async (ruleId) => {
    if (!confirm(`Are you sure you want to permanently delete rule "${ruleId}"?`)) return;
    try {
      await axios.delete(`http://localhost:4000/api/policies/rules/${ruleId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchAllData(page);
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to delete rule.');
    }
  };

  // Toggle Rule Status
  const handleToggleRule = async (rule) => {
    try {
      await axios.put(
        `http://localhost:4000/api/policies/rules/${rule.id}`,
        { enabled: !rule.enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      fetchAllData(page);
    } catch (err) {
      alert('Failed to toggle rule state.');
    }
  };

  // Test Pattern Sandbox
  const handleRunPatternTest = async () => {
    if (!newRule.pattern || !testSample) return;
    setTestingPattern(true);
    setTestResult(null);
    try {
      const res = await axios.post(
        'http://localhost:4000/api/policies/test',
        {
          patternType: newRule.patternType,
          pattern: newRule.pattern,
          sampleText: testSample
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setTestResult(res.data);
    } catch (err) {
      setTestResult({ valid: false, error: err.response?.data?.error || 'Validation failed' });
    } finally {
      setTestingPattern(false);
    }
  };

  // Switch to incident view filtered by employee
  const handleInspectEmployeeIncidents = (empId) => {
    setEmployeeFilter(empId);
    setActiveSubTab('telemetry');
  };

  if (!token || user?.role !== 'admin') {
    return (
      <div className="flex-1 p-6 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full flex items-center justify-center">
        <div className="bg-white neo-border neo-shadow rounded-2xl p-8 max-w-md text-center">
          <div className="bg-red-100 w-16 h-16 rounded-full neo-border flex items-center justify-center mx-auto mb-4">
            <Lock className="w-8 h-8 text-red-700" />
          </div>
          <h2 className="font-heading font-black text-2xl mb-2">Admin Authorization Required</h2>
          <p className="text-black/60 font-medium text-sm">
            This dashboard is restricted to authorized organization security administrators.
          </p>
        </div>
      </div>
    );
  }

  const s = metrics?.summary || {};

  return (
    <div className="flex-1 p-4 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="font-heading font-black text-3xl md:text-4xl mb-2 flex flex-wrap items-center gap-3">
            Admin Security Dashboard
            <span className="text-xs font-mono font-bold uppercase bg-purple-200 text-purple-900 px-3 py-1 rounded-full neo-border">
              {user?.organizationName || 'Enterprise'} Security Center
            </span>
          </h2>
          <p className="text-black/60 text-sm font-medium">
            Organization-wide telemetry, client-side policy management, employee tracking, and compliance audit logs.
          </p>
        </div>

        {/* Sub-Tabs Navigation */}
        <div className="flex items-center gap-1.5 bg-white neo-border p-1.5 rounded-2xl flex-wrap">
          {[
            { id: 'telemetry', label: 'Incidents & Analytics' },
            { id: 'employees', label: 'Employee Directory' },
            { id: 'dna_policies', label: 'Company Data DNA' },
            { id: 'audit_trail', label: 'Audit Trail' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              className={`px-3 py-1.5 rounded-xl font-bold text-xs transition-colors ${
                activeSubTab === tab.id ? 'bg-black text-white neo-border' : 'hover:bg-slate-100 text-black/70'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="mb-6 bg-red-100 text-red-800 p-4 rounded-xl neo-border font-bold text-sm">
          {error}
        </div>
      )}

      {/* ─── SUMMARY CARDS GRID (10 CARDS) ─────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-2.5 mb-8">
        {[
          { label: 'Employees', val: s.employeesCount || 0, bg: 'bg-white', text: 'text-black' },
          { label: 'Enrolled Ext.', val: s.enrolledUsersCount || 0, bg: 'bg-emerald-50', text: 'text-emerald-800' },
          { label: 'Incidents', val: s.totalIncidents || 0, bg: 'bg-white', text: 'text-black' },
          { label: 'Critical', val: s.criticalCount || 0, bg: 'bg-red-50', text: 'text-red-700' },
          { label: 'High', val: s.highCount || 0, bg: 'bg-amber-50', text: 'text-amber-700' },
          { label: 'Medium', val: s.mediumCount || 0, bg: 'bg-yellow-50', text: 'text-yellow-700' },
          { label: 'Blocked', val: s.blockedCount || 0, bg: 'bg-red-100', text: 'text-red-800' },
          { label: 'Warned', val: s.warnedCount || 0, bg: 'bg-amber-100', text: 'text-amber-800' },
          { label: 'Redacted', val: s.redactedCount || 0, bg: 'bg-blue-100', text: 'text-blue-800' },
          { label: 'Allowed', val: s.allowedCount || 0, bg: 'bg-emerald-100', text: 'text-emerald-800' }
        ].map((item, idx) => (
          <div key={idx} className={`${item.bg} neo-border neo-shadow-sm rounded-xl p-3 flex flex-col justify-between`}>
            <div className="text-[9px] font-black uppercase tracking-wider text-black/50 mb-1 leading-tight">{item.label}</div>
            <div className={`text-2xl font-black font-heading ${item.text}`}>{item.val}</div>
          </div>
        ))}
      </div>

      {/* ─── SUB-TAB 1: INCIDENTS & ANALYTICS ─────────────────────────────────── */}
      {activeSubTab === 'telemetry' && (
        <>
          {/* Analytics Charts Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            {/* Chart 1: Threat Severity Distribution */}
            <div className="bg-white neo-border neo-shadow rounded-2xl p-5 flex flex-col min-h-[300px]">
              <h3 className="font-heading font-bold text-base mb-3">Threat Severity Distribution</h3>
              <div className="flex-1 min-h-0">
                {metrics?.severityData && metrics.severityData.some((d) => d.value > 0) ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={metrics.severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={90}
                        paddingAngle={5}
                        dataKey="value"
                        stroke="#000"
                        strokeWidth={2}
                      >
                        {metrics.severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: '#fff',
                          border: '2px solid #000',
                          borderRadius: '12px',
                          boxShadow: '4px 4px 0 0 #000',
                          fontWeight: 'bold'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center font-bold text-black/40 text-xs">
                    No threat events recorded yet.
                  </div>
                )}
              </div>
            </div>

            {/* Chart 2: Interception Action Outcomes */}
            <div className="bg-white neo-border neo-shadow rounded-2xl p-5 flex flex-col min-h-[300px]">
              <h3 className="font-heading font-bold text-base mb-3">Action Outcomes Distribution</h3>
              <div className="flex-1 min-h-0">
                {metrics?.actionData && metrics.actionData.some((d) => d.value > 0) ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={metrics.actionData}>
                      <XAxis dataKey="name" stroke="#000" fontSize={11} tickLine={false} axisLine={{ strokeWidth: 2 }} />
                      <YAxis stroke="#000" fontSize={11} tickLine={false} axisLine={{ strokeWidth: 2 }} />
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: '#fff',
                          border: '2px solid #000',
                          borderRadius: '12px',
                          boxShadow: '4px 4px 0 0 #000',
                          fontWeight: 'bold'
                        }}
                      />
                      <Bar dataKey="value" fill="#818cf8" radius={[6, 6, 0, 0]} stroke="#000" strokeWidth={2}>
                        {metrics.actionData.map((entry, index) => (
                          <Cell key={`bar-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center font-bold text-black/40 text-xs">
                    No action outcomes recorded yet.
                  </div>
                )}
              </div>
            </div>

            {/* Chart 3: Incident Trends Over Time */}
            <div className="bg-white neo-border neo-shadow rounded-2xl p-5 flex flex-col min-h-[300px]">
              <h3 className="font-heading font-bold text-base mb-3">Incident Trends Over Time</h3>
              <div className="flex-1 min-h-0">
                {metrics?.incidentTrends && metrics.incidentTrends.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={metrics.incidentTrends}>
                      <XAxis dataKey="date" stroke="#000" fontSize={10} tickLine={false} axisLine={{ strokeWidth: 2 }} />
                      <YAxis stroke="#000" fontSize={11} tickLine={false} axisLine={{ strokeWidth: 2 }} />
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: '#fff',
                          border: '2px solid #000',
                          borderRadius: '12px',
                          boxShadow: '4px 4px 0 0 #000',
                          fontWeight: 'bold'
                        }}
                      />
                      <Bar dataKey="total" fill="#3b82f6" name="Total Incidents" radius={[4, 4, 0, 0]} stroke="#000" strokeWidth={1.5} />
                      <Bar dataKey="blocked" fill="#ef4444" name="Blocked Submissions" radius={[4, 4, 0, 0]} stroke="#000" strokeWidth={1.5} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center font-bold text-black/40 text-xs">
                    No temporal trends available.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Secondary Analytics: Top Rules & Employee Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {/* Top Triggered Rules */}
            <div className="bg-white neo-border neo-shadow rounded-2xl p-5">
              <h3 className="font-heading font-bold text-base mb-3 flex items-center justify-between">
                <span>Frequently Triggered Rules</span>
                <span className="text-[10px] font-mono text-black/50">TOP {metrics?.topRules?.length || 0}</span>
              </h3>
              {metrics?.topRules && metrics.topRules.length > 0 ? (
                <div className="space-y-2">
                  {metrics.topRules.map((r, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 bg-slate-50 neo-border rounded-xl">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-black text-xs text-purple-800">#{i + 1}</span>
                        <div>
                          <div className="font-bold text-xs">{r.ruleName || r.ruleId}</div>
                          <div className="font-mono text-[10px] text-black/50">{r.ruleId}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-black px-2 py-0.5 rounded neo-border ${
                            r.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          {r.severity}
                        </span>
                        <span className="font-mono font-black text-xs bg-white px-2 py-1 rounded neo-border">
                          {r.count} hits
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 font-bold text-black/40 text-xs">
                  No rule triggers recorded.
                </div>
              )}
            </div>

            {/* Employee-Wise Incident Breakdown */}
            <div className="bg-white neo-border neo-shadow rounded-2xl p-5">
              <h3 className="font-heading font-bold text-base mb-3 flex items-center justify-between">
                <span>Employee-Wise Incident Breakdown</span>
                <span className="text-[10px] font-mono text-black/50">TOP RISKS</span>
              </h3>
              {metrics?.employeeBreakdown && metrics.employeeBreakdown.length > 0 ? (
                <div className="space-y-2">
                  {metrics.employeeBreakdown.map((emp, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 bg-slate-50 neo-border rounded-xl">
                      <div>
                        <div className="font-bold text-xs">{emp.employeeName}</div>
                        <div className="text-[10px] text-black/50">{emp.employeeEmail}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-bold text-red-700 bg-red-50 px-2 py-0.5 rounded neo-border">
                          {emp.critical + emp.high} Crit/High
                        </span>
                        <span className="font-mono font-black text-xs bg-white px-2.5 py-1 rounded neo-border">
                          {emp.total} total
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 font-bold text-black/40 text-xs">
                  No employee incidents recorded.
                </div>
              )}
            </div>
          </div>

          {/* Incident Filter & Search Bar */}
          <div className="bg-white neo-border neo-shadow-sm rounded-2xl p-4 mb-6 flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[300px]">
              {/* Search text */}
              <div className="flex items-center bg-slate-50 neo-border rounded-xl px-3 py-1.5 flex-1 min-w-[180px]">
                <Search className="w-4 h-4 text-black/40 mr-2 shrink-0" />
                <input
                  type="text"
                  placeholder="Search rule, employee, email..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && fetchAllData(1)}
                  className="bg-transparent border-none outline-none text-xs font-bold w-full"
                />
              </div>

              {/* Employee Filter */}
              <select
                value={employeeFilter}
                onChange={(e) => setEmployeeFilter(e.target.value)}
                className="bg-slate-50 neo-border rounded-xl px-2.5 py-1.5 text-xs font-bold outline-none cursor-pointer"
              >
                <option value="ALL">All Employees</option>
                {employees.map((emp) => (
                  <option key={emp._id} value={emp._id}>
                    {emp.name}
                  </option>
                ))}
              </select>

              {/* Severity Filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-50 neo-border rounded-xl px-2.5 py-1.5 text-xs font-bold outline-none cursor-pointer"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              {/* Action Filter */}
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="bg-slate-50 neo-border rounded-xl px-2.5 py-1.5 text-xs font-bold outline-none cursor-pointer"
              >
                <option value="ALL">All Actions</option>
                <option value="BLOCKED">Blocked</option>
                <option value="WARNED">Warned</option>
                <option value="REDACTED">Redacted</option>
                <option value="ALLOWED">Allowed</option>
              </select>

              {/* Platform Filter */}
              <select
                value={platformFilter}
                onChange={(e) => setPlatformFilter(e.target.value)}
                className="bg-slate-50 neo-border rounded-xl px-2.5 py-1.5 text-xs font-bold outline-none cursor-pointer"
              >
                <option value="ALL">All Platforms</option>
                <option value="chatgpt">ChatGPT</option>
                <option value="claude">Claude</option>
              </select>

              {/* Date Range */}
              <div className="flex items-center gap-1.5">
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="bg-slate-50 neo-border rounded-xl px-2 py-1 text-[11px] font-bold outline-none"
                  title="Start Date"
                />
                <span className="text-black/40 text-xs font-bold">to</span>
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="bg-slate-50 neo-border rounded-xl px-2 py-1 text-[11px] font-bold outline-none"
                  title="End Date"
                />
              </div>

              {employeeFilter !== 'ALL' && (
                <button
                  onClick={() => setEmployeeFilter('ALL')}
                  className="bg-red-50 text-red-700 font-bold text-xs px-2.5 py-1 rounded-lg neo-border"
                >
                  Clear Employee Filter ✕
                </button>
              )}
            </div>

            <div className="text-xs font-bold text-black/60">
              Total <strong>{totalIncidentsCount}</strong> incident(s)
            </div>
          </div>

          {/* Incidents Table */}
          <div className="bg-white neo-border neo-shadow rounded-2xl overflow-hidden mb-8">
            <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[800px]">
                <thead className="bg-slate-100 border-b-2 border-black">
                  <tr>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Time</th>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Employee</th>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">AI Platform</th>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Severity</th>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Action</th>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Rule Triggered</th>
                    <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y-2 divide-black/10">
                  {loading ? (
                    <tr>
                      <td colSpan="7" className="p-12 text-center font-bold text-black/40">
                        <div className="flex items-center justify-center gap-2">
                          <RefreshCw className="w-4 h-4 animate-spin" /> Loading incidents...
                        </div>
                      </td>
                    </tr>
                  ) : incidents.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="p-12 text-center font-bold text-black/40">
                        No matching organization incidents found.
                      </td>
                    </tr>
                  ) : (
                    incidents.map((inc) => (
                      <tr key={inc._id || inc.eventId} className="hover:bg-slate-50 transition-colors">
                        <td className="p-4 font-mono text-xs font-bold">
                          {new Date(inc.occurredAt).toLocaleString([], {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </td>
                        <td className="p-4">
                          <div className="font-bold text-xs">{inc.employeeName}</div>
                          <div className="text-[10px] text-black/50">{inc.employeeEmail}</div>
                        </td>
                        <td className="p-4">
                          <span className="font-bold text-xs uppercase bg-slate-100 border border-black/20 px-2 py-1 rounded-md">
                            {inc.sourcePlatform || 'ChatGPT'}
                          </span>
                        </td>
                        <td className="p-4">
                          <span
                            className={`px-2.5 py-1 rounded-full text-xs font-black neo-border ${
                              inc.severity === 'CRITICAL'
                                ? 'bg-red-100 text-red-800'
                                : inc.severity === 'HIGH'
                                ? 'bg-amber-100 text-amber-800'
                                : inc.severity === 'MEDIUM'
                                ? 'bg-yellow-100 text-yellow-800'
                                : 'bg-emerald-100 text-emerald-800'
                            }`}
                          >
                            {inc.severity}
                          </span>
                        </td>
                        <td className="p-4 font-black text-xs">
                          {inc.action === 'BLOCKED' && <span className="text-red-600">BLOCKED</span>}
                          {inc.action === 'WARNED' && <span className="text-amber-600">WARNED</span>}
                          {inc.action === 'REDACTED' && <span className="text-blue-600">REDACTED</span>}
                          {inc.action === 'ALLOWED' && <span className="text-emerald-600">ALLOWED</span>}
                        </td>
                        <td className="p-4">
                          <div className="font-bold text-xs text-slate-900">{inc.ruleName || inc.ruleId}</div>
                          <div className="font-mono text-[10px] text-black/50">{inc.ruleId}</div>
                        </td>
                        <td className="p-4 text-right">
                          <button
                            onClick={() => setSelectedIncident(inc)}
                            className="bg-white neo-border p-2 rounded-full neo-hover neo-shadow-sm inline-flex items-center justify-center"
                            title="Inspect Sanitized Incident"
                          >
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="bg-slate-50 border-t-2 border-black p-3.5 flex items-center justify-between">
                <button
                  disabled={page <= 1}
                  onClick={() => fetchAllData(page - 1)}
                  className={`flex items-center gap-1 font-bold text-xs px-3 py-1.5 rounded-lg neo-border ${
                    page <= 1 ? 'opacity-40 cursor-not-allowed bg-slate-200' : 'bg-white neo-hover'
                  }`}
                >
                  <ChevronLeft className="w-3.5 h-3.5" /> Previous
                </button>

                <span className="text-xs font-bold text-black/60">
                  Page <strong>{page}</strong> of <strong>{totalPages}</strong>
                </span>

                <button
                  disabled={page >= totalPages}
                  onClick={() => fetchAllData(page + 1)}
                  className={`flex items-center gap-1 font-bold text-xs px-3 py-1.5 rounded-lg neo-border ${
                    page >= totalPages ? 'opacity-40 cursor-not-allowed bg-slate-200' : 'bg-white neo-hover'
                  }`}
                >
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {/* ─── SUB-TAB 2: EMPLOYEE DIRECTORY & ENROLLMENT ─────────────────────── */}
      {activeSubTab === 'employees' && (
        <div className="bg-white neo-border neo-shadow rounded-2xl overflow-hidden mb-8">
          <div className="p-5 border-b-2 border-black bg-slate-50 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="font-heading font-black text-xl">Organization Employee Directory</h3>
              <p className="text-xs text-black/60 font-medium">
                Real database-backed employee enrollment and telemetry status.
              </p>
            </div>
            <div className="font-bold text-xs text-black/60">
              Total <strong>{employees.length}</strong> Registered Employee(s)
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left min-w-[750px]">
              <thead className="bg-slate-100 border-b-2 border-black">
                <tr>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Employee</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Work Email</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Role</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Extension Status</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Total Incidents</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Crit / High Threats</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Last Incident</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y-2 divide-black/10">
                {employees.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="p-8 text-center font-bold text-black/40">
                      No employees found in organization.
                    </td>
                  </tr>
                ) : (
                  employees.map((emp) => (
                    <tr key={emp._id} className="hover:bg-slate-50 transition-colors">
                      <td className="p-4 font-bold text-xs">{emp.name}</td>
                      <td className="p-4 font-mono text-xs text-black/70">{emp.email}</td>
                      <td className="p-4">
                        <span className="text-[10px] font-mono font-bold uppercase bg-slate-100 border border-black/20 px-2 py-0.5 rounded">
                          {emp.role}
                        </span>
                      </td>
                      <td className="p-4">
                        <span
                          className={`text-[10px] font-bold px-2.5 py-1 rounded-full neo-border flex items-center gap-1.5 w-max ${
                            emp.extensionStatus === 'Enrolled'
                              ? 'bg-emerald-100 text-emerald-800'
                              : 'bg-amber-100 text-amber-800'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              emp.extensionStatus === 'Enrolled' ? 'bg-emerald-600 animate-pulse' : 'bg-amber-600'
                            }`}
                          />
                          {emp.extensionStatus}
                        </span>
                      </td>
                      <td className="p-4 font-mono font-black text-xs">{emp.totalIncidents}</td>
                      <td className="p-4 font-mono font-bold text-xs text-red-700">{emp.criticalHighCount}</td>
                      <td className="p-4 font-mono text-xs text-black/60">
                        {emp.lastIncidentAt
                          ? new Date(emp.lastIncidentAt).toLocaleString([], {
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit'
                            })
                          : 'None'}
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => handleInspectEmployeeIncidents(emp._id)}
                          className="bg-black text-white px-3 py-1.5 rounded-xl font-bold text-xs neo-hover inline-flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" /> Filter Incidents
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ─── SUB-TAB 3: COMPANY DATA DNA MANAGEMENT ─────────────────────────── */}
      {activeSubTab === 'dna_policies' && (
        <>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="font-heading font-black text-2xl">Company Confidential Data DNA</h3>
              <p className="text-xs text-black/60 font-medium">
                Admin-configured exact markers and ReDoS-screened regex patterns pushed to employee extensions.
              </p>
            </div>

            <button
              onClick={() => setShowCreateModal(true)}
              className="bg-black text-white px-4 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 neo-hover"
            >
              <Plus className="w-4 h-4" /> Create Company Rule
            </button>
          </div>

          <div className="bg-white neo-border neo-shadow rounded-2xl overflow-x-auto mb-8">
            <table className="w-full text-left min-w-[750px]">
              <thead className="bg-slate-100 border-b-2 border-black">
                <tr>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Rule ID</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Rule Name</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Type</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Pattern</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Severity</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Action</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Status</th>
                  <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y-2 divide-black/10">
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="p-8 text-center font-bold text-black/40">
                      No custom company rules configured yet. Click "Create Company Rule" above to define your first pattern.
                    </td>
                  </tr>
                ) : (
                  rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-50 transition-colors">
                      <td className="p-4 font-mono font-bold text-xs">{rule.id}</td>
                      <td className="p-4">
                        <div className="font-bold text-xs">{rule.name}</div>
                        <div className="text-[10px] text-black/50 truncate max-w-xs">{rule.description}</div>
                      </td>
                      <td className="p-4">
                        <span className="font-mono text-[10px] font-bold uppercase bg-slate-100 border border-black/20 px-2 py-0.5 rounded">
                          {rule.patternType}
                        </span>
                      </td>
                      <td className="p-4 font-mono text-xs max-w-xs truncate">{rule.pattern}</td>
                      <td className="p-4">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-black neo-border ${
                            rule.severity === 'CRITICAL'
                              ? 'bg-red-100 text-red-800'
                              : rule.severity === 'HIGH'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-yellow-100 text-yellow-800'
                          }`}
                        >
                          {rule.severity}
                        </span>
                      </td>
                      <td className="p-4 font-black text-xs uppercase">{rule.action}</td>
                      <td className="p-4">
                        <button
                          onClick={() => handleToggleRule(rule)}
                          className={`text-xs font-bold px-2.5 py-1 rounded-full neo-border ${
                            rule.enabled ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-black/50'
                          }`}
                        >
                          {rule.enabled ? 'Active' : 'Disabled'}
                        </button>
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="bg-red-50 text-red-700 neo-border p-2 rounded-xl neo-hover"
                          title="Delete Rule"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ─── SUB-TAB 4: ADMINISTRATIVE AUDIT TRAIL ─────────────────────────── */}
      {activeSubTab === 'audit_trail' && (
        <div className="bg-white neo-border neo-shadow rounded-2xl overflow-x-auto mb-8">
          <table className="w-full text-left min-w-[700px]">
            <thead className="bg-slate-100 border-b-2 border-black">
              <tr>
                <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Time</th>
                <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Administrator</th>
                <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Action</th>
                <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Rule Target</th>
                <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Change Details</th>
              </tr>
            </thead>
            <tbody className="divide-y-2 divide-black/10">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan="5" className="p-8 text-center font-bold text-black/40">
                    No policy modifications recorded yet.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log) => (
                  <tr key={log._id} className="hover:bg-slate-50 transition-colors">
                    <td className="p-4 font-mono text-xs font-bold">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="p-4 text-xs font-bold">{log.actorEmail}</td>
                    <td className="p-4 font-mono text-xs font-bold uppercase text-purple-700">{log.actionType}</td>
                    <td className="p-4 font-mono text-xs">{log.ruleId}</td>
                    <td className="p-4 text-xs text-black/70 font-medium">{log.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ─── CREATE RULE MODAL WITH LIVE PATTERN TESTER ─────────────────────── */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-white neo-border neo-shadow rounded-[24px] p-6 md:p-8 w-full max-w-2xl relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setShowCreateModal(false)}
              className="absolute top-5 right-5 text-black/50 hover:text-black font-black text-xl"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="font-heading font-black text-2xl mb-1">Create Company Data DNA Rule</h3>
            <p className="text-xs text-black/60 font-medium mb-6">
              Define sensitive tokens or regex patterns to be blocked or warned locally before AI model submission.
            </p>

            {ruleFormError && (
              <div className="bg-red-100 text-red-800 p-3 rounded-xl neo-border font-bold text-xs mb-4">
                {ruleFormError}
              </div>
            )}

            <form onSubmit={handleCreateRule} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Rule ID</label>
                  <input
                    type="text"
                    required
                    placeholder="CDR-005"
                    value={newRule.id}
                    onChange={(e) => setNewRule({ ...newRule, id: e.target.value })}
                    className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-mono font-bold outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Rule Name</label>
                  <input
                    type="text"
                    required
                    placeholder="Project Chimera Codename"
                    value={newRule.name}
                    onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                    className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-bold outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Description</label>
                <input
                  type="text"
                  placeholder="Guards confidential Q4 initiative codename."
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-medium outline-none"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Pattern Type</label>
                  <select
                    value={newRule.patternType}
                    onChange={(e) => setNewRule({ ...newRule, patternType: e.target.value })}
                    className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-bold outline-none"
                  >
                    <option value="exact">Exact Marker (Literal)</option>
                    <option value="regex">Regular Expression</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
                    className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-bold outline-none"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Action</label>
                  <select
                    value={newRule.action}
                    onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}
                    className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-bold outline-none"
                  >
                    <option value="block">Block Prompt</option>
                    <option value="warn">Warn User</option>
                    <option value="redact">Redact Match</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-black tracking-widest text-black/60 mb-1.5 uppercase">Pattern String</label>
                <input
                  type="text"
                  required
                  placeholder={newRule.patternType === 'exact' ? 'PROJECT-CHIMERA-99' : 'CHIMERA-[A-Z0-9]{6}'}
                  value={newRule.pattern}
                  onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                  className="w-full bg-slate-50 neo-border rounded-xl px-3 py-2 text-xs font-mono font-bold outline-none"
                />
              </div>

              {/* Pattern Testing Sandbox Card */}
              <div className="bg-slate-50 neo-border rounded-xl p-4 mt-2">
                <span className="text-[10px] font-black uppercase text-black/60 block mb-2">Live Pattern Testing Sandbox</span>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    placeholder="Type synthetic text to test pattern against..."
                    value={testSample}
                    onChange={(e) => setTestSample(e.target.value)}
                    className="flex-1 bg-white neo-border rounded-lg px-3 py-1.5 text-xs font-medium outline-none"
                  />
                  <button
                    type="button"
                    onClick={handleRunPatternTest}
                    className="bg-black text-white px-3 py-1.5 rounded-lg font-bold text-xs flex items-center gap-1 neo-hover"
                  >
                    <Play className="w-3 h-3" /> Test
                  </button>
                </div>

                {testResult && (
                  <div
                    className={`p-2.5 rounded-lg text-xs font-bold neo-border ${
                      testResult.valid
                        ? testResult.matched
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-200 text-slate-700'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {testResult.valid ? (
                      testResult.matched ? (
                        <>✓ Matched {testResult.matchCount} occurrence(s). Masked match: {testResult.matchesMasked?.join(', ')}</>
                      ) : (
                        'No matches found in sample text.'
                      )
                    ) : (
                      <>✗ Validation Error: {testResult.error}</>
                    )}
                  </div>
                )}
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="bg-white neo-border px-4 py-2 rounded-xl font-bold text-xs neo-hover"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-black text-white px-5 py-2.5 rounded-xl font-bold text-xs neo-hover"
                >
                  Save & Publish Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ─── SANITIZED INCIDENT DETAIL INSPECTOR MODAL ───────────────────────── */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-white neo-border neo-shadow rounded-[24px] p-6 md:p-8 w-full max-w-lg relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setSelectedIncident(null)}
              className="absolute top-5 right-5 text-black/50 hover:text-black font-black text-xl"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-6 pb-4 border-b border-black/10">
              <div
                className={`p-3 rounded-xl neo-border ${
                  selectedIncident.severity === 'CRITICAL' || selectedIncident.severity === 'HIGH'
                    ? 'bg-red-100 text-red-800'
                    : 'bg-amber-100 text-amber-800'
                }`}
              >
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <h3 className="font-heading font-black text-xl">{selectedIncident.ruleName || selectedIncident.ruleId}</h3>
                <div className="font-mono text-xs text-black/50">Audit ID: {selectedIncident.eventId}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Employee:</span>
                <span className="font-bold text-xs">{selectedIncident.employeeName}</span>
                <span className="text-[10px] text-black/50 block">{selectedIncident.employeeEmail}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Time:</span>
                <span className="font-bold text-xs">{new Date(selectedIncident.occurredAt).toLocaleString()}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Severity:</span>
                <span className="font-black text-xs">{selectedIncident.severity}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Action Enforced:</span>
                <span className="font-black text-xs text-red-600">[{selectedIncident.action}]</span>
              </div>
            </div>

            <div className="bg-slate-50 p-4 rounded-xl neo-border mb-6">
              <span className="text-[10px] font-bold text-black/50 uppercase block mb-1.5">Sanitized Telemetry Metadata:</span>
              <p className="text-xs text-slate-800 font-medium leading-relaxed">
                {selectedIncident.sanitizedMetadata?.explanation ||
                  `PromptShield AI guardrail evaluated prompt on ${selectedIncident.sourcePlatform}. Rule ${selectedIncident.ruleId} was triggered and ${selectedIncident.action.toLowerCase()} prior to outbound dispatch.`}
              </p>
            </div>

            <div className="bg-emerald-50 border border-emerald-300 p-3.5 rounded-xl text-xs text-emerald-900 font-medium flex items-start gap-2.5">
              <CheckCircle className="w-4 h-4 text-emerald-700 shrink-0 mt-0.5" />
              <span>
                <strong>Privacy Preservation:</strong> Zero raw prompt content was captured. Audit records contain only anonymized indicator classifications.
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
