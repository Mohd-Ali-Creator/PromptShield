import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  Search,
  RefreshCw,
  Copy,
  Check,
  Info,
  FileText,
  ChevronRight,
  ChevronLeft,
  X,
  ExternalLink,
  Calendar,
  Sparkles,
  Terminal
} from 'lucide-react';

export default function EmployeeReports({ token, user, socket }) {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [summary, setSummary] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    blocked: 0,
    warned: 0,
    redacted: 0,
    allowed: 0
  });
  const [extensionEnrolled, setExtensionEnrolled] = useState(false);
  const [lastEnrolledAt, setLastEnrolledAt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [search, setSearch] = useState('');

  // UI state
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedSyntheticPrompt, setCopiedSyntheticPrompt] = useState(false);

  const fetchReports = async (targetPage = page) => {
    if (!token) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await axios.get('http://localhost:4000/api/reports/employee', {
        headers: { Authorization: `Bearer ${token}` },
        params: {
          severity: severityFilter,
          action: actionFilter,
          startDate: startDate || undefined,
          endDate: endDate || undefined,
          search: search.trim() || undefined,
          page: targetPage,
          limit: 10
        }
      });
      setIncidents(res.data.incidents || []);
      setTotal(res.data.total || 0);
      setPage(res.data.page || 1);
      setTotalPages(res.data.totalPages || 1);
      if (res.data.summary) {
        setSummary(res.data.summary);
      }
      setExtensionEnrolled(Boolean(res.data.extensionEnrolled));
      setLastEnrolledAt(res.data.lastEnrolledAt);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load employee security reports.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports(1);
  }, [token, severityFilter, actionFilter, startDate, endDate]);

  // Real-time live incident feed from Socket.IO
  useEffect(() => {
    if (!socket) return;
    const handleNewIncident = () => {
      fetchReports(page);
    };
    socket.on('promptshield_incident', handleNewIncident);
    return () => socket.off('promptshield_incident', handleNewIncident);
  }, [socket, page]);

  const handleCopyToken = () => {
    if (!token) return;
    navigator.clipboard.writeText(token);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const handleCopySyntheticPrompt = () => {
    const syntheticText = 'sk-proj-DEMOTESTINGSECRETKEY1234567890abcdef12345678';
    navigator.clipboard.writeText(syntheticText);
    setCopiedSyntheticPrompt(true);
    setTimeout(() => setCopiedSyntheticPrompt(false), 2000);
  };

  if (!token) {
    return (
      <div className="flex-1 p-6 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full flex items-center justify-center">
        <div className="bg-white neo-border neo-shadow rounded-2xl p-8 max-w-md text-center">
          <div className="bg-amber-100 w-16 h-16 rounded-full neo-border flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-amber-700" />
          </div>
          <h2 className="font-heading font-black text-2xl mb-2">Authentication Required</h2>
          <p className="text-black/60 font-medium text-sm mb-6">
            Please log in or create an account to view your personal PromptShield AI security incidents.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 p-4 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex flex-wrap items-center gap-3 mb-2">
            <h2 className="font-heading font-black text-3xl md:text-4xl">
              My Security Reports
            </h2>
            <span className="text-xs font-mono font-bold uppercase bg-emerald-100 text-emerald-800 px-3 py-1 rounded-full neo-border">
              PromptShield Guardrail
            </span>
            <span
              className={`text-xs font-mono font-bold uppercase px-3 py-1 rounded-full neo-border flex items-center gap-1.5 ${
                extensionEnrolled
                  ? 'bg-emerald-100 text-emerald-800'
                  : 'bg-amber-100 text-amber-800'
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  extensionEnrolled ? 'bg-emerald-600 animate-pulse' : 'bg-amber-600'
                }`}
              />
              {extensionEnrolled ? 'Extension Connected' : 'Extension Disconnected'}
            </span>
          </div>
          <p className="text-black/60 text-sm font-medium">
            Personal incident telemetry. 🔒 <strong>Zero-Knowledge:</strong> Raw prompts and credentials are never captured, transmitted, or logged.
          </p>
        </div>

        <button
          onClick={() => fetchReports(page)}
          className="bg-white neo-border neo-hover px-4 py-2 rounded-xl font-bold text-xs flex items-center gap-2 self-start md:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {error && (
        <div className="mb-6 bg-red-100 text-red-800 p-4 rounded-xl neo-border font-bold text-sm">
          {error}
        </div>
      )}

      {/* Extension Enrollment Token Banner */}
      <div className="bg-purple-50 neo-border neo-shadow-sm rounded-2xl p-5 mb-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="bg-purple-200 p-2.5 rounded-xl neo-border shrink-0 mt-0.5">
            <Shield className="w-5 h-5 text-purple-900" />
          </div>
          <div>
            <div className="font-black text-sm text-purple-950 mb-0.5">PromptShield Chrome Extension Synchronization</div>
            <p className="text-xs text-purple-900/70 font-medium leading-relaxed">
              Connect the browser extension to your account to synchronize local guardrail detections and receive organization confidential data policies.
              {lastEnrolledAt && (
                <span className="block mt-1 font-mono text-[11px] text-purple-900/60">
                  Last synchronized: {new Date(lastEnrolledAt).toLocaleString()}
                </span>
              )}
            </p>
          </div>
        </div>

        <button
          onClick={handleCopyToken}
          className="bg-black text-white px-4 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 neo-hover shrink-0 self-stretch md:self-auto justify-center"
        >
          {copiedToken ? (
            <>
              <Check className="w-4 h-4 text-emerald-400" /> Token Copied!
            </>
          ) : (
            <>
              <Copy className="w-4 h-4" /> Copy Extension Token
            </>
          )}
        </button>
      </div>

      {/* Real Summary Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 mb-8">
        {[
          { label: 'Total', count: summary.total, bg: 'bg-white', text: 'text-black' },
          { label: 'Critical', count: summary.critical, bg: 'bg-red-50', text: 'text-red-700' },
          { label: 'High', count: summary.high, bg: 'bg-amber-50', text: 'text-amber-700' },
          { label: 'Medium', count: summary.medium, bg: 'bg-yellow-50', text: 'text-yellow-700' },
          { label: 'Blocked', count: summary.blocked, bg: 'bg-red-100', text: 'text-red-800' },
          { label: 'Warned', count: summary.warned, bg: 'bg-amber-100', text: 'text-amber-800' },
          { label: 'Redacted', count: summary.redacted, bg: 'bg-blue-100', text: 'text-blue-800' },
          { label: 'Allowed', count: summary.allowed, bg: 'bg-emerald-100', text: 'text-emerald-800' }
        ].map((item, idx) => (
          <div key={idx} className={`${item.bg} neo-border neo-shadow-sm rounded-xl p-3 flex flex-col justify-between`}>
            <div className="text-[10px] font-black uppercase tracking-wider text-black/50 mb-1">{item.label}</div>
            <div className={`text-2xl font-black font-heading ${item.text}`}>{item.count}</div>
          </div>
        ))}
      </div>

      {/* Filter & Search Toolbar */}
      <div className="bg-white neo-border neo-shadow-sm rounded-2xl p-4 mb-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[280px]">
          {/* Keyword Search */}
          <div className="flex items-center bg-slate-50 neo-border rounded-xl px-3 py-2 flex-1 min-w-[180px]">
            <Search className="w-4 h-4 text-black/40 mr-2 shrink-0" />
            <input
              type="text"
              placeholder="Search by rule or platform..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchReports(1)}
              className="bg-transparent border-none outline-none text-xs font-bold w-full"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-black text-black/50 uppercase">Severity:</span>
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
          </div>

          {/* Action Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-black text-black/50 uppercase">Action:</span>
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
          </div>

          {/* Date Range Filters */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 bg-slate-50 neo-border rounded-xl px-2.5 py-1 text-xs">
              <Calendar className="w-3.5 h-3.5 text-black/40" />
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="bg-transparent border-none outline-none text-[11px] font-bold"
                title="Start Date"
              />
            </div>
            <span className="text-black/40 font-bold text-xs">to</span>
            <div className="flex items-center gap-1 bg-slate-50 neo-border rounded-xl px-2.5 py-1 text-xs">
              <Calendar className="w-3.5 h-3.5 text-black/40" />
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="bg-transparent border-none outline-none text-[11px] font-bold"
                title="End Date"
              />
            </div>
          </div>
        </div>

        <div className="text-xs font-bold text-black/60">
          Showing <strong>{incidents.length}</strong> of <strong>{total}</strong> incident(s)
        </div>
      </div>

      {/* Incidents Table / Empty State */}
      <div className="bg-white neo-border neo-shadow rounded-2xl overflow-hidden mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-left min-w-[700px]">
            <thead className="bg-slate-100 border-b-2 border-black">
              <tr>
                <th className="p-4 font-bold uppercase tracking-wider text-xs text-black/60">Time</th>
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
                  <td colSpan="6" className="p-12 text-center font-bold text-black/40">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin" /> Loading incident logs...
                    </div>
                  </td>
                </tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan="6" className="p-10">
                    <div className="max-w-xl mx-auto text-center py-4">
                      <div className="bg-purple-100 w-14 h-14 rounded-2xl neo-border flex items-center justify-center mx-auto mb-4">
                        <Sparkles className="w-7 h-7 text-purple-800" />
                      </div>
                      <h3 className="font-heading font-black text-xl text-slate-900 mb-2">
                        No Incidents Recorded Yet
                      </h3>
                      <p className="text-xs text-black/60 font-medium mb-6 leading-relaxed">
                        Your AI submissions are clean, or the PromptShield extension has not detected confidential patterns. Follow the quick guide below to perform a safe synthetic test.
                      </p>

                      {/* Interactive Synthetic Test Guide */}
                      <div className="bg-slate-50 neo-border rounded-2xl p-5 text-left mb-4">
                        <div className="font-bold text-xs uppercase tracking-wider text-black/50 mb-3 flex items-center gap-2">
                          <Terminal className="w-4 h-4" /> Quick Extension Verification Steps
                        </div>
                        <ol className="text-xs space-y-2.5 font-medium text-slate-800 pl-4 list-decimal">
                          <li>
                            <strong>Connect Extension:</strong> Click "Copy Extension Token" above and paste it into the PromptShield extension popup under <em>Aegis Platform Sync</em>.
                          </li>
                          <li>
                            <strong>Open AI Interface:</strong> Visit ChatGPT or open the extension test harness sandbox.
                          </li>
                          <li>
                            <strong>Submit Synthetic Sensitive Prompt:</strong> Paste a safe test key like below and attempt to send:
                            <div className="mt-2 flex items-center gap-2 bg-white neo-border rounded-lg p-2 font-mono text-[11px] text-purple-900">
                              <span className="flex-1 truncate">sk-proj-DEMOTESTINGSECRETKEY1234567890abcdef12345678</span>
                              <button
                                onClick={handleCopySyntheticPrompt}
                                className="bg-black text-white px-2.5 py-1 rounded neo-hover font-sans font-bold text-[10px] shrink-0"
                              >
                                {copiedSyntheticPrompt ? 'Copied!' : 'Copy'}
                              </button>
                            </div>
                          </li>
                          <li>
                            <strong>Observe Guardrail:</strong> PromptShield intercepts the prompt before network dispatch and creates a sanitized telemetry entry here.
                          </li>
                        </ol>
                      </div>
                    </div>
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
                        title="View Sanitized Details"
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
              onClick={() => fetchReports(page - 1)}
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
              onClick={() => fetchReports(page + 1)}
              className={`flex items-center gap-1 font-bold text-xs px-3 py-1.5 rounded-lg neo-border ${
                page >= totalPages ? 'opacity-40 cursor-not-allowed bg-slate-200' : 'bg-white neo-hover'
              }`}
            >
              Next <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Sanitized Incident Detail Modal */}
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
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Time of Evaluation:</span>
                <span className="font-bold text-xs">{new Date(selectedIncident.occurredAt).toLocaleString()}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Target AI Host:</span>
                <span className="font-bold text-xs uppercase">{selectedIncident.sourcePlatform || 'ChatGPT'}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Severity Rating:</span>
                <span className="font-black text-xs">{selectedIncident.severity}</span>
              </div>
              <div className="bg-slate-50 p-3 rounded-xl neo-border">
                <span className="text-[10px] font-bold text-black/50 uppercase block mb-1">Guardrail Outcome:</span>
                <span className="font-black text-xs text-red-600">[{selectedIncident.action}]</span>
              </div>
            </div>

            <div className="bg-slate-50 p-4 rounded-xl neo-border mb-6">
              <span className="text-[10px] font-bold text-black/50 uppercase block mb-1.5">Sanitized Incident Explanation:</span>
              <p className="text-xs text-slate-800 font-medium leading-relaxed">
                {selectedIncident.sanitizedMetadata?.explanation ||
                  `PromptShield AI detected a ${selectedIncident.severity} risk matching rule ${selectedIncident.ruleId}. Submission was ${selectedIncident.action.toLowerCase()} locally in your browser.`}
              </p>
            </div>

            <div className="bg-emerald-50 border border-emerald-300 p-3.5 rounded-xl text-xs text-emerald-900 font-medium flex items-start gap-2.5">
              <CheckCircle className="w-4 h-4 text-emerald-700 shrink-0 mt-0.5" />
              <span>
                <strong>Privacy Guaranteed:</strong> Neither your prompt content nor the confidential secret was ever transmitted to the server or saved to the audit log.
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
