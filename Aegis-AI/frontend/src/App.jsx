import React, { useState, useEffect, useRef, memo } from 'react';
import { Shield, ShieldAlert, Send, Activity, Lock, AlertTriangle, Paperclip, CheckCircle, Server, FileText, Mic, Trash2, LayoutDashboard, History, Info, BookOpen, Terminal, ChevronRight, Menu, Download, Search, UserCircle, Eye, EyeOff } from 'lucide-react';
import { io } from 'socket.io-client';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import EmployeeReports from './components/EmployeeReports';
import AdminSecurityDashboard from './components/AdminSecurityDashboard';

const socket = io('http://localhost:4000');

// ---------------------------------------------------------
// REUSABLE COMPONENTS
// ---------------------------------------------------------

const MessageBubble = memo(({ msg, isProtectedPanel }) => {
  const isUser = msg.role === 'user';
  const isError = msg.isError;
  const isSystem = msg.role === 'system';

  let bubbleStyle = isUser 
    ? 'bg-slate-100 text-slate-900 ml-6 md:ml-12 neo-border shadow-sm' 
    : 'bg-white text-slate-900 mr-6 md:mr-12 neo-border shadow-sm';
    
  if (isProtectedPanel && !isUser) {
    if (isError || msg.security?.action === 'BLOCKED') {
      bubbleStyle = 'bg-red-50 text-red-900 mr-6 md:mr-12 neo-border shadow-sm';
    } else if (msg.security?.action === 'WARNED') {
      bubbleStyle = 'bg-amber-50 text-amber-900 mr-6 md:mr-12 neo-border shadow-sm';
    } else if (msg.security?.action === 'SANITIZED') {
      bubbleStyle = 'bg-blue-50 text-blue-900 mr-6 md:mr-12 neo-border shadow-sm';
    } else {
      bubbleStyle = 'bg-emerald-50 text-emerald-900 mr-6 md:mr-12 neo-border shadow-sm';
    }
  } else if (!isProtectedPanel && !isUser && isError) {
    bubbleStyle = 'bg-red-50 text-red-900 mr-6 md:mr-12 neo-border shadow-sm';
  }

  return (
    <div className={`p-3 md:p-4 rounded-xl ${bubbleStyle} mb-4 transition-all`}>
      <div className="flex justify-between items-center mb-2 pb-2 border-b border-black/10">
        <div className="text-[10px] md:text-[11px] font-bold tracking-wide uppercase text-black/60 flex items-center gap-1.5">
          {isUser ? 'USER INPUT' : isSystem ? 'SYSTEM EVENT' : (isProtectedPanel ? 'AEGIS GUARDRAIL' : 'STANDARD API')}
        </div>
      </div>
      
      {isProtectedPanel && msg.security && !isUser && (
        <div className="mb-4 text-xs md:text-sm bg-white p-3 md:p-4 rounded-lg border border-black/20 shadow-sm flex flex-col gap-2 font-mono">
          <div className="flex items-center justify-between border-b border-black/10 pb-2">
            <div className="text-[10px] md:text-xs font-bold text-black/60">AEGIS ANALYSIS</div>
            <div className="flex items-center gap-2 font-black tracking-wider text-[10px] md:text-[11px]">
              {msg.security.risk_level === 'SAFE' ? (
                <span className="text-emerald-700 flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5"/> SAFE</span>
              ) : msg.security.risk_level === 'LOW' ? (
                <span className="text-emerald-600 flex items-center gap-1.5"><Activity className="w-3.5 h-3.5"/> LOW RISK</span>
              ) : msg.security.risk_level === 'MEDIUM' ? (
                <span className="text-amber-600 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5"/> MEDIUM RISK</span>
              ) : msg.security.risk_level === 'HIGH' ? (
                <span className="text-red-600 flex items-center gap-1.5"><ShieldAlert className="w-3.5 h-3.5"/> HIGH RISK</span>
              ) : (
                <span className="text-red-700 flex items-center gap-1.5"><ShieldAlert className="w-3.5 h-3.5"/> CRITICAL THREAT</span>
              )}
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-2 md:gap-4 text-[11px] md:text-[12px] text-black/80">
            <div>
              <span className="text-black/50 block mb-0.5 font-bold">RISK SCORE:</span>
              <span className="font-bold">{(msg.security.risk_score * 100).toFixed(1)}%</span>
            </div>
            <div>
              <span className="text-black/50 block mb-0.5 font-bold">CONFIDENCE:</span>
              <span className="font-bold">{(msg.security.confidence * 100).toFixed(1)}%</span>
            </div>
          </div>

          <div className="text-[11px] md:text-[12px]">
            <span className="text-black/50 block mb-0.5 font-bold">INDICATORS:</span>
            {msg.security.threat_reasons?.length > 0 && typeof msg.security.threat_reasons[0] === 'object' ? (
              <ul className="space-y-2 list-none pl-0 m-0">
                {Object.entries(msg.security.threat_reasons.reduce((acc, r) => {
                  const key = r.type || 'Unknown';
                  if (!acc[key]) acc[key] = [];
                  acc[key].push(r.indicator || r);
                  return acc;
                }, {})).map(([type, indicators], i) => (
                  <li key={i} className="flex flex-col">
                    <span className="font-bold text-black/70 uppercase text-[10px] tracking-wider mb-1">
                      {i === 0 ? 'PRIMARY THREAT:' : 'SECONDARY THREAT:'} {type}
                    </span>
                    <ul className="pl-1 space-y-0.5">
                      {indicators.map((ind, j) => (
                        <li key={j} className="flex items-start gap-1.5 font-medium text-black/60">
                          <span className="text-black/30">•</span><span>{ind}</span>
                        </li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-black/50 font-medium">No meaningful security indicators detected.</span>
            )}
          </div>
          
          {msg.security.action === 'SANITIZED' && (
            <div className="text-[11px] md:text-[12px] bg-blue-50/50 p-2 md:p-3 rounded-lg border border-blue-200 mt-1">
              <span className="text-blue-700 block mb-1 font-black">SANITIZATION:</span>
              <div className="mb-1"><span className="text-black/50 font-bold">Original:</span> <span className="line-through">{msg.security.original_prompt}</span></div>
              <div><span className="text-black/50 font-bold">Rewritten:</span> <span className="font-bold">{msg.security.redacted_prompt}</span></div>
            </div>
          )}

          <div className="text-[11px] md:text-[12px] pt-2 border-t border-black/10 flex justify-between items-center">
            <span className="text-black/50 font-bold">ACTION TAKEN:</span>
            <span className={`font-black ${msg.security.action === 'BLOCKED' ? 'text-red-600' : msg.security.action === 'WARNED' ? 'text-amber-600' : msg.security.action === 'SANITIZED' ? 'text-blue-700' : 'text-emerald-700'}`}>
              [{msg.security.action}]
            </span>
          </div>
        </div>
      )}

      {!isUser && (
        <div className="text-[9px] md:text-[10px] font-black tracking-widest uppercase text-black/40 mb-1">
           {isProtectedPanel ? 'PROTECTED RESPONSE' : 'STANDARD RESPONSE'}
        </div>
      )}
      <div className="leading-relaxed text-[13px] md:text-[14px] whitespace-pre-wrap font-mono break-all font-medium text-black">
        {msg.content}
      </div>
    </div>
  );
});


// ---------------------------------------------------------
// MAIN APP COMPONENT
// ---------------------------------------------------------

function App() {
  const [activeTab, setActiveTab] = useState('Overview');
  const [selectedReportId, setSelectedReportId] = useState(null);
  
  // Auth State
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'signup'
  const [authName, setAuthName] = useState('');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  const [authOrgName, setAuthOrgName] = useState('');
  const [authAdminSecret, setAuthAdminSecret] = useState('');
  
  const [prompt, setPrompt] = useState('');
  const [dbHistory, setDbHistory] = useState([]);
  const [unprotectedHistory, setUnprotectedHistory] = useState([]);
  const [protectedHistory, setProtectedHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isListening, setIsListening] = useState(false);
  
  const unprotEndRef = useRef(null);
  const protEndRef = useRef(null);
  const fileInputRef = useRef(null);

  const refreshHistory = () => {
    const savedToken = localStorage.getItem('token');
    if (!savedToken) {
      setDbHistory([]);
      setUnprotectedHistory([]);
      setProtectedHistory([]);
      return;
    }
    const headers = { Authorization: `Bearer ${savedToken}` };
    axios.get('http://localhost:4000/api/history', { headers }).then(res => {
      const logs = res.data;
      setDbHistory(logs);
      setUnprotectedHistory(logs.filter(log => !log.isProtected));
      setProtectedHistory(logs.filter(log => log.isProtected));
    }).catch(err => {
      if (err.response?.status === 401 || err.response?.status === 403) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setIsLoggedIn(false);
        setUser(null);
      }
      console.warn("History not loaded:", err.message);
    });
  };

  // Analytics Dashboard State
  const [analyticsData, setAnalyticsData] = useState(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [analyticsError, setAnalyticsError] = useState('');
  const [analyticsStartDate, setAnalyticsStartDate] = useState('');
  const [analyticsEndDate, setAnalyticsEndDate] = useState('');

  const fetchAnalytics = (sDate = analyticsStartDate, eDate = analyticsEndDate) => {
    const savedToken = localStorage.getItem('token');
    if (!savedToken) {
      setAnalyticsData(null);
      setAnalyticsLoading(false);
      return;
    }
    setAnalyticsLoading(true);
    setAnalyticsError('');
    const headers = { Authorization: `Bearer ${savedToken}` };
    const params = {};
    if (sDate) params.startDate = sDate;
    if (eDate) params.endDate = eDate;

    axios.get('http://localhost:4000/api/analytics', { headers, params })
      .then(res => {
        setAnalyticsData(res.data);
      })
      .catch(err => {
        console.error("Failed to load security analytics:", err);
        setAnalyticsError(err.response?.data?.error || 'Failed to load security analytics.');
      })
      .finally(() => {
        setAnalyticsLoading(false);
      });
  };

  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (savedToken && savedUser) {
      setIsLoggedIn(true);
      setUser(JSON.parse(savedUser));
      socket.emit('join_org', { token: savedToken });
    }

    refreshHistory();
    fetchAnalytics();

    const handleIncident = () => {
      fetchAnalytics();
    };

    socket.on('promptshield_incident', handleIncident);
    socket.on('threat_alert', (data) => {
      setAlerts(prev => [...prev, data]);
      setTimeout(() => setAlerts(prev => prev.filter(a => a !== data)), 5000);
      fetchAnalytics();
    });

    return () => {
      socket.off('threat_alert');
      socket.off('promptshield_incident', handleIncident);
    };
  }, []);

  useEffect(() => {
    if (activeTab === 'Dashboard') {
      fetchAnalytics(analyticsStartDate, analyticsEndDate);
    }
  }, [activeTab, analyticsStartDate, analyticsEndDate]);

  useEffect(() => { unprotEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [unprotectedHistory, activeTab]);
  useEffect(() => { protEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [protectedHistory, activeTab]);

  const handleSend = async () => {
    if (!prompt.trim() || isProcessing) return;
    const currentPrompt = prompt;
    setPrompt('');
    setIsProcessing(true);
    
    const userMsgUnprot = { role: 'user', content: currentPrompt, isProtected: false };
    const userMsgProt = { role: 'user', content: currentPrompt, isProtected: true };
    
    setUnprotectedHistory(prev => [...prev, userMsgUnprot]);
    setProtectedHistory(prev => [...prev, userMsgProt]);

    const savedToken = localStorage.getItem('token');
    const headers = savedToken ? { Authorization: `Bearer ${savedToken}` } : {};

    const reqUnprotected = axios.post('http://localhost:4000/api/chat', { prompt: currentPrompt, isProtected: false }, { headers })
      .then(res => setUnprotectedHistory(prev => [...prev, { role: 'assistant', content: res.data.response, isProtected: false }]))
      .catch(() => setUnprotectedHistory(prev => [...prev, { role: 'system', content: 'Connection Error.', isError: true, isProtected: false }]));

    const reqProtected = axios.post('http://localhost:4000/api/chat', { prompt: currentPrompt, isProtected: true }, { headers })
      .then(res => setProtectedHistory(prev => [...prev, { role: 'assistant', content: res.data.response, security: res.data.security, isProtected: true }]))
      .catch(err => {
        if (err.response && err.response.status === 403) {
          setProtectedHistory(prev => [...prev, { role: 'system', content: 'REQUEST INTERCEPTED AND BLOCKED', security: err.response.data.security, isError: true, isProtected: true }]);
        } else {
          setProtectedHistory(prev => [...prev, { role: 'system', content: 'Connection Error.', isError: true, isProtected: true }]);
        }
      });

    await Promise.all([reqUnprotected, reqProtected]);
    setIsProcessing(false);
    refreshHistory(); // Pull latest DB IDs
  };

  const clearConsole = () => {
    setUnprotectedHistory([]);
    setProtectedHistory([]);
    if (activeTab === 'Report') setActiveTab('History');
  };

  const Footer = () => (
    <footer className="mt-12 pt-8 border-t-2 border-black/10 flex flex-col md:flex-row items-center justify-between gap-4 text-sm font-bold text-black/60 pb-8 w-full">
      <div>
        Created & Developed by <span className="text-black font-black">Mohd Ali Khan</span>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-6">
        <a href="#" className="hover:text-purple-600 transition-colors">Privacy Policy</a>
        <a href="#" className="hover:text-purple-600 transition-colors">Terms of Service</a>
        <a href="#" className="hover:text-purple-600 transition-colors">Contact</a>
        <span className="text-black/40">© {new Date().getFullYear()} Aegis Security</span>
      </div>
    </footer>
  );

  const handleVoice = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) { alert("Voice recognition not supported in this browser."); return; }
    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';
    recognition.onstart = () => setIsListening(true);
    recognition.onresult = (event) => setPrompt(prev => prev + (prev ? ' ' : '') + event.results[0][0].transcript);
    recognition.onend = () => setIsListening(false);
    recognition.start();
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      let content = event.target.result;
      if (content.length > 1000) content = content.substring(0, 1000) + '...[TRUNCATED]';
      setPrompt(prev => prev + (prev ? ' ' : '') + `[FILE: ${file.name} - Content: "${content.replace(/"/g, "'").replace(/\n/g, " ")}"]`);
      e.target.value = null;
    };
    reader.readAsText(file);
  };

  // ---------------------------------------------------------
  // TAB RENDERERS
  // ---------------------------------------------------------
  
  const renderOverview = () => (
    <div className="flex-1 p-6 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full">
      <div className="flex flex-col md:flex-row gap-8">
        
        {/* Left Big Card */}
        <div className="flex-[2] bg-white rounded-[24px] neo-border neo-shadow p-8 md:p-12">
          <div className="inline-flex items-center gap-2 bg-purple-100 neo-border px-4 py-2 rounded-full mb-8 neo-shadow-sm font-bold text-sm">
            <CheckCircle className="w-4 h-4 fill-purple-300" />
            Verified for 2026 Security Audits
          </div>
          
          <h1 className="font-heading text-5xl md:text-7xl font-black mb-6 leading-tight tracking-tight">
            Aegis Security<br/>Framework & Console
          </h1>
          
          <p className="text-lg text-black/70 font-medium mb-10 max-w-xl leading-relaxed">
            Get ready for Enterprise Security with live guardrails, advanced telemetry, prompt injection detection, and detailed forensic reporting. Use these Aegis tools to connect threats, vulnerabilities, and defense-in-depth reasoning for your organization.
          </p>
          
          <div className="flex flex-wrap gap-4 font-heading font-bold">
            <button className="bg-black text-white px-6 py-3 rounded-full neo-hover transition-transform border-2 border-transparent">
              unlock all features
            </button>
            <button onClick={() => setActiveTab('Console')} className="bg-purple-100 text-black px-6 py-3 rounded-full neo-border neo-hover neo-shadow-sm transition-transform">
              start diagnostic
            </button>
            <button className="bg-blue-100 text-black px-6 py-3 rounded-full neo-border neo-hover neo-shadow-sm transition-transform">
              for enterprise
            </button>
          </div>
        </div>

        {/* Right Nav Stack */}
        <div className="flex-1 bg-cyan-100 rounded-[24px] neo-border neo-shadow p-6 md:p-8 flex flex-col">
          <h3 className="font-heading font-black text-lg mb-6 uppercase tracking-widest text-black/80">Jump into a resource</h3>
          
          <div className="flex flex-col gap-4">
            {[
              { id: 'Console', icon: Terminal, title: 'Live Console', count: 'Active →' },
              { id: 'Dashboard', icon: LayoutDashboard, title: 'Dashboard', count: 'Analytics →' },
              { id: 'History', icon: History, title: 'Scan History', count: `${dbHistory.length} logs →` },
              { id: 'Guidance', icon: BookOpen, title: 'Guidance Docs', count: 'Read →' },
              { id: 'About', icon: Info, title: 'About Aegis', count: 'Learn →' },
            ].map(item => (
              <button 
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className="bg-white neo-border rounded-xl p-4 flex items-center justify-between neo-hover neo-shadow-sm transition-transform group"
              >
                <div className="flex items-center gap-3 font-bold text-lg">
                  <item.icon className="w-5 h-5 text-black/70" />
                  {item.title}
                </div>
                <span className="text-black/50 text-sm font-semibold group-hover:text-black">{item.count}</span>
              </button>
            ))}
          </div>
        </div>

      </div>
      <Footer />
    </div>
  );

  const renderConsole = () => (
    <div className="flex-1 flex flex-col min-h-0 bg-slate-50 max-w-7xl mx-auto w-full p-6">
      <div className="flex items-center justify-between mb-4 gap-2">
        <h2 className="font-heading font-black text-2xl md:text-3xl truncate">Live Security Console</h2>
        <button onClick={clearConsole} className="bg-white neo-border px-3 md:px-4 py-2 rounded-full font-bold text-xs md:text-sm neo-hover neo-shadow-sm flex items-center gap-2 shrink-0">
          <Trash2 className="w-4 h-4"/> Clear Chat
        </button>
      </div>
      
      <div className="flex-1 flex flex-col md:flex-row gap-6 min-h-0 mb-6">
        {/* Unprotected Side */}
        <div className="flex-1 bg-white neo-border neo-shadow rounded-2xl flex flex-col overflow-hidden">
          <div className="bg-slate-100 p-4 border-b-2 border-black flex items-center gap-3 shrink-0">
            <div className="bg-white neo-border p-1.5 rounded-lg"><Server className="w-5 h-5" /></div>
            <h2 className="font-heading font-bold text-lg">Standard API</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-6 bg-white">
            {unprotectedHistory.map((msg, idx) => <MessageBubble key={idx} msg={msg} isProtectedPanel={false} />)}
            {isProcessing && <div className="text-sm text-black/50 font-bold font-mono">Processing payload...</div>}
            <div ref={unprotEndRef} />
          </div>
        </div>
        
        {/* Protected Side */}
        <div className="flex-1 bg-white neo-border neo-shadow rounded-2xl flex flex-col overflow-hidden">
          <div className="bg-emerald-100 p-4 border-b-2 border-black flex items-center gap-3 shrink-0">
            <div className="bg-white neo-border p-1.5 rounded-lg"><Lock className="w-5 h-5 text-emerald-600" /></div>
            <h2 className="font-heading font-bold text-lg text-emerald-950">Aegis Guardrail</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-6 bg-white">
            {protectedHistory.map((msg, idx) => <MessageBubble key={idx} msg={msg} isProtectedPanel={true} />)}
            {isProcessing && <div className="text-sm text-emerald-600/50 font-bold font-mono">Analyzing telemetry...</div>}
            <div ref={protEndRef} />
          </div>
        </div>
      </div>

      <div className="shrink-0 bg-white neo-border neo-shadow rounded-2xl p-2 flex items-end">
        <button onClick={() => fileInputRef.current?.click()} className="p-2 md:p-3 hover:bg-slate-100 rounded-xl transition-colors neo-border neo-shadow-none border-transparent hover:border-black shrink-0"><Paperclip className="w-5 md:w-6 h-5 md:h-6" /></button>
        <button onClick={handleVoice} className={`p-2 md:p-3 rounded-xl transition-colors neo-border border-transparent hover:border-black shrink-0 ${isListening ? 'bg-red-100 text-red-600 animate-pulse' : 'hover:bg-slate-100'}`}><Mic className="w-5 md:w-6 h-5 md:h-6" /></button>
        <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleFileUpload} accept=".txt,.md,.js,.json,.csv,.log"/>
        
        <textarea 
          value={prompt} 
          onChange={(e) => setPrompt(e.target.value)} 
          onKeyDown={(e) => { if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); handleSend();} }} 
          placeholder="Enter payload..." 
          className="flex-1 bg-transparent border-none focus:outline-none text-black placeholder-black/40 text-sm md:text-lg font-medium resize-none py-3 px-2 md:px-4 min-h-[50px] max-h-[150px]" 
          disabled={isProcessing} 
          rows={1}
        />
        
        <button onClick={handleSend} disabled={isProcessing || !prompt.trim()} className={`ml-1 md:ml-2 px-4 md:px-8 py-3 rounded-xl font-heading font-black text-sm md:text-lg transition-transform border-2 border-transparent shrink-0 ${isProcessing || !prompt.trim() ? 'bg-slate-200 text-slate-400' : 'bg-black text-white neo-hover'}`}>
          {isProcessing ? 'Wait' : 'Send'}
        </button>
      </div>
    </div>
  );

  const renderDashboard = () => {
    const summary = analyticsData?.summary || { scanned: 0, blocked: 0, sanitized: 0, allowed: 0 };
    const actionData = analyticsData?.actionDistribution || [
      { name: 'Blocked', value: 0, color: '#ef4444' },
      { name: 'Sanitized', value: 0, color: '#3b82f6' },
      { name: 'Allowed', value: 0, color: '#10b981' }
    ];
    const riskVolumeData = analyticsData?.recentRiskVolume || [];
    const hasData = summary.scanned > 0;

    return (
      <div className="flex-1 p-6 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="font-heading font-black text-3xl md:text-4xl mb-1">Analytics Dashboard</h2>
            <p className="text-black/60 text-xs md:text-sm font-medium">
              Verified guardrail analytics across PromptShield client guardrails and protected AI gateway sessions.
            </p>
          </div>

          {/* Date Filters & Controls Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 bg-white neo-border rounded-xl px-2.5 py-1.5 text-xs font-bold">
              <span className="text-[10px] text-black/50 uppercase">From:</span>
              <input
                type="date"
                value={analyticsStartDate}
                onChange={(e) => setAnalyticsStartDate(e.target.value)}
                className="bg-transparent border-none outline-none text-[11px] font-bold"
                title="Start Date"
              />
            </div>
            <div className="flex items-center gap-1.5 bg-white neo-border rounded-xl px-2.5 py-1.5 text-xs font-bold">
              <span className="text-[10px] text-black/50 uppercase">To:</span>
              <input
                type="date"
                value={analyticsEndDate}
                onChange={(e) => setAnalyticsEndDate(e.target.value)}
                className="bg-transparent border-none outline-none text-[11px] font-bold"
                title="End Date"
              />
            </div>
            {(analyticsStartDate || analyticsEndDate) && (
              <button
                onClick={() => { setAnalyticsStartDate(''); setAnalyticsEndDate(''); }}
                className="bg-slate-100 hover:bg-slate-200 text-black text-xs font-bold px-2.5 py-1.5 rounded-xl neo-border transition-colors"
                title="Reset date filter"
              >
                Clear
              </button>
            )}
            <button
              onClick={() => fetchAnalytics()}
              className="bg-white neo-border neo-hover px-3 py-1.5 rounded-xl font-bold text-xs flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${analyticsLoading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        </div>

        {analyticsError && (
          <div className="mb-6 bg-red-100 text-red-800 p-4 rounded-xl neo-border font-bold text-xs flex items-center justify-between">
            <span>{analyticsError}</span>
            <button onClick={() => fetchAnalytics()} className="underline ml-4">Retry</button>
          </div>
        )}

        {!isLoggedIn && (
          <div className="mb-6 bg-amber-50 border border-amber-300 text-amber-900 p-4 rounded-2xl neo-border font-medium text-xs flex items-center justify-between">
            <span>Viewing unauthenticated mode. Please log in or sign up to access your authenticated organization analytics.</span>
            <button onClick={() => { setAuthMode('login'); setShowAuthModal(true); }} className="bg-black text-white px-3 py-1.5 rounded-xl font-bold text-xs neo-hover ml-4 shrink-0">
              Log In
            </button>
          </div>
        )}

        {/* KPI Cards Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6 mb-10">
          {[ 
            { label: 'Scanned', val: summary.scanned, color: 'bg-white', text: 'text-black' },
            { label: 'Blocked', val: summary.blocked, color: 'bg-red-100', text: 'text-red-600' },
            { label: 'Sanitized', val: summary.sanitized, color: 'bg-blue-100', text: 'text-blue-600' },
            { label: 'Allowed', val: summary.allowed, color: 'bg-emerald-100', text: 'text-emerald-600' }
          ].map((stat, i) => (
            <div key={i} className={`${stat.color} neo-border neo-shadow rounded-2xl p-4 md:p-6 transition-all`}>
              <div className="text-black/60 text-xs md:text-sm font-bold mb-2 uppercase tracking-wider">{stat.label}</div>
              <div className={`text-3xl md:text-5xl font-black font-heading ${stat.text}`}>
                {analyticsLoading ? '...' : stat.val}
              </div>
            </div>
          ))}
        </div>

        {analyticsLoading ? (
          <div className="bg-white neo-border neo-shadow rounded-2xl p-16 text-center mb-8">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto text-black/40 mb-3" />
            <div className="font-heading font-black text-lg">Loading Analytics Data...</div>
            <p className="text-xs text-black/50 font-medium">Aggregating verified security incidents from database.</p>
          </div>
        ) : !hasData ? (
          <div className="bg-white neo-border neo-shadow rounded-2xl p-12 text-center mb-8">
            <div className="bg-purple-100 w-16 h-16 rounded-full neo-border flex items-center justify-center mx-auto mb-4">
              <Shield className="w-8 h-8 text-purple-800" />
            </div>
            <h3 className="font-heading font-black text-xl mb-2">No Scan Events Recorded</h3>
            <p className="text-xs text-black/60 font-medium max-w-md mx-auto mb-6 leading-relaxed">
              No prompt scans or security incidents match the current filters. Guardrail interceptions from the PromptShield Chrome extension or the Protected Console will populate here automatically.
            </p>
            {isLoggedIn && (
              <button
                onClick={() => setActiveTab('My Reports')}
                className="bg-black text-white px-5 py-2.5 rounded-xl font-bold text-xs neo-hover inline-flex items-center gap-2"
              >
                Go to My Reports <ChevronRight className="w-4 h-4" />
              </button>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            <div className="bg-white neo-border neo-shadow rounded-2xl p-6 flex flex-col min-h-[320px]">
              <h3 className="font-heading font-bold text-xl mb-6">Action Distribution</h3>
              <div className="flex-1 min-h-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={actionData} cx="50%" cy="50%" innerRadius={70} outerRadius={110} paddingAngle={5} dataKey="value" stroke="#000" strokeWidth={2}>
                      {actionData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                    </Pie>
                    <RechartsTooltip contentStyle={{backgroundColor: '#fff', border: '2px solid #000', borderRadius: '12px', boxShadow: '4px 4px 0 0 #000', fontWeight: 'bold'}}/>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            
            <div className="bg-white neo-border neo-shadow rounded-2xl p-6 flex flex-col min-h-[320px]">
              <h3 className="font-heading font-bold text-xl mb-6">Recent Risk Volume</h3>
              <div className="flex-1 min-h-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={riskVolumeData}>
                    <XAxis dataKey="name" stroke="#000" fontSize={12} tickLine={false} axisLine={{strokeWidth: 2}} />
                    <YAxis stroke="#000" fontSize={12} tickLine={false} axisLine={{strokeWidth: 2}} domain={[0, 100]} />
                    <RechartsTooltip
                      contentStyle={{backgroundColor: '#fff', border: '2px solid #000', borderRadius: '12px', boxShadow: '4px 4px 0 0 #000', fontWeight: 'bold'}}
                      cursor={{fill: '#f1f5f9'}}
                      formatter={(val, name, item) => [`${val}% Risk (${item?.payload?.action || 'EVALUATED'})`, 'Risk Score']}
                    />
                    <Bar dataKey="score" fill="#c084fc" radius={[8, 8, 0, 0]} stroke="#000" strokeWidth={2} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}
        <Footer />
      </div>
    );
  };

  const renderHistory = () => {
    const secLogs = dbHistory.filter(h => h.isProtected && h.security && (h.role === 'assistant' || h.role === 'system'));
    return (
      <div className="flex-1 p-4 md:p-12 overflow-y-auto max-w-7xl mx-auto w-full">
        <h2 className="font-heading font-black text-3xl md:text-4xl mb-8">Scan History</h2>
        <div className="bg-white neo-border neo-shadow rounded-2xl overflow-x-auto">
          <table className="w-full text-left min-w-[600px]">
            <thead className="bg-slate-100 border-b-2 border-black">
              <tr>
                <th className="p-5 font-bold uppercase tracking-wider text-sm text-black/60">Time</th>
                <th className="p-5 font-bold uppercase tracking-wider text-sm text-black/60">Risk</th>
                <th className="p-5 font-bold uppercase tracking-wider text-sm text-black/60">Action</th>
                <th className="p-5 font-bold uppercase tracking-wider text-sm text-black/60">Prompt Preview</th>
                <th className="p-5"></th>
              </tr>
            </thead>
            <tbody className="divide-y-2 divide-black/10">
              {secLogs.length === 0 && <tr><td colSpan="5" className="p-8 text-center font-bold text-black/50">No logs yet.</td></tr>}
              {[...secLogs].reverse().map(log => (
                <tr key={log._id} className="hover:bg-slate-50 transition-colors">
                  <td className="p-5 font-mono text-sm font-bold">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="p-5">
                    <span className={`px-3 py-1.5 rounded-full text-xs font-black neo-border ${log.security.risk_level === 'SAFE' ? 'text-emerald-700 bg-emerald-100' : log.security.risk_level === 'CRITICAL' || log.security.risk_level === 'HIGH' ? 'text-red-700 bg-red-100' : 'text-amber-700 bg-amber-100'}`}>
                      {log.security.risk_level}
                    </span>
                  </td>
                  <td className="p-5 font-black text-sm">
                    {log.security.action === 'BLOCKED' && <span className="text-red-600">BLOCKED</span>}
                    {log.security.action === 'SANITIZED' && <span className="text-blue-600">SANITIZED</span>}
                    {log.security.action === 'WARNED' && <span className="text-amber-600">WARNED</span>}
                    {log.security.action === 'ALLOWED' && <span className="text-emerald-600">ALLOWED</span>}
                  </td>
                  <td className="p-5 text-black/70 truncate max-w-xs font-mono font-medium">{log.security.original_prompt}</td>
                  <td className="p-5 text-right">
                    <button onClick={() => { setSelectedReportId(log._id); setActiveTab('Report'); }} className="bg-white neo-border p-2 rounded-full neo-hover neo-shadow-sm">
                      <ChevronRight className="w-5 h-5"/>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Footer />
      </div>
    );
  };

  const renderReport = () => {
    const log = dbHistory.find(h => h._id === selectedReportId);
    if (!log) return <div className="p-12 text-center font-bold">No report selected.</div>;
    const s = log.security;
    
    const groupedThreats = Object.entries(s.threat_reasons?.reduce((acc, r) => {
      if (typeof r === 'object') {
        if (!acc[r.type]) acc[r.type] = [];
        acc[r.type].push(r.indicator);
      }
      return acc;
    }, {}) || {});

    const downloadReport = () => {
      const reportText = `
========================================
AEGIS SECURITY FORENSIC REPORT
========================================
Report ID: ${log._id}
Timestamp: ${new Date(log.timestamp).toLocaleString()}

[ OVERVIEW ]
Risk Level:   ${s.risk_level} (${(s.risk_score*100).toFixed(1)}%) - Estimated security risk
Action Taken: ${s.action}
Confidence:   ${(s.confidence*100).toFixed(1)}% - Confidence in classification
Latency:      ${s.analysis_latency_ms ? s.analysis_latency_ms.toFixed(2) + 'ms' : 'N/A'}

[ ORIGINAL PAYLOAD ]
${s.original_prompt}

[ REWRITTEN/INTERCEPTED PAYLOAD ]
${s.redacted_prompt || 'N/A'}

[ DETAILED THREAT BREAKDOWN ]
${groupedThreats.length > 0 ? groupedThreats.map(([type, inds], i) => 
  `${i === 0 ? 'PRIMARY THREAT' : 'SECONDARY THREAT'}: ${type}\nEvidence:\n${inds.map(ind => `• ${ind}`).join('\n')}`
).join('\n\n') : 'No specific threats detected.'}

========================================
Generated by Aegis.AI Security Console
`;
      const blob = new Blob([reportText.trim()], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Aegis_Security_Report_${log._id}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };

    return (
      <div className="flex-1 p-6 md:p-12 overflow-y-auto max-w-5xl mx-auto w-full">
        <div className="flex justify-between items-center mb-8">
          <button onClick={() => setActiveTab('History')} className="flex items-center gap-2 font-bold hover:underline">← Back to History</button>
          <button onClick={downloadReport} className="bg-emerald-100 text-emerald-800 neo-border neo-shadow-sm neo-hover px-6 py-2 rounded-full font-bold flex items-center gap-2">
            <Download className="w-4 h-4" /> Export Report
          </button>
        </div>
        
        <h2 className="font-heading font-black text-2xl md:text-4xl mb-8">Detailed Security Report</h2>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6 mb-8">
          <div className="bg-white neo-border shadow-sm rounded-2xl p-5">
            <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1">RISK LEVEL</div>
            <div className={`text-2xl font-black font-heading ${s.risk_level==='CRITICAL'||s.risk_level==='HIGH'?'text-red-600':s.risk_level==='SAFE'?'text-emerald-600':'text-amber-600'}`}>
              {s.risk_level}
            </div>
            <div className="text-[10px] text-black/40 font-bold uppercase mt-1 tracking-widest">Score: {(s.risk_score*100).toFixed(1)}% (Est. Risk)</div>
          </div>
          <div className="bg-white neo-border shadow-sm rounded-2xl p-5">
            <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1">CONFIDENCE</div>
            <div className="text-2xl font-black font-heading">{(s.confidence*100).toFixed(1)}%</div>
            <div className="text-[10px] text-black/40 font-bold uppercase mt-1 tracking-widest">in Classification</div>
          </div>
          <div className="bg-white neo-border shadow-sm rounded-2xl p-5">
            <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1">ACTION TAKEN</div>
            <div className="text-2xl font-black font-heading">{s.action}</div>
          </div>
          <div className="bg-white neo-border shadow-sm rounded-2xl p-5">
            <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1">LATENCY</div>
            <div className="text-2xl font-black font-heading">{s.analysis_latency_ms ? s.analysis_latency_ms.toFixed(0) + 'ms' : '<1ms'}</div>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
          <div className="bg-white neo-border shadow-sm rounded-2xl p-5 text-xs text-black/70 leading-relaxed">
            <strong className="text-black block mb-1">Security Pipeline Trace:</strong>
            USER INPUT → SECURITY ANALYSIS → CLASSIFICATION → RISK SCORE → ACTION → {s.action === 'SANITIZED' ? 'SANITIZATION → VALIDATION → PROTECTED MODEL' : s.action === 'BLOCKED' ? 'REQUEST REJECTED' : 'PROTECTED MODEL'}
          </div>
          <div className="bg-white neo-border shadow-sm rounded-2xl p-5 text-[11px] text-black/70 leading-relaxed grid grid-cols-2 gap-4">
            <div><strong className="text-emerald-700">ALLOWED:</strong> No meaningful security indicators.</div>
            <div><strong className="text-amber-700">WARNED:</strong> Potentially risky but allowed.</div>
            <div><strong className="text-blue-700">SANITIZED:</strong> Unsafe portions removed/re-written before reaching model.</div>
            <div><strong className="text-red-700">BLOCKED:</strong> Request is prevented from reaching model.</div>
          </div>
        </div>

        <div className="bg-white neo-border shadow-sm rounded-2xl p-6 mb-8">
          <div className="flex flex-col md:flex-row gap-8 mb-4 border-b border-black/10 pb-4">
             <div className="flex-1">
               <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1">Audit ID:</div>
               <div className="font-mono font-medium text-sm">{log._id}</div>
             </div>
             <div className="flex-1">
               <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1">Timestamp:</div>
               <div className="font-mono font-medium text-sm">{new Date(log.timestamp).toLocaleString()}</div>
             </div>
          </div>

          <h3 className="font-heading font-bold text-lg mb-4 border-b border-black/10 pb-3">PROMPT ANALYSIS</h3>
          <div className="mb-4">
            <span className="text-black/50 block mb-1.5 font-bold text-xs uppercase tracking-widest">Original Payload:</span>
            <div className="bg-slate-50 p-4 rounded-xl border border-black/10 font-mono font-medium text-sm">{s.original_prompt}</div>
          </div>
          {s.action === 'SANITIZED' && (
            <div>
              <span className="text-blue-600 block mb-1.5 font-bold text-xs uppercase tracking-widest">Safe Rewrite:</span>
              <div className="bg-blue-50/50 p-4 rounded-xl border border-blue-200 font-mono font-medium text-sm">{s.redacted_prompt}</div>
            </div>
          )}
        </div>

        <div className="bg-white neo-border shadow-sm rounded-2xl p-6">
          <h3 className="font-heading font-bold text-lg mb-4 border-b border-black/10 pb-3">THREAT BREAKDOWN</h3>
          
          <div className="mb-6">
            <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-1.5">Decision Explanation:</div>
            <p className="font-medium text-sm text-black/80">
              {groupedThreats.length > 0 
                ? `The security engine detected ${groupedThreats.length} distinct threat classifications that elevated the risk score to ${(s.risk_score * 100).toFixed(1)}%.`
                : "No meaningful security indicators detected. The payload was evaluated as safe and authorized for standard processing."}
            </p>
          </div>

          <div className="text-black/50 font-bold text-xs uppercase tracking-widest mb-2">Detection Method & Indicators:</div>
          {groupedThreats.length > 0 ? (
            <div className="grid grid-cols-1 gap-4">
              {groupedThreats.map(([type, inds], i) => (
                <div key={i} className="p-4 rounded-xl border bg-slate-50 border-black/10">
                  <div className="flex items-center justify-between mb-3 border-b border-black/5 pb-2">
                     <div>
                       <div className="text-[10px] text-black/50 font-bold tracking-wider mb-0.5">{i === 0 ? 'PRIMARY THREAT' : 'SECONDARY THREAT'}</div>
                       <div className="font-black text-lg">{type}</div>
                     </div>
                  </div>
                  <div>
                    <span className="text-[10px] text-black/50 font-bold tracking-wider block mb-2">EVIDENCE INDICATORS:</span>
                    <ul className="space-y-2">
                       {inds.map((ind, j) => (
                         <li key={j} className="flex items-start gap-2">
                           <span className="text-black/30 mt-0.5">•</span>
                           <span className="bg-white border border-black/20 px-2 py-1 rounded-md font-mono font-bold text-xs">
                             {ind}
                           </span>
                         </li>
                       ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          ) : (
             <div className="font-bold text-black/50 text-sm italic">✓ Passed all security checks seamlessly.</div>
          )}
        </div>
        <Footer />
      </div>
    );
  };

  // ---------------------------------------------------------
  // AUTH LOGIC & MODAL
  // ---------------------------------------------------------
  const handleAuth = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const payload = authMode === 'login' 
        ? { email: authEmail, password: authPassword }
        : {
            name: authName,
            email: authEmail,
            password: authPassword,
            organizationName: authOrgName || undefined,
            adminSecret: authAdminSecret || undefined
          };
      
      const res = await axios.post(`http://localhost:4000${endpoint}`, payload);
      
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('user', JSON.stringify(res.data.user));
      
      setUser(res.data.user);
      setIsLoggedIn(true);
      setShowAuthModal(false);
      socket.emit('join_org', { token: res.data.token });
      refreshHistory();
      
      // Reset fields
      setAuthPassword('');
      setAuthAdminSecret('');
    } catch (err) {
      setAuthError(err.response?.data?.error || 'Authentication failed');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setIsLoggedIn(false);
    setActiveTab('Overview');
    refreshHistory();
  };

  const renderAuthModal = () => {
    if (!showAuthModal) return null;
    
    return (
      <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
        <div className="bg-white neo-border neo-shadow-sm rounded-[24px] p-8 w-full max-w-md relative max-h-[90vh] overflow-y-auto">
          <button onClick={() => setShowAuthModal(false)} className="absolute top-4 right-4 text-black/50 hover:text-black font-black text-xl">✕</button>
          
          <div className="text-center mb-6">
            <div className="bg-purple-100 w-16 h-16 rounded-full neo-border flex items-center justify-center mx-auto mb-4">
              <Shield className="w-8 h-8 fill-purple-300" />
            </div>
            <h2 className="font-heading font-black text-3xl mb-2">{authMode === 'login' ? 'Welcome Back' : 'Create Account'}</h2>
            <p className="text-black/60 font-bold text-sm">
              {authMode === 'login' ? 'Log in to access your security console.' : 'Sign up to secure your organization.'}
            </p>
          </div>

          {authError && <div className="mb-4 bg-red-100 text-red-700 font-bold text-sm p-3 rounded-lg neo-border">{authError}</div>}

          <form onSubmit={handleAuth} className="flex flex-col gap-4">
            {authMode === 'signup' && (
              <>
                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-2 uppercase">Full Name</label>
                  <input type="text" required value={authName} onChange={e => setAuthName(e.target.value)} placeholder="Mohd Ali Khan" className="w-full bg-slate-50 neo-border rounded-xl px-4 py-3 font-medium outline-none focus:ring-2 ring-black" />
                </div>
                <div>
                  <label className="block text-xs font-black tracking-widest text-black/60 mb-2 uppercase">Organization Name (Optional)</label>
                  <input type="text" value={authOrgName} onChange={e => setAuthOrgName(e.target.value)} placeholder="Acme Cybersecurity Ltd" className="w-full bg-slate-50 neo-border rounded-xl px-4 py-3 font-medium outline-none focus:ring-2 ring-black" />
                </div>
              </>
            )}
            <div>
              <label className="block text-xs font-black tracking-widest text-black/60 mb-2 uppercase">Email Address</label>
              <input type="email" required value={authEmail} onChange={e => setAuthEmail(e.target.value)} placeholder="admin@aegis.ai" className="w-full bg-slate-50 neo-border rounded-xl px-4 py-3 font-medium outline-none focus:ring-2 ring-black" />
            </div>
            <div>
              <label className="block text-xs font-black tracking-widest text-black/60 mb-2 uppercase">Password</label>
              <div className="relative flex items-center">
                <input type={showPassword ? "text" : "password"} required value={authPassword} onChange={e => setAuthPassword(e.target.value)} placeholder="••••••••" className="w-full bg-slate-50 neo-border rounded-xl px-4 py-3 font-medium outline-none focus:ring-2 ring-black pr-12" />
                <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-4 text-black/50 hover:text-black">
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {authMode === 'signup' && (
              <div>
                <label className="block text-xs font-black tracking-widest text-black/60 mb-1 uppercase">Admin Secret (Optional)</label>
                <span className="text-[10px] text-black/50 block mb-2">Leave blank for Employee role. Enter secret for Admin privileges.</span>
                <input type="password" value={authAdminSecret} onChange={e => setAuthAdminSecret(e.target.value)} placeholder="Admin provisioning secret" className="w-full bg-slate-50 neo-border rounded-xl px-4 py-2.5 font-medium outline-none text-xs focus:ring-2 ring-black" />
              </div>
            )}
            
            <button type="submit" className="w-full bg-black text-white py-3 rounded-xl font-heading font-black text-lg mt-2 neo-hover border-2 border-transparent">
              {authMode === 'login' ? 'LOG IN' : 'SIGN UP'}
            </button>
          </form>

          <div className="mt-6 text-center font-bold text-sm">
            {authMode === 'login' ? (
              <span className="text-black/60">Don't have an account? <button onClick={() => { setAuthMode('signup'); setAuthError(''); }} className="text-purple-600 hover:underline">Sign up</button></span>
            ) : (
              <span className="text-black/60">Already have an account? <button onClick={() => { setAuthMode('login'); setAuthError(''); }} className="text-purple-600 hover:underline">Log in</button></span>
            )}
          </div>
        </div>
      </div>
    );
  };

  // ---------------------------------------------------------
  // TOP NAVIGATION BAR (NEO-BRUTALISM)
  // ---------------------------------------------------------

  const navTabs = [
    'Overview',
    'Console',
    'Dashboard',
    'History',
    ...(isLoggedIn ? ['My Reports'] : []),
    ...(isLoggedIn && user?.role === 'admin' ? ['Admin Security'] : [])
  ];

  return (
    <div className="h-[100dvh] w-full flex flex-col bg-slate-50 text-slate-900 overflow-hidden">
      
      {/* Top Purple Banner */}
      <div className="bg-purple-200 text-center py-2 text-sm font-bold border-b-2 border-black">
        Aegis is live. <a href="#" className="underline hover:text-purple-700">See what's new for the 2026 security audits →</a>
      </div>

      {/* Main Header */}
      <header className="bg-white border-b-2 border-black px-4 md:px-6 py-4 flex flex-col lg:flex-row items-center justify-between shrink-0 gap-4">
        
        {/* Left: Logo & Nav */}
        <div className="flex flex-col sm:flex-row items-center justify-between w-full lg:w-auto gap-4 md:gap-8">
          <div className="bg-black text-white px-4 py-2 rounded-lg flex items-center gap-2 neo-hover cursor-pointer shrink-0" onClick={() => setActiveTab('Overview')}>
            <Shield className="w-5 h-5 fill-white" />
            <span className="font-heading font-black text-xl tracking-tight">aegis.ai</span>
          </div>
          
          <nav className="flex items-center gap-3 md:gap-5 font-bold text-xs sm:text-sm overflow-x-auto scrollbar-hide w-full sm:w-auto pb-1 sm:pb-0 justify-center">
            {navTabs.map(tab => (
              <button 
                key={tab} 
                onClick={() => setActiveTab(tab)}
                className={`hover:text-purple-600 transition-colors whitespace-nowrap ${activeTab === tab ? 'border-b-2 border-black pb-1' : ''}`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>

        {/* Right: Search & Actions */}
        <div className="flex flex-wrap items-center justify-center gap-3 w-full lg:w-auto">
          <div className="hidden xl:flex items-center bg-white neo-border rounded-full px-4 py-2 focus-within:ring-2 ring-black">
            <Search className="w-4 h-4 text-black/50 mr-2" />
            <input type="text" placeholder="search logs, policies..." className="border-none outline-none text-sm font-bold w-64" />
            <div className="bg-slate-200 text-xs px-1.5 py-0.5 rounded border border-black font-mono">⌘K</div>
          </div>
          
          <button onClick={() => setActiveTab('Console')} className="hidden sm:block bg-cyan-100 neo-border neo-hover px-4 md:px-5 py-2 rounded-full font-bold text-xs md:text-sm">
            diagnostic
          </button>
          
          {!isLoggedIn ? (
            <div className="flex items-center gap-2">
              <button onClick={() => { setAuthMode('login'); setShowAuthModal(true); }} className="flex items-center gap-1 md:gap-2 font-bold text-xs md:text-sm hover:text-purple-600 px-2 md:px-3">
                <UserCircle className="w-4 h-4 md:w-5 md:h-5" /> log in
              </button>
              <button onClick={() => { setAuthMode('signup'); setShowAuthModal(true); }} className="bg-black text-white neo-hover border-2 border-transparent px-4 md:px-5 py-2 rounded-full font-bold text-xs md:text-sm">
                sign up
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 md:gap-4 pl-0 sm:pl-4 sm:border-l-2 border-black/10">
              <div className="flex items-center gap-1 md:gap-2 font-bold text-xs md:text-sm truncate max-w-[150px] md:max-w-xs">
                <div className="bg-purple-200 p-1 md:p-1.5 rounded-full neo-border shrink-0"><UserCircle className="w-3.5 h-3.5 md:w-4 md:h-4 text-purple-800" /></div>
                <div className="truncate flex flex-col">
                  <span className="truncate text-xs">{user?.name || 'Mohd Ali Khan'}</span>
                  <span className="text-[9px] font-mono font-normal uppercase text-purple-700 tracking-wide">{user?.role || 'employee'}</span>
                </div>
              </div>
              <button onClick={handleLogout} className="text-xs font-bold text-red-600 hover:bg-red-50 px-2 md:px-3 py-1 md:py-1.5 rounded-full neo-border transition-colors shrink-0">
                Sign Out
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Auth Modal Overlay */}
      {renderAuthModal()}

      {/* Main Content View */}
      <main className="flex-1 flex flex-col min-h-0 relative">
        {activeTab === 'Overview' && renderOverview()}
        {activeTab === 'Console' && renderConsole()}
        {activeTab === 'Dashboard' && renderDashboard()}
        {activeTab === 'History' && renderHistory()}
        {activeTab === 'Report' && renderReport()}
        {activeTab === 'My Reports' && (
          <EmployeeReports token={localStorage.getItem('token')} user={user} socket={socket} />
        )}
        {activeTab === 'Admin Security' && (
          <AdminSecurityDashboard token={localStorage.getItem('token')} user={user} socket={socket} />
        )}
      </main>

    </div>
  );
}

export default App;
