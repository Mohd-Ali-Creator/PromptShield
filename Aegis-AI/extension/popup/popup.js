/**
 * PromptShield AI - Extension Popup Controller
 * 
 * Synchronizes user preferences, real-time protection state,
 * local storage metrics, and Aegis-AI Cloud Gateway telemetry.
 * 
 * Strict Zero-Knowledge Privacy: Never displays or logs raw prompts,
 * secret tokens, or sensitive credentials.
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Element References ---
  // Header
  const connStatusBadge = document.getElementById('conn-status-badge');
  const connStatusDot = document.getElementById('conn-status-dot');
  const connStatusText = document.getElementById('conn-status-text');
  const refreshBtn = document.getElementById('refresh-btn');
  const refreshIcon = document.getElementById('refresh-icon');

  // Error Banner
  const errorBanner = document.getElementById('error-banner');
  const errorBannerText = document.getElementById('error-banner-text');
  const errorCloseBtn = document.getElementById('error-close-btn');

  // Guardrail Status Card
  const guardrailDot = document.getElementById('guardrail-indicator-dot');
  const guardrailStatusText = document.getElementById('guardrail-status-text');
  const protectionToggle = document.getElementById('protection-toggle');
  const employeeDisplayVal = document.getElementById('employee-display-val');
  const orgDisplayVal = document.getElementById('org-display-val');
  const policySyncTag = document.getElementById('policy-sync-tag');
  const policySyncTime = document.getElementById('policy-sync-time');
  const modeSelect = document.getElementById('mode-select');

  // Security Metrics
  const metricScanned = document.getElementById('metric-scanned');
  const metricScannedSub = document.getElementById('metric-scanned-sub');
  const metricBlocked = document.getElementById('metric-blocked');
  const metricBlockedSub = document.getElementById('metric-blocked-sub');
  const metricWarned = document.getElementById('metric-warned');
  const metricWarnedSub = document.getElementById('metric-warned-sub');
  const metricSanitized = document.getElementById('metric-sanitized');
  const metricSanitizedSub = document.getElementById('metric-sanitized-sub');
  const metricsSourceNote = document.getElementById('metrics-source-note');

  // Connection Panel
  const connPanelBadge = document.getElementById('conn-panel-badge');
  const connDisconnectedView = document.getElementById('conn-disconnected-view');
  const connConnectedView = document.getElementById('conn-connected-view');
  const aegisTokenInput = document.getElementById('aegis-token-input');
  const aegisConnectBtn = document.getElementById('aegis-connect-btn');
  const connectBtnText = document.getElementById('connect-btn-text');
  const connectSpinner = document.getElementById('connect-spinner');
  const userAvatarChar = document.getElementById('user-avatar-char');
  const userNameText = document.getElementById('user-name-text');
  const userOrgText = document.getElementById('user-org-text');
  const syncPoliciesBtn = document.getElementById('sync-policies-btn');
  const aegisDisconnectBtn = document.getElementById('aegis-disconnect-btn');

  // Incidents
  const incidentsList = document.getElementById('incidents-list');
  const clearLogBtn = document.getElementById('clear-log-btn');

  // Quick Actions
  const openReportsBtn = document.getElementById('open-reports-btn');
  const openSandboxBtn = document.getElementById('open-sandbox-btn');

  // --- Constants & Defaults ---
  const DEFAULT_BACKEND_URL = 'http://localhost:4000';
  const DEFAULT_FRONTEND_URL = 'http://localhost:5173';
  const BUILTIN_RULE_COUNT = 10;

  // --- State Initialization ---
  loadAndRenderState();

  // --- Event Listeners ---

  // Dismiss Error Banner
  if (errorCloseBtn) {
    errorCloseBtn.addEventListener('click', () => {
      hideError();
    });
  }

  // Real-Time Protection Master Toggle
  if (protectionToggle) {
    protectionToggle.addEventListener('change', () => {
      const isEnabled = protectionToggle.checked;
      updateGuardrailUI(isEnabled);

      chrome.storage.local.set({ promptshield_enabled: isEnabled }, () => {
        if (chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            type: 'PROMPTSHIELD_TOGGLE_STATE',
            enabled: isEnabled
          }).catch(() => {});
        }
      });
    });
  }

  // Enforcement Mode Selector
  if (modeSelect) {
    modeSelect.addEventListener('change', () => {
      chrome.storage.local.set({ promptshield_mode: modeSelect.value });
    });
  }

  // Refresh Button
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      triggerRefreshAnimation();
      loadAndRenderState(true);
    });
  }

  // Connect to Aegis Platform
  if (aegisConnectBtn) {
    aegisConnectBtn.addEventListener('click', async () => {
      const token = (aegisTokenInput?.value || '').trim();
      if (!token) {
        showError('Please paste your Aegis-AI JWT token. (Find it in My Reports → Copy Extension Token)');
        return;
      }

      setConnectingState(true);
      hideError();

      try {
        const stored = await getStorageData(['aegis_backend_url']);
        const backendUrl = stored.aegis_backend_url || DEFAULT_BACKEND_URL;

        const res = await fetch(`${backendUrl}/api/extension/status`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (!res.ok) {
          if (res.status === 401 || res.status === 403) {
            throw new Error('Authentication rejected. Invalid or expired token.');
          }
          throw new Error(`Server returned HTTP ${res.status}`);
        }

        const data = await res.json();
        const profile = data.user || { name: 'Employee', organizationName: 'Organization' };

        // Save authenticated state
        await setStorageData({
          aegis_auth_token: token,
          aegis_backend_url: backendUrl,
          aegis_user_profile: profile,
          promptshield_sync_enabled: true
        });

        // Clear sensitive token input
        if (aegisTokenInput) aegisTokenInput.value = '';

        // Sync rules immediately
        await syncPolicies(backendUrl, token);

        // Re-render UI
        await loadAndRenderState(false);
      } catch (err) {
        showError(`Connection failed: ${err.message}. Verify Aegis-AI gateway is running at http://localhost:4000.`);
      } finally {
        setConnectingState(false);
      }
    });
  }

  // Disconnect from Aegis Platform
  if (aegisDisconnectBtn) {
    aegisDisconnectBtn.addEventListener('click', () => {
      chrome.storage.local.remove(['aegis_auth_token', 'aegis_user_profile'], () => {
        hideError();
        loadAndRenderState(false);
      });
    });
  }

  // Sync Policies Action
  if (syncPoliciesBtn) {
    syncPoliciesBtn.addEventListener('click', async () => {
      syncPoliciesBtn.disabled = true;
      const originalText = syncPoliciesBtn.innerHTML;
      syncPoliciesBtn.innerHTML = '<span>Syncing...</span>';

      try {
        const data = await getStorageData(['aegis_auth_token', 'aegis_backend_url']);
        if (!data.aegis_auth_token) {
          showError('Cannot sync policies: Not enrolled in an Aegis organization.');
          return;
        }
        const backendUrl = data.aegis_backend_url || DEFAULT_BACKEND_URL;
        await syncPolicies(backendUrl, data.aegis_auth_token);
        await loadAndRenderState(false);
      } catch (err) {
        showError(`Policy sync failed: ${err.message}`);
      } finally {
        syncPoliciesBtn.disabled = false;
        syncPoliciesBtn.innerHTML = originalText;
      }
    });
  }

  // Clear Local Incident History
  if (clearLogBtn) {
    clearLogBtn.addEventListener('click', () => {
      chrome.storage.local.set({
        promptshield_incidents: [],
        promptshield_blocked_count: 0
      }, () => {
        metricBlocked.textContent = '0';
        renderIncidents([]);
        if (chrome.action && chrome.action.setBadgeText) {
          chrome.action.setBadgeText({ text: protectionToggle.checked ? 'ON' : 'OFF' });
        }
      });
    });
  }

  // Quick Action: Open My Reports
  if (openReportsBtn) {
    openReportsBtn.addEventListener('click', async () => {
      const data = await getStorageData(['aegis_frontend_url']);
      const frontendUrl = (data.aegis_frontend_url || DEFAULT_FRONTEND_URL).replace(/\/$/, '');
      const reportsUrl = `${frontendUrl}/reports`;
      chrome.tabs.create({ url: reportsUrl });
    });
  }

  // Quick Action: Open Test Sandbox
  if (openSandboxBtn) {
    openSandboxBtn.addEventListener('click', () => {
      const sandboxUrl = chrome.runtime.getURL('sandbox/test-harness.html');
      chrome.tabs.create({ url: sandboxUrl });
    });
  }

  // --- Core State Loader & Renderer ---
  async function loadAndRenderState(isManualRefresh = false) {
    const keys = [
      'promptshield_enabled',
      'promptshield_mode',
      'promptshield_blocked_count',
      'promptshield_scanned_count',
      'promptshield_incidents',
      'aegis_auth_token',
      'aegis_user_profile',
      'aegis_backend_url',
      'aegis_frontend_url',
      'promptshield_company_rules',
      'promptshield_last_policy_sync'
    ];

    const data = await getStorageData(keys);

    const isEnabled = data.promptshield_enabled !== false;
    const mode = data.promptshield_mode || 'STRICT';
    const localBlocked = data.promptshield_blocked_count || 0;
    const localScanned = data.promptshield_scanned_count;
    const localIncidents = data.promptshield_incidents || [];
    const token = data.aegis_auth_token;
    const userProfile = data.aegis_user_profile;
    const backendUrl = data.aegis_backend_url || DEFAULT_BACKEND_URL;
    const companyRules = data.promptshield_company_rules || [];
    const lastSyncTime = data.promptshield_last_policy_sync;

    // 1. Guardrail Switch & Mode
    if (protectionToggle) protectionToggle.checked = isEnabled;
    updateGuardrailUI(isEnabled);
    if (modeSelect) modeSelect.value = mode;

    // 2. Policies Tag & Timestamp
    updatePoliciesUI(companyRules, lastSyncTime);

    // 3. Connection & Metrics Sync
    if (token) {
      setConnectionStatus('checking', 'Connecting...');
      try {
        // Verify connectivity & update profile
        const statusRes = await fetch(`${backendUrl}/api/extension/status`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!statusRes.ok) {
          if (statusRes.status === 401 || statusRes.status === 403) {
            throw new Error('Session expired. Please reconnect your extension token.');
          }
          throw new Error(`Gateway returned HTTP ${statusRes.status}`);
        }

        const statusData = await statusRes.json();
        const activeProfile = statusData.user || userProfile || {};

        // Fetch real aggregated reports summary from gateway
        let cloudSummary = null;
        let cloudIncidents = [];
        try {
          const reportsRes = await fetch(`${backendUrl}/api/reports/employee?limit=10`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (reportsRes.ok) {
            const reportsData = await reportsRes.json();
            cloudSummary = reportsData.summary;
            cloudIncidents = reportsData.incidents || [];
          }
        } catch {
          // Cloud reports fetch non-fatal; fall back gracefully
        }

        // Successfully connected!
        setConnectionStatus('connected', 'Connected');
        renderConnectedView(activeProfile);

        // Render Real Metrics
        renderMetrics({
          scanned: localScanned !== undefined ? localScanned : 0,
          blocked: cloudSummary ? Math.max(cloudSummary.blocked, localBlocked) : localBlocked,
          warned: cloudSummary ? cloudSummary.warned : countLocalByAction(localIncidents, 'WARNED', 'MEDIUM'),
          sanitized: cloudSummary ? cloudSummary.redacted : countLocalByAction(localIncidents, 'REDACTED'),
          isCloud: Boolean(cloudSummary)
        });

        // Merge and render incidents (prefer cloud enriched or local)
        const combinedIncidents = cloudIncidents.length > 0 ? cloudIncidents : localIncidents;
        renderIncidents(combinedIncidents);

        if (isManualRefresh) {
          hideError();
        }
      } catch (err) {
        // Disconnected due to gateway offline or expired token
        setConnectionStatus('disconnected', 'Offline');
        renderDisconnectedView();
        showError(`Gateway unreachable: ${err.message}. Local guardrail protection remains 100% active.`);

        // Render Local Metrics
        renderMetrics({
          scanned: localScanned !== undefined ? localScanned : 0,
          blocked: localBlocked,
          warned: countLocalByAction(localIncidents, 'WARNED', 'MEDIUM'),
          sanitized: countLocalByAction(localIncidents, 'REDACTED'),
          isCloud: false
        });

        renderIncidents(localIncidents);
      }
    } else {
      // Stand-alone / Not enrolled
      setConnectionStatus('disconnected', 'Disconnected');
      renderDisconnectedView();

      renderMetrics({
        scanned: localScanned !== undefined ? localScanned : 0,
        blocked: localBlocked,
        warned: countLocalByAction(localIncidents, 'WARNED', 'MEDIUM'),
        sanitized: countLocalByAction(localIncidents, 'REDACTED'),
        isCloud: false
      });

      renderIncidents(localIncidents);
    }
  }

  // --- Helper UI Updaters ---

  function updateGuardrailUI(isEnabled) {
    if (isEnabled) {
      if (guardrailDot) guardrailDot.classList.remove('paused');
      if (guardrailStatusText) guardrailStatusText.textContent = 'Active Protection';
    } else {
      if (guardrailDot) guardrailDot.classList.add('paused');
      if (guardrailStatusText) guardrailStatusText.textContent = 'Paused (Disabled)';
    }
  }

  function updatePoliciesUI(companyRules, lastSyncTime) {
    const compCount = Array.isArray(companyRules) ? companyRules.length : 0;
    if (policySyncTag) {
      if (compCount > 0) {
        policySyncTag.textContent = `${BUILTIN_RULE_COUNT} Built-in + ${compCount} Org`;
      } else {
        policySyncTag.textContent = `${BUILTIN_RULE_COUNT} Built-in Rules`;
      }
    }

    if (policySyncTime) {
      if (lastSyncTime) {
        const d = new Date(lastSyncTime);
        policySyncTime.textContent = `Last sync: ${formatTime(d)}`;
      } else {
        policySyncTime.textContent = 'Last sync: Local Default';
      }
    }
  }

  function setConnectionStatus(type, label) {
    if (!connStatusBadge || !connStatusText) return;

    connStatusBadge.className = 'status-pill-badge';
    if (type === 'connected') {
      connStatusBadge.classList.add('status-connected');
    } else if (type === 'checking') {
      connStatusBadge.classList.add('status-checking');
    } else {
      connStatusBadge.classList.add('status-disconnected');
    }

    connStatusText.textContent = label;
  }

  function renderConnectedView(profile) {
    if (connDisconnectedView) connDisconnectedView.style.display = 'none';
    if (connConnectedView) connConnectedView.style.display = 'block';
    if (connPanelBadge) {
      connPanelBadge.textContent = 'Enrolled';
      connPanelBadge.style.background = '#d1fae5';
      connPanelBadge.style.color = '#065f46';
      connPanelBadge.style.borderColor = '#059669';
    }

    const name = profile.name || 'Enrolled Employee';
    const org = profile.organizationName || 'Organization';
    const role = profile.role || 'Member';

    if (userNameText) userNameText.textContent = name;
    if (userOrgText) userOrgText.textContent = `${capitalize(role)} • ${org}`;
    if (userAvatarChar) userAvatarChar.textContent = (name[0] || 'E').toUpperCase();

    if (employeeDisplayVal) employeeDisplayVal.textContent = name;
    if (orgDisplayVal) orgDisplayVal.textContent = org;
  }

  function renderDisconnectedView() {
    if (connDisconnectedView) connDisconnectedView.style.display = 'block';
    if (connConnectedView) connConnectedView.style.display = 'none';
    if (connPanelBadge) {
      connPanelBadge.textContent = 'Offline';
      connPanelBadge.style.background = '#f1f5f9';
      connPanelBadge.style.color = '#475569';
      connPanelBadge.style.borderColor = '#0f172a';
    }

    if (employeeDisplayVal) employeeDisplayVal.textContent = 'Not Enrolled (Stand-Alone)';
    if (orgDisplayVal) orgDisplayVal.textContent = 'Local Workspace';
  }

  function renderMetrics({ scanned, blocked, warned, sanitized, isCloud }) {
    if (metricScanned) {
      metricScanned.textContent = String(scanned !== undefined && scanned !== null ? scanned : '—');
      if (metricScannedSub) {
        metricScannedSub.textContent = scanned > 0 ? 'Evaluated locally' : 'No prompts sent';
      }
    }

    if (metricBlocked) {
      metricBlocked.textContent = String(blocked !== undefined && blocked !== null ? blocked : 0);
    }

    if (metricWarned) {
      metricWarned.textContent = String(warned !== undefined && warned !== null ? warned : (isCloud ? 0 : '—'));
      if (metricWarnedSub && !isCloud && warned === 0) {
        metricWarnedSub.textContent = 'Connect for cloud data';
      }
    }

    if (metricSanitized) {
      metricSanitized.textContent = String(sanitized !== undefined && sanitized !== null ? sanitized : (isCloud ? 0 : '—'));
      if (metricSanitizedSub && !isCloud && sanitized === 0) {
        metricSanitizedSub.textContent = 'Connect for cloud data';
      }
    }

    if (metricsSourceNote) {
      metricsSourceNote.textContent = isCloud ? 'Live Gateway & Local Extension' : 'Local Extension Storage';
    }
  }

  function renderIncidents(incidents) {
    if (!incidentsList) return;

    if (!Array.isArray(incidents) || incidents.length === 0) {
      incidentsList.innerHTML = `
        <div class="empty-incidents-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" class="empty-icon">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
          <p class="empty-title">No Incidents Recorded</p>
          <p class="empty-desc">Prompts are clean. Zero leaks detected.</p>
        </div>
      `;
      return;
    }

    incidentsList.innerHTML = incidents
      .slice(0, 10)
      .map((inc) => {
        const timeStr = formatTime(new Date(inc.occurredAt || inc.timestamp));
        const sev = escapeHtml(inc.severity || 'MEDIUM');
        const rule = escapeHtml(inc.ruleName || inc.ruleId || 'Security Violation');
        const act = escapeHtml(inc.action || (sev === 'CRITICAL' || sev === 'HIGH' ? 'BLOCKED' : 'WARNED'));

        return `
          <div class="incident-row">
            <div class="incident-meta">
              <span class="incident-rule" title="${rule}">${rule}</span>
              <span class="incident-time">${timeStr}</span>
            </div>
            <div class="incident-badges">
              <span class="badge-sev ${sev}">${sev}</span>
              <span class="badge-action">${act}</span>
            </div>
          </div>
        `;
      })
      .join('');
  }

  // --- API Actions ---

  async function syncPolicies(backendUrl, token) {
    const res = await fetch(`${backendUrl}/api/extension/rules`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) throw new Error(`Rules sync returned HTTP ${res.status}`);
    const data = await res.json();
    const rules = Array.isArray(data.rules) ? data.rules : [];

    await setStorageData({
      promptshield_company_rules: rules,
      promptshield_last_policy_sync: Date.now()
    });
  }

  // --- Utility Functions ---

  function setConnectingState(isConnecting) {
    if (!aegisConnectBtn) return;
    aegisConnectBtn.disabled = isConnecting;
    if (connectBtnText) connectBtnText.textContent = isConnecting ? 'Connecting...' : 'Connect to Aegis';
    if (connectSpinner) connectSpinner.style.display = isConnecting ? 'inline-block' : 'none';
  }

  function triggerRefreshAnimation() {
    if (!refreshIcon) return;
    refreshIcon.classList.add('spinning');
    setTimeout(() => {
      refreshIcon.classList.remove('spinning');
    }, 800);
  }

  function showError(msg) {
    if (!errorBanner || !errorBannerText) return;
    errorBannerText.textContent = msg;
    errorBanner.style.display = 'flex';
  }

  function hideError() {
    if (!errorBanner) return;
    errorBanner.style.display = 'none';
  }

  function countLocalByAction(incidents, action, severityFallback) {
    if (!Array.isArray(incidents)) return 0;
    return incidents.filter((i) => {
      if (i.action === action) return true;
      if (severityFallback && i.severity === severityFallback) return true;
      return false;
    }).length;
  }

  function formatTime(dateObj) {
    if (!dateObj || isNaN(dateObj.getTime())) return 'Recently';
    return dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function getStorageData(keys) {
    return new Promise((resolve) => {
      chrome.storage.local.get(keys, (res) => resolve(res || {}));
    });
  }

  function setStorageData(items) {
    return new Promise((resolve) => {
      chrome.storage.local.set(items, () => resolve());
    });
  }
});
