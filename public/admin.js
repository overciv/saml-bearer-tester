'use strict';

let currentUserId = null;
let exportedAppData = null;

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  // Pre-fill from server settings
  fetch('/api/settings').then(r => r.json()).then(s => {
    if (s.oktaDomain)    document.getElementById('adminDomain').value = s.oktaDomain;
    if (s.adminApiToken) document.getElementById('adminToken').value  = s.adminApiToken;
  }).catch(() => {});

  // Default "since" = 1 hour ago
  const oneHourAgo = new Date(Date.now() - 3600000);
  const iso = oneHourAgo.toISOString().slice(0, 16);
  document.getElementById('logSince').value = iso;
});

function adminParams(extra = {}) {
  return { oktaDomain: val('adminDomain'), adminApiToken: document.getElementById('adminToken')?.value || '', ...extra };
}

// ─── App Lifecycle ─────────────────────────────────────────────────────────────
function showAppTab(tab) {
  ['create','export','clone'].forEach((t,i) => {
    document.getElementById(`appTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#appTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

function showCreateTab(tab) {
  document.getElementById('createTabPayload').style.display = tab==='payload'?'':'none';
  document.getElementById('createTabResponse').style.display = tab==='response'?'':'none';
  document.querySelectorAll('#createAppTabs .tab-btn').forEach((b,i) => b.classList.toggle('active', ['payload','response'][i]===tab));
}

async function createApp() {
  const btn = document.getElementById('createAppBtn');
  setLoading(btn, true, '<i class="bi bi-plus-circle me-1"></i>Creating…');

  const grantTypes = [];
  if (document.getElementById('grant_authcode')?.checked) grantTypes.push('authorization_code');
  if (document.getElementById('grant_refresh')?.checked)  grantTypes.push('refresh_token');
  if (document.getElementById('grant_creds')?.checked)    grantTypes.push('client_credentials');
  if (document.getElementById('grant_device')?.checked)   grantTypes.push('urn:ietf:params:oauth:grant-type:device_code');
  if (document.getElementById('grant_tokex')?.checked)    grantTypes.push('urn:ietf:params:oauth:grant-type:token-exchange');
  if (document.getElementById('grant_saml')?.checked)     grantTypes.push('urn:ietf:params:oauth:grant-type:saml2-bearer');

  try {
    const res = await post('/api/admin/create-app', adminParams({
      label: val('appLabel'),
      applicationType: val('appType'),
      tokenEndpointAuthMethod: val('appAuthMethod'),
      redirectUris: val('appRedirectUris').split('\n').map(s => s.trim()).filter(Boolean),
      grantTypes
    }));

    document.getElementById('createAppOutput').style.display = '';
    document.getElementById('createAppStatus').innerHTML =
      `${statusBadge(res.statusCode)}<span style="font-size:0.75rem;color:var(--text-muted);margin-left:8px">${res.durationMs}ms</span>`;
    document.getElementById('createPayloadEl').textContent = JSON.stringify(res.payload, null, 2);
    document.getElementById('createResponseEl').textContent = JSON.stringify(res.response, null, 2);
    showCreateTab('payload');

    if (res.success) {
      const cid = res.response?.credentials?.oauthClient?.client_id || res.response?.id;
      toast(`App created! client_id: ${cid}`, 'success');
    } else {
      toast('Creation failed: ' + (res.response?.errorSummary || `HTTP ${res.statusCode}`), 'error');
    }
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-plus-circle me-1"></i>Create App via API');
  }
}

async function exportApp() {
  const btn = document.getElementById('exportAppBtn');
  setLoading(btn, true, '<i class="bi bi-download me-1"></i>Exporting…');
  try {
    const res = await post('/api/admin/get-app', adminParams({ appId: val('exportAppId') }));
    if (!res.success) { toast('Export failed: ' + (res.response?.errorSummary || `HTTP ${res.statusCode}`), 'error'); return; }
    exportedAppData = res.response;
    document.getElementById('exportAppOutput').style.display = '';
    document.getElementById('exportAppJson').textContent = JSON.stringify(res.response, null, 2);
    toast(`Exported: ${res.response.label}`, 'success');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-download me-1"></i>Export App Config');
  }
}

function downloadExportedApp() {
  if (!exportedAppData) return;
  const blob = new Blob([JSON.stringify(exportedAppData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `${exportedAppData.label || 'app'}-config.json`;
  a.click();
}

async function cloneApp() {
  const btn = document.getElementById('cloneAppBtn');
  setLoading(btn, true, '<i class="bi bi-copy me-1"></i>Cloning…');
  try {
    const res = await post('/api/admin/clone-app', adminParams({ sourceAppId: val('cloneSourceId'), newLabel: val('cloneLabel') }));
    document.getElementById('cloneAppOutput').style.display = '';
    document.getElementById('cloneAppStatus').innerHTML = `${statusBadge(res.statusCode)}<span style="font-size:0.75rem;color:var(--text-muted);margin-left:8px">${res.durationMs}ms</span>`;
    document.getElementById('cloneAppJson').textContent = JSON.stringify(res.response || res.error, null, 2);
    if (res.success) toast(`Cloned as: ${res.response?.label} (${res.response?.id})`, 'success');
    else toast('Clone failed: ' + (res.response?.errorSummary || `HTTP ${res.statusCode}`), 'error');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-copy me-1"></i>Clone App');
  }
}

// ─── MFA ───────────────────────────────────────────────────────────────────────
async function findUser() {
  const btn = document.getElementById('findUserBtn');
  setLoading(btn, true, '<i class="bi bi-search me-1"></i>Finding…');
  try {
    const res = await post('/api/admin/find-user', adminParams({ login: val('mfaUserLogin') }));
    if (!res.success) { toast('User not found: ' + (res.response?.errorSummary || `HTTP ${res.statusCode}`), 'error'); return; }

    const u = res.response;
    currentUserId = u.id;
    document.getElementById('mfaUserInfo').style.display = '';
    document.getElementById('mfaUserCard').innerHTML =
      `<strong>${escHtml(u.profile?.displayName || u.profile?.login)}</strong>
       <span style="color:var(--text-muted);margin:0 10px">·</span>${escHtml(u.profile?.login)}
       <span style="color:var(--text-muted);margin:0 10px">·</span>
       <span class="status-badge ${u.status === 'ACTIVE' ? 'status-ok' : 'status-err'}">${escHtml(u.status)}</span>
       <span style="color:var(--text-muted);font-size:0.72rem;margin-left:10px">id: ${escHtml(u.id)}</span>`;

    await refreshFactors();
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-search me-1"></i>Find User');
  }
}

async function refreshFactors() {
  if (!currentUserId) return;
  try {
    const res = await post('/api/admin/list-factors', adminParams({ userId: currentUserId }));
    if (!res.success) { toast('Failed to list factors', 'error'); return; }
    renderFactors(res.response || []);
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  }
}

function renderFactors(factors) {
  const tbody = document.getElementById('factorTableBody');
  if (!factors.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted);text-align:center;padding:20px">No factors enrolled</td></tr>';
    return;
  }
  const factorLabels = { token_software_totp:'TOTP (Authenticator)', token_hardware:'Hardware (YubiKey)', push:'Push (Okta Verify)', signed_nonce:'Signed Nonce', question:'Security Question', email:'Email OTP', sms:'SMS', call:'Voice Call', webauthn:'WebAuthn / FIDO2', password:'Password' };
  tbody.innerHTML = factors.map(f => `<tr>
    <td><strong>${escHtml(factorLabels[f.factorType] || f.factorType)}</strong></td>
    <td style="color:var(--text-muted);font-size:0.75rem">${escHtml(f.provider)}</td>
    <td><span class="${f.status === 'ACTIVE' ? 'factor-status-active' : 'factor-status-inactive'}">${escHtml(f.status)}</span></td>
    <td style="color:var(--text-muted);font-size:0.75rem">${f.created ? new Date(f.created).toLocaleDateString() : '—'}</td>
    <td>
      <button class="btn btn-outline-secondary btn-sm" style="color:var(--red);border-color:var(--red);font-size:0.72rem" onclick="resetFactor('${escHtml(f.id)}','${escHtml(factorLabels[f.factorType]||f.factorType)}')">
        <i class="bi bi-trash me-1"></i>Reset
      </button>
    </td>
  </tr>`).join('');
}

async function resetFactor(factorId, label) {
  if (!confirm(`Reset factor "${label}" for this user? The user will need to re-enroll.`)) return;
  try {
    const res = await post('/api/admin/reset-factor', adminParams({ userId: currentUserId, factorId }));
    if (res.success) { toast(`Factor "${label}" reset successfully`, 'success'); await refreshFactors(); }
    else toast('Reset failed: ' + `HTTP ${res.statusCode}`, 'error');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  }
}

// ─── System Log ────────────────────────────────────────────────────────────────
async function fetchSystemLog() {
  const btn = document.getElementById('fetchLogBtn');
  setLoading(btn, true, '<i class="bi bi-arrow-clockwise me-1"></i>Fetching…');
  try {
    const since = document.getElementById('logSince')?.value;
    const until = document.getElementById('logUntil')?.value;
    const res = await post('/api/admin/system-log', adminParams({
      since: since ? new Date(since).toISOString() : undefined,
      until: until ? new Date(until).toISOString() : undefined,
      limit: parseInt(val('logLimit')) || 25,
      filter: val('logFilter') || undefined,
      q: val('logQ') || undefined
    }));

    document.getElementById('logOutput').style.display = '';

    if (!res.success) { toast(`Log fetch failed: HTTP ${res.statusCode}`, 'error'); return; }

    const events = res.response || [];
    document.getElementById('logSummary').innerHTML =
      `<span class="status-badge status-ok">${events.length} events</span>
       <span style="color:var(--text-muted);font-size:0.75rem">${res.durationMs}ms</span>
       ${res.nextLink ? '<span style="color:var(--text-muted);font-size:0.75rem">· next page available</span>' : ''}`;

    document.getElementById('logRawJson').textContent = JSON.stringify(events, null, 2);
    renderLogTimeline(events);
    showLogTab('timeline');
    toast(`${events.length} log events loaded`, 'success');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-arrow-clockwise me-1"></i>Fetch Logs');
  }
}

function renderLogTimeline(events) {
  const el = document.getElementById('logTimeline');
  if (!events.length) { el.innerHTML = '<div style="color:var(--text-muted);font-size:0.82rem">No events found for the given filters.</div>'; return; }

  el.innerHTML = events.map(e => {
    const outcome = e.outcome?.result || 'UNKNOWN';
    const cls = outcome === 'SUCCESS' ? 'success' : outcome === 'FAILURE' ? 'failure' : 'unknown';
    const time = e.published ? new Date(e.published).toLocaleString() : '—';
    const actor = e.actor?.displayName || e.actor?.alternateId || '—';
    const target = (e.target || []).map(t => t.displayName || t.alternateId).join(', ') || '—';
    const app = e.client?.userAgent?.rawUserAgent ? '' : (e.debugContext?.debugData?.requestId ? '' : '');
    const clientApp = (e.target || []).find(t => t.type === 'AppInstance')?.displayName || '';

    return `<div class="log-entry ${cls}">
      <div class="log-time">${escHtml(time)}</div>
      <div class="log-event">${escHtml(e.eventType || '—')}</div>
      <div class="d-flex gap-3 flex-wrap mt-1">
        <span class="log-actor"><i class="bi bi-person me-1"></i>${escHtml(actor)}</span>
        ${target !== '—' ? `<span class="log-target"><i class="bi bi-bullseye me-1"></i>${escHtml(target)}</span>` : ''}
        ${clientApp ? `<span style="color:var(--purple);font-size:0.75rem"><i class="bi bi-app me-1"></i>${escHtml(clientApp)}</span>` : ''}
        <span class="status-badge ${cls === 'success' ? 'status-ok' : cls === 'failure' ? 'status-err' : ''}" style="font-size:0.65rem">${escHtml(outcome)}</span>
      </div>
    </div>`;
  }).join('');
}

function showLogTab(tab) {
  document.getElementById('logTabTimeline').style.display = tab==='timeline'?'':'none';
  document.getElementById('logTabRaw').style.display = tab==='raw'?'':'none';
  document.querySelectorAll('#logTabs .tab-btn').forEach((b,i) => b.classList.toggle('active', ['timeline','raw'][i]===tab));
}
