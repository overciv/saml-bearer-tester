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

// ─── Protocol toggle ──────────────────────────────────────────────────────────
let currentProtocol = 'oidc';

function setProtocol(proto) {
  currentProtocol = proto;
  document.getElementById('oidcFields').style.display = proto === 'oidc' ? '' : 'none';
  document.getElementById('samlFields').style.display  = proto === 'saml' ? '' : 'none';
  document.getElementById('protoOidcBtn').style.cssText = proto === 'oidc'
    ? 'background:rgba(61,203,122,0.1);color:var(--emerald);border:1px solid rgba(61,203,122,0.3)'
    : 'color:var(--text-muted);border:1px solid var(--border)';
  document.getElementById('protoSamlBtn').style.cssText = proto === 'saml'
    ? 'background:rgba(61,203,122,0.1);color:var(--emerald);border:1px solid rgba(61,203,122,0.3)'
    : 'color:var(--text-muted);border:1px solid var(--border)';
  document.getElementById('payloadPreviewSection').style.display = 'none';
  document.getElementById('createAppOutput').style.display = 'none';
}

// SAML attribute rows
let samlAttrCount = 0;
function addSamlAttr(name = '', value = '', format = 'basic') {
  samlAttrCount++;
  const id = samlAttrCount;
  const row = document.createElement('div');
  row.id = `samlAttr_${id}`;
  row.className = 'd-flex gap-2 mb-2 align-items-center';
  row.innerHTML = `
    <input type="text" class="form-control sa-name" placeholder="Attribute name (e.g. email)" value="${escHtml(name)}" style="flex:1">
    <input type="text" class="form-control sa-value" placeholder="Okta expression (e.g. \${user.email})" value="${escHtml(value)}" style="flex:1.5">
    <select class="form-select sa-format" style="width:180px;flex-shrink:0">
      <option value="basic" ${format==='basic'?'selected':''}>basic</option>
      <option value="uri" ${format==='uri'?'selected':''}>uri reference</option>
      <option value="unspecified" ${format==='unspecified'?'selected':''}>unspecified</option>
    </select>
    <button class="btn btn-outline-secondary btn-sm" onclick="document.getElementById('samlAttr_${id}').remove()" style="flex-shrink:0"><i class="bi bi-trash"></i></button>`;
  document.getElementById('samlAttrRows').appendChild(row);
}

function collectSamlAttrs() {
  return Array.from(document.querySelectorAll('#samlAttrRows > div')).map(row => ({
    type: 'EXPRESSION',
    name: row.querySelector('.sa-name')?.value?.trim() || '',
    values: [row.querySelector('.sa-value')?.value?.trim() || ''],
    namespace: `urn:oasis:names:tc:SAML:2.0:attrname-format:${row.querySelector('.sa-format')?.value || 'basic'}`
  })).filter(a => a.name && a.values[0]);
}

// ─── Payload builders ─────────────────────────────────────────────────────────
function buildOidcPayload() {
  const grantTypes = [];
  if (document.getElementById('grant_authcode')?.checked)   grantTypes.push('authorization_code');
  if (document.getElementById('grant_refresh')?.checked)    grantTypes.push('refresh_token');
  if (document.getElementById('grant_creds')?.checked)      grantTypes.push('client_credentials');
  if (document.getElementById('grant_device')?.checked)     grantTypes.push('urn:ietf:params:oauth:grant-type:device_code');
  if (document.getElementById('grant_tokex')?.checked)      grantTypes.push('urn:ietf:params:oauth:grant-type:token-exchange');
  if (document.getElementById('grant_saml_grant')?.checked) grantTypes.push('urn:ietf:params:oauth:grant-type:saml2-bearer');

  const responseTypes = grantTypes.includes('authorization_code') ? ['code'] : [];
  return {
    name: 'oidc_client',
    label: val('appLabel') || 'New OIDC App',
    signOnMode: 'OPENID_CONNECT',
    credentials: { oauthClient: { token_endpoint_auth_method: val('appAuthMethod') } },
    settings: {
      oauthClient: {
        redirect_uris: val('appRedirectUris').split('\n').map(s => s.trim()).filter(Boolean),
        grant_types: grantTypes,
        response_types: responseTypes,
        application_type: val('appType')
      }
    }
  };
}

function buildSamlPayload() {
  const acsUrl = val('samlAcsUrl');
  const attrs  = collectSamlAttrs();
  return {
    name: 'template_saml_2_0',
    label: val('appLabel') || 'New SAML App',
    signOnMode: 'SAML_2_0',
    settings: {
      signOn: {
        ssoAcsUrl: acsUrl,
        idpIssuer: 'http://www.okta.com/${org.externalKey}',
        audience: val('samlAudience') || acsUrl,
        recipient: val('samlRecipient') || acsUrl,
        defaultRelayState: val('samlRelayState') || '',
        subjectNameIdTemplate: val('samlNameIdTemplate') || '${user.userName}',
        subjectNameIdFormat: val('samlNameIdFormat'),
        authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        requestCompressed: false,
        assertionSigned: true,
        signatureAlgorithm: 'RSA_SHA256',
        digestAlgorithm: 'SHA256',
        honorForceAuthn: true,
        responseSigned: true,
        allowMultipleAcsEndpoints: false,
        samlSignedRequestEnabled: false,
        attributeStatements: attrs
      }
    }
  };
}

// ─── Step 1: Generate payload preview ────────────────────────────────────────
function generateAppPayload() {
  if (!val('appLabel')) { toast('Enter an App Label first', 'warning'); return; }
  if (currentProtocol === 'saml' && !val('samlAcsUrl')) { toast('ACS URL is required for SAML apps', 'warning'); return; }

  const payload = currentProtocol === 'oidc' ? buildOidcPayload() : buildSamlPayload();
  document.getElementById('payloadTextarea').value = JSON.stringify(payload, null, 2);
  document.getElementById('payloadPreviewSection').style.display = '';
  document.getElementById('payloadTextarea').scrollIntoView({ behavior: 'smooth', block: 'center' });
  toast('Payload generated — review and edit, then click Send', 'info');
}

// ─── Step 2: Send request ─────────────────────────────────────────────────────
async function sendAppRequest() {
  const btn = document.getElementById('sendAppBtn');
  setLoading(btn, true, '<i class="bi bi-send-fill me-1"></i>Sending…');

  let payload;
  try { payload = JSON.parse(document.getElementById('payloadTextarea').value); }
  catch { toast('Invalid JSON in the payload editor — fix it before sending', 'error'); setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send to Okta'); return; }

  const isOidc = payload.signOnMode === 'OPENID_CONNECT';

  try {
    const res = await fetch('/api/admin/create-app', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(adminParams({ ...payload, _rawPayload: true }))
    }).then(r => r.json());

    document.getElementById('createAppOutput').style.display = '';
    document.getElementById('createAppStatus').innerHTML =
      `${statusBadge(res.statusCode)}<span style="font-size:0.75rem;color:var(--text-muted);margin-left:8px">${res.durationMs}ms</span>
       ${res.success ? `<code style="font-size:0.75rem;color:var(--emerald);margin-left:8px">${escHtml(res.response?.id || '')}</code>` : ''}`;
    document.getElementById('createResponseEl').textContent = JSON.stringify(res.response || res.error, null, 2);
    showCreateTab('response');

    if (res.success) {
      const appId = res.response.id;
      const appName = payload.name; // 'oidc_client' or 'template_saml_2_0'
      toast(`App created! ID: ${appId}`, 'success');

      // Assign owner if set
      const ownerLogin = val('appOwner');
      if (ownerLogin) await assignAppOwner(appId, appName, ownerLogin);
    } else {
      toast('Creation failed: ' + (res.response?.errorSummary || `HTTP ${res.statusCode}`), 'error');
    }
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send to Okta');
  }
}

// ─── Owner assignment ──────────────────────────────────────────────────────────
async function assignAppOwner(appId, appName, ownerLogin) {
  showCreateTab('owner');
  const resultEl = document.getElementById('ownerAssignmentResult');
  const detailEl = document.getElementById('ownerAssignmentDetails');
  resultEl.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Assigning ${escHtml(ownerLogin)} as APP_ADMIN for this app…`;

  try {
    const res = await fetch('/api/admin/assign-app-owner', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(adminParams({ login: ownerLogin, appId, appName }))
    }).then(r => r.json());

    if (res.success) {
      resultEl.innerHTML = `<i class="bi bi-check-circle-fill me-2" style="color:var(--green)"></i>
        <strong style="color:var(--green)">Owner assigned</strong> — ${escHtml(ownerLogin)} now has
        <strong>APP_ADMIN</strong> role scoped to this application only (role ID: <code>${escHtml(res.roleId || '—')}</code>)`;
      toast('App owner assigned successfully', 'success');
    } else {
      resultEl.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2" style="color:var(--yellow)"></i>
        <strong style="color:var(--yellow)">Owner assignment failed</strong>: ${escHtml(res.error || `HTTP ${res.statusCode}`)}`;
      toast('Owner assignment failed — see Owner Assignment tab', 'warning');
    }

    detailEl.textContent = JSON.stringify(res, null, 2);
    detailEl.style.display = '';
  } catch (e) {
    resultEl.innerHTML = `<i class="bi bi-x-circle me-2" style="color:var(--red)"></i>${escHtml(e.message)}`;
    toast('Owner assignment error: ' + e.message, 'error');
  }
}

function showCreateTab(tab) {
  ['response', 'owner'].forEach((t, i) => {
    document.getElementById(`createTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#createAppTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
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
