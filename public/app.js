'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
let currentAssertion = null;
let scopeList = ['openid'];

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadConfig();
  renderScopes();
  setupTokenEndpointPreview();
  setupAutoFill();
});

// Check auth status and show user in navbar (self-contained, no common.js dependency)
async function initNavAuth() {
  const navArea = document.getElementById('navAuthArea');
  if (!navArea) return;
  try {
    const r = await fetch('/api/auth/me');
    if (r.status === 401) {
      window.location.href = '/auth/login?returnTo=' + encodeURIComponent(window.location.pathname);
      return;
    }
    const data = await r.json();
    if (data.user) {
      navArea.innerHTML = `<div class="d-flex align-items-center gap-2">
        <span style="font-size:0.78rem;color:var(--text-muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(data.user.name || data.user.email || data.user.sub)}</span>
        <a href="/auth/logout" class="btn btn-outline-secondary btn-sm" style="font-size:0.72rem;padding:2px 8px;white-space:nowrap">Logout</a>
      </div>`;
    }
  } catch { /* server not ready */ }
}

function setupTokenEndpointPreview() {
  ['oktaDomain', 'authServerId'].forEach(id => {
    document.getElementById(id).addEventListener('input', updateTokenEndpointPreview);
  });
  updateTokenEndpointPreview();
}

function updateTokenEndpointPreview() {
  const domain = document.getElementById('oktaDomain').value.trim();
  const sid = document.getElementById('authServerId').value.trim();
  const el = document.getElementById('tokenEndpointPreview');
  if (!domain) { el.textContent = '—'; return; }
  const ep = sid
    ? `https://${domain}/oauth2/${sid}/v1/token`
    : `https://${domain}/oauth2/v1/token`;
  el.textContent = ep;
  // Auto-fill recipient in assertion step
  const recipient = document.getElementById('recipient');
  if (!recipient.value || recipient.dataset.autoFilled === 'true') {
    recipient.value = ep;
    recipient.dataset.autoFilled = 'true';
  }
}

function setupAutoFill() {
  document.getElementById('recipient').addEventListener('input', (e) => {
    if (e.target.value) e.target.dataset.autoFilled = 'false';
  });
}

// ─── Key Pair Generation ───────────────────────────────────────────────────────
async function generateKeyPair() {
  const btn = document.getElementById('generateKeysBtn');
  setLoading(btn, true, 'Generating... (~2s)');
  try {
    const res = await post('/api/generate-keypair', {});
    document.getElementById('privateKey').value = res.privateKey;
    document.getElementById('certificate').value = res.certificate;
    markNavDone('nav-keys');
    toast('Key pair generated — copy the certificate to Okta IdP config', 'success');
  } catch (e) {
    toast('Key generation failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-shuffle me-1"></i>Generate New Key Pair');
  }
}

// ─── SAML Assertion ────────────────────────────────────────────────────────────
async function generateAssertion() {
  const btn = document.getElementById('generateAssertionBtn');
  setLoading(btn, true, 'Generating...');

  const params = {
    issuer: val('issuer'),
    subject: val('subject'),
    nameIdFormat: val('nameIdFormat'),
    recipient: val('recipient'),
    audience: val('audience'),
    validityMinutes: parseInt(val('validityMinutes')) || 60,
    clockSkewMinutes: parseInt(val('clockSkewMinutes')) || 5,
    authnContextClass: val('authnContextClass'),
    privateKey: val('privateKey'),
    certificate: val('certificate'),
    attributes: collectAttributes()
  };

  const required = ['issuer', 'subject', 'recipient', 'audience', 'privateKey', 'certificate'];
  const missing = required.filter(k => !params[k]);
  if (missing.length) {
    toast('Missing required fields: ' + missing.join(', '), 'warning');
    setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion');
    return;
  }

  try {
    const res = await post('/api/generate-assertion', params);
    currentAssertion = res;

    document.getElementById('assertionXml').textContent = formatXml(res.xml);
    document.getElementById('assertionB64').textContent = res.base64url;
    document.getElementById('assertionOutput').style.display = '';
    showAssertionTab('xml');

    // Pre-fill exchange
    document.getElementById('exchangeAssertion').value = res.base64url;

    markNavDone('nav-assertion');
    scrollTo('step-assertion');
    toast('Assertion generated successfully', 'success');
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion');
  }
}

// ─── Token Exchange ────────────────────────────────────────────────────────────
async function exchangeToken() {
  const btn = document.getElementById('exchangeBtn');
  setLoading(btn, true, 'Exchanging...');

  const params = {
    oktaDomain: val('oktaDomain'),
    authServerId: val('authServerId'),
    clientId: val('clientId'),
    clientSecret: val('clientSecret'),
    scope: [...scopeList],
    assertion: val('exchangeAssertion')
  };

  const required = ['oktaDomain', 'clientId', 'clientSecret', 'assertion'];
  const missing = required.filter(k => !params[k]);
  if (missing.length) {
    toast('Missing: ' + missing.join(', '), 'warning');
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Exchange Token');
    return;
  }
  if (scopeList.length === 0) {
    toast('Add at least one scope (e.g. openid)', 'warning');
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Exchange Token');
    return;
  }

  try {
    const res = await post('/api/exchange-token', params);

    document.getElementById('exchangeResult').style.display = '';

    const statusEl = document.getElementById('exchangeStatus');
    if (res.success) {
      statusEl.innerHTML = `
        <span class="status-badge status-ok"><i class="bi bi-check-circle me-1"></i>HTTP ${res.statusCode} OK</span>
        <span style="font-size:0.75rem; color:var(--text-muted); margin-left:8px">${res.durationMs}ms · ${res.tokenEndpoint}</span>`;
    } else {
      statusEl.innerHTML = `
        <span class="status-badge status-err"><i class="bi bi-x-circle me-1"></i>HTTP ${res.statusCode || 'Error'}</span>
        <span style="font-size:0.75rem; color:var(--text-muted); margin-left:8px">${res.durationMs}ms · ${res.tokenEndpoint}</span>`;
    }

    document.getElementById('requestDetails').textContent =
      JSON.stringify(res.requestDetails, null, 2);

    const raw = res.response || res.error || {};
    document.getElementById('rawResponse').textContent = JSON.stringify(raw, null, 2);

    // Decode tokens
    if (raw.access_token) {
      document.getElementById('accessTokenDecoded').innerHTML = renderJwtDecoded(raw.access_token, 'Access Token');
    }
    if (raw.id_token) {
      document.getElementById('idTokenDecoded').innerHTML = renderJwtDecoded(raw.id_token, 'ID Token');
    }

    showTokenTab('raw');
    markNavDone('nav-exchange');

    if (res.success) {
      toast('Tokens received successfully!', 'success');
      scrollTo('step-exchange');
    } else {
      toast('Token exchange failed — see response for details', 'error');
    }
  } catch (e) {
    toast('Request failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Exchange Token');
  }
}

// ─── Decode Tools ──────────────────────────────────────────────────────────────
async function decodeAssertion() {
  const encoded = val('decodeAssertionInput');
  if (!encoded) { toast('Paste an encoded assertion first', 'warning'); return; }
  try {
    const res = await post('/api/decode-assertion', { encoded });
    document.getElementById('decodedAssertionXml').textContent = formatXml(res.xml);
    toast('Decoded', 'success');
  } catch (e) {
    toast('Decode failed: ' + e.message, 'error');
  }
}

function decodeJwtManual() {
  const token = val('decodeJwtInput').trim();
  if (!token) { toast('Paste a JWT token first', 'warning'); return; }
  document.getElementById('manualJwtDecoded').innerHTML = renderJwtDecoded(token, 'Token');
}

// ─── JWT Decoder ───────────────────────────────────────────────────────────────
function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const decode = s => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '=')));
    return { header: decode(parts[0]), payload: decode(parts[1]), signature: parts[2] };
  } catch { return null; }
}

function renderJwtDecoded(token, label) {
  const decoded = decodeJwt(token);
  if (!decoded) {
    return `<div class="code-block" style="color:var(--red)">Invalid JWT</div>`;
  }
  const expInfo = decoded.payload.exp
    ? (() => {
        const d = new Date(decoded.payload.exp * 1000);
        const expired = d < new Date();
        return `<span class="status-badge ${expired ? 'status-err' : 'status-ok'} ms-2">${expired ? 'Expired' : 'Valid'} · ${d.toLocaleString()}</span>`;
      })()
    : '';
  return `
    <div class="jwt-decoded">
      <div class="jwt-part">
        <div class="jwt-part-label jwt-header-label">Header ${expInfo}</div>
        <div class="jwt-content">${escHtml(JSON.stringify(decoded.header, null, 2))}</div>
      </div>
      <div class="jwt-part">
        <div class="jwt-part-label jwt-payload-label">Payload</div>
        <div class="jwt-content">${escHtml(JSON.stringify(decoded.payload, null, 2))}</div>
      </div>
      <div class="jwt-part">
        <div class="jwt-part-label jwt-sig-label">Signature</div>
        <div class="jwt-content" style="color:var(--text-muted); word-break:break-all">${decoded.signature.substring(0, 60)}...</div>
      </div>
    </div>`;
}

// ─── Attributes ────────────────────────────────────────────────────────────────
function addAttrRow(name = '', value = '') {
  const row = document.createElement('div');
  row.className = 'attr-row';
  row.innerHTML = `
    <input type="text" class="form-control attr-name" placeholder="Attribute name" value="${escHtml(name)}">
    <input type="text" class="form-control attr-value" placeholder="Attribute value" value="${escHtml(value)}">
    <button class="btn btn-outline-secondary btn-sm" onclick="this.parentElement.remove()">
      <i class="bi bi-trash"></i>
    </button>`;
  document.getElementById('attrRows').appendChild(row);
}

function collectAttributes() {
  const attrs = {};
  document.querySelectorAll('.attr-row').forEach(row => {
    const name = row.querySelector('.attr-name').value.trim();
    const value = row.querySelector('.attr-value').value.trim();
    if (name) attrs[name] = value;
  });
  return attrs;
}

// ─── Scopes ────────────────────────────────────────────────────────────────────
function handleScopeKey(e) {
  const input = e.target;
  if (e.key === 'Enter' || e.key === ' ' || e.key === ',') {
    e.preventDefault();
    const scope = input.value.trim();
    if (scope && !scopeList.includes(scope)) {
      scopeList.push(scope);
      renderScopes();
    }
    input.value = '';
  } else if (e.key === 'Backspace' && !input.value && scopeList.length > 0) {
    scopeList.pop();
    renderScopes();
  }
}

function renderScopes() {
  const container = document.getElementById('scopeTags');
  const input = document.getElementById('scopeInput');
  container.innerHTML = '';
  scopeList.forEach((scope, i) => {
    const tag = document.createElement('div');
    tag.className = 'scope-tag';
    tag.innerHTML = `${escHtml(scope)}<span class="rm" onclick="removeScope(${i})">×</span>`;
    container.appendChild(tag);
  });
  container.appendChild(input);
}

function removeScope(i) {
  scopeList.splice(i, 1);
  renderScopes();
}

// ─── Tab Switching ─────────────────────────────────────────────────────────────
function showAssertionTab(tab) {
  document.getElementById('assertionTabXml').style.display = tab === 'xml' ? '' : 'none';
  document.getElementById('assertionTabB64').style.display = tab === 'b64' ? '' : 'none';
  document.querySelectorAll('#assertionTabs .tab-btn').forEach((btn, i) => {
    btn.classList.toggle('active', (i === 0 && tab === 'xml') || (i === 1 && tab === 'b64'));
  });
}

function showTokenTab(tab) {
  ['raw', 'access', 'id'].forEach((t, i) => {
    const panel = document.getElementById(`tokenTab${t.charAt(0).toUpperCase() + t.slice(1)}`);
    if (panel) panel.style.display = t === tab ? '' : 'none';
  });
  document.querySelectorAll('#tokenTabs .tab-btn').forEach((btn, i) => {
    btn.classList.toggle('active', ['raw', 'access', 'id'][i] === tab);
  });
}

function useAssertionForExchange() {
  if (currentAssertion) {
    document.getElementById('exchangeAssertion').value = currentAssertion.base64url;
    scrollTo('step-exchange');
    toast('Assertion loaded into token exchange', 'info');
  }
}

// ─── Config Persistence ────────────────────────────────────────────────────────
const CONFIG_KEY = 'saml-bearer-tester-config';
const CONFIG_FIELDS = ['oktaDomain', 'authServerId', 'clientId', 'issuer', 'subject',
  'nameIdFormat', 'audience', 'recipient', 'validityMinutes', 'clockSkewMinutes',
  'authnContextClass', 'privateKey', 'certificate'];

function saveConfig() {
  const cfg = {};
  CONFIG_FIELDS.forEach(id => { cfg[id] = document.getElementById(id)?.value || ''; });
  cfg.scopes = [...scopeList];
  cfg.attributes = collectAttributes();
  localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg));

  // Sync global fields
  const GLOBAL = ['oktaDomain', 'authServerId', 'clientId'];
  const existing = JSON.parse(localStorage.getItem('oauthst-global') || '{}');
  const update = {};
  GLOBAL.forEach(id => { if (cfg[id]) update[id] = cfg[id]; });
  localStorage.setItem('oauthst-global', JSON.stringify({ ...existing, ...update }));

  toast('Configuration saved', 'success');
}

function loadConfig() {
  // Global settings first (lower priority)
  try {
    const globalRaw = localStorage.getItem('oauthst-global');
    if (globalRaw) {
      const global = JSON.parse(globalRaw);
      ['oktaDomain', 'authServerId', 'clientId'].forEach(id => {
        const el = document.getElementById(id);
        if (el && global[id]) el.value = global[id];
      });
    }
  } catch {}

  // Page-specific overrides globals
  const raw = localStorage.getItem(CONFIG_KEY);
  if (!raw) return;
  try {
    const cfg = JSON.parse(raw);
    CONFIG_FIELDS.forEach(id => {
      const el = document.getElementById(id);
      if (el && cfg[id] !== undefined) el.value = cfg[id];
    });
    if (cfg.scopes?.length) { scopeList = cfg.scopes; renderScopes(); }
    if (cfg.attributes) {
      Object.entries(cfg.attributes).forEach(([k, v]) => addAttrRow(k, v));
    }
    updateTokenEndpointPreview();
  } catch {}
}

function clearConfig() {
  if (!confirm('Clear all saved configuration?')) return;
  localStorage.removeItem(CONFIG_KEY);
  CONFIG_FIELDS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  scopeList = ['openid'];
  renderScopes();
  document.getElementById('attrRows').innerHTML = '';
  toast('Configuration cleared', 'info');
}

// ─── Helpers ───────────────────────────────────────────────────────────────────
function val(id) {
  return (document.getElementById(id)?.value || '').trim();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function formatXml(xml) {
  let depth = 0;
  const INDENT = '  ';
  return xml
    .replace(/>\s*</g, '><')
    .replace(/(<[^/!?][^>]*[^/]>|<[^/!?][^>]*[^/]>(?=<))/g, m => m)
    .split(/(?<=>)(?=<)|(?<=<[^>]+\/>)/)
    .reduce((acc, node) => {
      if (!node.trim()) return acc;
      const isClose = /^<\//.test(node.trim());
      const isSelfClose = /\/>$/.test(node.trim());
      const isOpen = !isClose && !isSelfClose && /^<[^!?]/.test(node.trim());
      if (isClose) depth = Math.max(0, depth - 1);
      acc += INDENT.repeat(depth) + node.trim() + '\n';
      if (isOpen) depth++;
      return acc;
    }, '').trim();
}

function copyText(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.value || el.textContent || '')
    .then(() => toast('Copied to clipboard', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

function copyCode(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent || '')
    .then(() => toast('Copied!', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

function setLoading(btn, loading, html) {
  btn.disabled = loading;
  btn.innerHTML = loading
    ? `<span class="spinner-border spinner-border-sm me-1"></span>Loading…`
    : html;
}

function markNavDone(navId) {
  const el = document.getElementById(navId);
  if (el) el.classList.add('done');
}

function scrollTo(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toast(msg, type = 'info') {
  const colors = { success: 'var(--green)', error: 'var(--red)', warning: 'var(--yellow)', info: 'var(--blue)' };
  const icons = { success: 'bi-check-circle', error: 'bi-x-circle', warning: 'bi-exclamation-triangle', info: 'bi-info-circle' };
  const el = document.createElement('div');
  el.style.cssText = `
    position:fixed; bottom:20px; right:20px; z-index:9999;
    background:var(--surface); border:1px solid ${colors[type]};
    border-radius:8px; padding:10px 16px; font-size:0.82rem;
    color:var(--text); box-shadow:0 4px 20px rgba(0,0,0,0.4);
    display:flex; align-items:center; gap:8px; max-width:360px;
    animation: fadeInUp 0.2s ease;`;
  el.innerHTML = `<i class="bi ${icons[type]}" style="color:${colors[type]}; flex-shrink:0"></i>${escHtml(msg)}`;
  document.body.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 3000);
}

// Fade-in animation
const style = document.createElement('style');
style.textContent = `@keyframes fadeInUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }`;
document.head.appendChild(style);
