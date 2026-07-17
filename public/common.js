'use strict';
// Shared utilities for all OAuth Super Tester pages

function val(id) {
  return (document.getElementById(id)?.value || '').trim();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await r.json();
  if (!r.ok || data.error) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function copyCode(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent || '')
    .then(() => toast('Copied!', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

function copyText(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.value || el.textContent || '')
    .then(() => toast('Copied to clipboard', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

function copyRaw(text) {
  navigator.clipboard.writeText(text || '')
    .then(() => toast('Copied!', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

function setLoading(btn, loading, html) {
  btn.disabled = loading;
  btn.innerHTML = loading
    ? `<span class="spinner-border spinner-border-sm me-1"></span>Loading…`
    : html;
}

function decodeJwt(token) {
  try {
    const parts = (token || '').trim().split('.');
    if (parts.length !== 3) return null;
    const decode = s => JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(s.length+(4-s.length%4)%4,'=')));
    return { header: decode(parts[0]), payload: decode(parts[1]), signature: parts[2] };
  } catch { return null; }
}

function renderJwtDecoded(token, label = 'Token') {
  const d = decodeJwt(token);
  if (!d) return `<div class="code-block" style="color:var(--red)">Invalid JWT — cannot decode</div>`;
  const exp = d.payload.exp;
  const expired = exp && (new Date(exp * 1000) < new Date());
  const expBadge = exp ? `<span class="status-badge ${expired ? 'status-err' : 'status-ok'} ms-2">${expired ? 'Expired' : 'Valid'} · ${new Date(exp * 1000).toLocaleString()}</span>` : '';
  const cnfJkt = d.payload?.cnf?.jkt ? `<div class="mt-2 p-2" style="background:rgba(88,166,255,0.07);border-radius:6px;font-size:0.75rem;"><span style="color:var(--text-muted)">cnf.jkt (DPoP binding): </span><code style="color:var(--orange)">${escHtml(d.payload.cnf.jkt)}</code></div>` : '';
  return `<div class="jwt-decoded">
    <div class="jwt-part"><div class="jwt-part-label jwt-header-label">Header</div><div class="jwt-content">${escHtml(JSON.stringify(d.header,null,2))}</div></div>
    <div class="jwt-part"><div class="jwt-part-label jwt-payload-label">Payload ${expBadge}</div><div class="jwt-content">${escHtml(JSON.stringify(d.payload,null,2))}</div>${cnfJkt}</div>
    <div class="jwt-part"><div class="jwt-part-label jwt-sig-label">Signature</div><div class="jwt-content" style="color:var(--text-muted);word-break:break-all">${d.signature.substring(0,80)}...</div></div>
  </div>`;
}

function toast(msg, type = 'info') {
  const colors = { success:'var(--green)', error:'var(--red)', warning:'var(--yellow)', info:'var(--blue)' };
  const icons  = { success:'bi-check-circle', error:'bi-x-circle', warning:'bi-exclamation-triangle', info:'bi-info-circle' };
  const el = document.createElement('div');
  el.style.cssText = `position:fixed;bottom:20px;right:20px;z-index:9999;background:var(--surface);border:1px solid ${colors[type]};border-radius:8px;padding:10px 16px;font-size:0.82rem;color:var(--text);box-shadow:0 4px 20px rgba(0,0,0,0.4);display:flex;align-items:center;gap:8px;max-width:380px;animation:fadeInUp 0.2s ease;`;
  el.innerHTML = `<i class="bi ${icons[type]}" style="color:${colors[type]};flex-shrink:0"></i>${escHtml(msg)}`;
  document.body.appendChild(el);
  setTimeout(() => { el.style.opacity='0'; el.style.transition='opacity 0.3s'; setTimeout(()=>el.remove(),300); }, 3500);
}

// Pretty-print JSON in a code block
function renderJson(obj) {
  return escHtml(typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2));
}

// Pretty-print a JWK without private fields
function renderPublicJwk(jwk) {
  const pub = { ...jwk };
  delete pub.d; delete pub.p; delete pub.q; delete pub.dp; delete pub.dq; delete pub.qi;
  return escHtml(JSON.stringify(pub, null, 2));
}

// Validation result list
function renderValidationResults(results, valid) {
  const icon = valid
    ? `<i class="bi bi-shield-fill-check" style="color:var(--green)"></i> All checks passed`
    : `<i class="bi bi-shield-fill-x" style="color:var(--red)"></i> Some checks failed`;

  const rows = results.map(r => `
    <div class="d-flex align-items-start gap-2 py-2" style="border-bottom:1px solid var(--border)">
      <i class="bi ${r.ok ? 'bi-check-circle-fill' : 'bi-x-circle-fill'}" style="color:${r.ok ? 'var(--green)' : 'var(--red)'};margin-top:1px;flex-shrink:0"></i>
      <div>
        <div style="font-size:0.82rem;font-weight:600">${escHtml(r.check)}</div>
        ${r.detail ? `<div style="font-size:0.75rem;color:var(--text-muted);font-family:monospace;word-break:break-all">${escHtml(r.detail)}</div>` : ''}
      </div>
    </div>`).join('');

  return `<div class="mb-2" style="font-size:0.875rem;font-weight:600">${icon}</div><div>${rows}</div>`;
}

// Scope tag management (pass a config object with containerId, inputId, initial list)
function createScopeManager(containerId, inputId, initial = []) {
  const state = { list: [...initial] };

  function render() {
    const container = document.getElementById(containerId);
    const input = document.getElementById(inputId);
    if (!container || !input) return;
    container.innerHTML = '';
    state.list.forEach((scope, i) => {
      const tag = document.createElement('div');
      tag.className = 'scope-tag';
      tag.innerHTML = `${escHtml(scope)}<span class="rm" onclick="window._scopeMgr_${containerId}.remove(${i})">×</span>`;
      container.appendChild(tag);
    });
    container.appendChild(input);
  }

  function add(scope) {
    const s = scope.trim();
    if (s && !state.list.includes(s)) { state.list.push(s); render(); }
  }

  function remove(i) { state.list.splice(i, 1); render(); }

  function handleKey(e) {
    const input = e.target;
    if (e.key === 'Enter' || e.key === ' ' || e.key === ',') {
      e.preventDefault(); add(input.value); input.value = '';
    } else if (e.key === 'Backspace' && !input.value && state.list.length > 0) {
      state.list.pop(); render();
    }
  }

  // Register globally so onclick can find it
  window[`_scopeMgr_${containerId}`] = { remove, add };

  // Wire up input keydown
  setTimeout(() => {
    const input = document.getElementById(inputId);
    if (input) input.addEventListener('keydown', handleKey);
    render();
  }, 0);

  return { state, add, remove, render };
}

// Global fields synced across all tester pages via oauthst-global AND config.json
const GLOBAL_FIELDS = ['oktaDomain', 'authServerId', 'clientId', 'clientSecret'];

// Config persistence per page prefix
function savePageConfig(prefix, fieldIds) {
  const cfg = {};
  fieldIds.forEach(id => { cfg[id] = document.getElementById(id)?.value || ''; });
  localStorage.setItem(`oauthst-${prefix}`, JSON.stringify(cfg));

  // Sync shared fields to oauthst-global localStorage
  const existing = JSON.parse(localStorage.getItem('oauthst-global') || '{}');
  const update = {};
  fieldIds.filter(id => GLOBAL_FIELDS.includes(id)).forEach(id => { if (cfg[id]) update[id] = cfg[id]; });
  if (Object.keys(update).length) {
    localStorage.setItem('oauthst-global', JSON.stringify({ ...existing, ...update }));
    // Persist to server so settings survive restarts
    fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(update) }).catch(() => {});
  }

  toast('Configuration saved', 'success');
}

function loadPageConfig(prefix, fieldIds) {
  // 1. Global localStorage (immediate, no flash)
  try {
    const globalRaw = localStorage.getItem('oauthst-global');
    if (globalRaw) {
      const g = JSON.parse(globalRaw);
      fieldIds.filter(id => GLOBAL_FIELDS.includes(id)).forEach(id => {
        const el = document.getElementById(id);
        if (el && g[id]) el.value = g[id];
      });
    }
  } catch {}

  // 2. Page-specific localStorage (overrides global)
  try {
    const raw = localStorage.getItem(`oauthst-${prefix}`);
    if (raw) {
      const cfg = JSON.parse(raw);
      fieldIds.forEach(id => {
        const el = document.getElementById(id);
        if (el && cfg[id] !== undefined) el.value = cfg[id];
      });
    }
  } catch {}

  // 3. Server config.json (authoritative — overwrites stale localStorage)
  fetch('/api/settings').then(r => r.json()).then(s => {
    const serverVals = { oktaDomain: s.oktaDomain, authServerId: s.authServerId, clientId: s.clientId, clientSecret: s.clientSecret };
    let changed = false;
    fieldIds.filter(id => GLOBAL_FIELDS.includes(id) && serverVals[id]).forEach(id => {
      const el = document.getElementById(id);
      if (el && el.value !== serverVals[id]) { el.value = serverVals[id]; changed = true; }
    });
    // Sync server values back into localStorage so they're immediately available next load
    const existing = JSON.parse(localStorage.getItem('oauthst-global') || '{}');
    localStorage.setItem('oauthst-global', JSON.stringify({ ...existing, ...Object.fromEntries(GLOBAL_FIELDS.filter(id => serverVals[id]).map(id => [id, serverVals[id]])) }));
    // Trigger endpoint preview update if any field changed
    if (changed) ['oktaDomain', 'authServerId'].forEach(id => document.getElementById(id)?.dispatchEvent(new Event('input')));
  }).catch(() => {});
}

function clearPageConfig(prefix, fieldIds) {
  if (!confirm('Clear all saved configuration for this page?')) return;
  localStorage.removeItem(`oauthst-${prefix}`);
  fieldIds.forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  toast('Configuration cleared', 'info');
}

// Auth: check login status and update navbar
async function initNavAuth() {
  const navArea = document.getElementById('navAuthArea');
  try {
    const r = await fetch('/api/auth/me');
    if (r.status === 401) {
      window.location.href = '/auth/login?returnTo=' + encodeURIComponent(window.location.pathname + window.location.search);
      return;
    }
    const data = await r.json();
    if (navArea && data.user) {
      navArea.innerHTML = `<div class="d-flex align-items-center gap-2">
        <span style="font-size:0.78rem;color:var(--text-muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(data.user.name || data.user.email || data.user.sub)}</span>
        <a href="/auth/logout" class="btn btn-outline-secondary btn-sm" style="font-size:0.72rem;padding:2px 8px;white-space:nowrap">Logout</a>
      </div>`;
    }
  } catch { /* server not yet ready — ignore */ }
}

// ─── HTTP Exchange display ─────────────────────────────────────────────────────
// Renders a reusable "Time to Token / Request / Response" section.
// options: { url, method, statusCode, durationMs, requestDetails, response, open }
function renderHttpExchange({ url, method = 'POST', statusCode, durationMs, requestDetails, response, open = false } = {}) {
  const ok     = statusCode >= 200 && statusCode < 300;
  const timing = durationMs != null
    ? `<span style="background:rgba(45,217,198,0.1);color:#2dd9c6;border:1px solid rgba(45,217,198,0.25);border-radius:10px;padding:2px 8px;font-size:0.7rem;font-weight:700;font-family:monospace;margin-left:6px">⏱ ${durationMs}ms</span>` : '';
  const endpoint = url
    ? `<span style="font-size:0.7rem;color:var(--text-muted);font-family:monospace;margin-left:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:400px;display:inline-block;vertical-align:middle">${escHtml(url)}</span>` : '';

  const reqJson  = requestDetails ? JSON.stringify(requestDetails, null, 2) : null;
  const respJson = response       ? JSON.stringify(response, null, 2)       : null;

  const reqSection = reqJson ? `
    <details${open?' open':''} style="margin-top:6px">
      <summary style="cursor:pointer;font-size:0.75rem;color:var(--text-muted);padding:3px 0;user-select:none;list-style:none;display:flex;align-items:center;gap:5px">
        <i class="bi bi-arrow-up-circle"></i> Request
      </summary>
      <div style="position:relative;margin-top:4px">
        <div class="code-block json" style="max-height:220px">${escHtml(reqJson)}</div>
        <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyRaw(${JSON.stringify(reqJson)})"><i class="bi bi-clipboard"></i></button>
      </div>
    </details>` : '';

  const respSection = respJson ? `
    <details${open?' open':''} style="margin-top:4px">
      <summary style="cursor:pointer;font-size:0.75rem;color:var(--text-muted);padding:3px 0;user-select:none;list-style:none;display:flex;align-items:center;gap:5px">
        <i class="bi bi-arrow-down-circle"></i> Response
      </summary>
      <div style="position:relative;margin-top:4px">
        <div class="code-block json" style="max-height:220px">${escHtml(respJson)}</div>
        <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyRaw(${JSON.stringify(respJson)})"><i class="bi bi-clipboard"></i></button>
      </div>
    </details>` : '';

  return `<div style="border-top:1px solid var(--border);padding-top:10px;margin-top:12px">
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin-bottom:4px">
      <span class="status-badge ${ok?'status-ok':'status-err'}">HTTP ${statusCode||'—'}</span>
      ${timing}
      ${endpoint}
    </div>
    ${reqSection}
    ${respSection}
  </div>`;
}

// Status badge
function statusBadge(code) {
  const ok = code >= 200 && code < 300;
  return `<span class="status-badge ${ok ? 'status-ok' : 'status-err'}">HTTP ${code || 'Error'}</span>`;
}

// Inject animation style once
const _styleEl = document.createElement('style');
_styleEl.textContent = `@keyframes fadeInUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}`;
document.head.appendChild(_styleEl);
