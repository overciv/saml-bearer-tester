'use strict';

document.addEventListener('DOMContentLoaded', () => {
  window._pageSave = saveSettings;
  initNavAuth();
  loadTenantInfo();
  loadSettings();
});

async function loadTenantInfo() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();
    if (data.tenant) {
      document.getElementById('tenantId').value = data.tenant.id || '';
      document.getElementById('tenantTitle').value = data.tenant.title || '';
    }
  } catch {}
}

// ─── Load from server + localStorage ─────────────────────────────────────────

async function loadSettings() {
  // Populate from localStorage first (instant)
  const global = JSON.parse(localStorage.getItem('oauthst-global') || '{}');
  if (global.oktaDomain) document.getElementById('oktaDomain').value = global.oktaDomain;
  if (global.adminApiToken) document.getElementById('adminApiToken').value = global.adminApiToken;

  // Fetch from server (authoritative, scoped to the current tenant)
  try {
    const res = await fetch('/api/tenant-settings/global');
    const data = await res.json();
    if (data.oktaDomain) document.getElementById('oktaDomain').value = data.oktaDomain;
    if (data.adminApiToken) document.getElementById('adminApiToken').value = data.adminApiToken;
    localStorage.setItem('oauthst-global', JSON.stringify(data));

    const jwksRes = await fetch('/auth/jwks');
    const jwks = await jwksRes.json();
    renderSigningKey({ jwks, hasKey: jwks.keys?.length > 0 });
  } catch {
    toast('Could not reach server — using localStorage only', 'warning');
  }
}

function renderSigningKey(signingKey) {
  if (!signingKey?.hasKey || !signingKey.jwks?.keys?.length) {
    document.getElementById('keyMeta').style.display = 'none';
    document.getElementById('noKey').style.display = '';
    document.getElementById('jwksOutput').textContent = 'No key generated yet';
    return;
  }
  const key = signingKey.jwks.keys[0];
  document.getElementById('noKey').style.display = 'none';
  document.getElementById('keyMeta').style.display = '';
  document.getElementById('keyKid').textContent = key.kid;
  document.getElementById('keyAlg').textContent = key.alg || 'RS256';
  document.getElementById('jwksOutput').textContent = JSON.stringify(signingKey.jwks, null, 2);
}

// ─── Save ─────────────────────────────────────────────────────────────────────

async function saveSettings() {
  const btn = document.getElementById('saveBtn');
  if (btn) setLoading(btn, true, '<i class="bi bi-floppy me-1"></i>Save Settings');

  const payload = {
    oktaDomain: val('oktaDomain'),
    adminApiToken: document.getElementById('adminApiToken')?.value || ''
  };

  localStorage.setItem('oauthst-global', JSON.stringify(payload));

  try {
    const res = await fetch('/api/tenant-settings/global', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error((await res.json()).error || `HTTP ${res.status}`);
    toast('Settings saved', 'success');
  } catch (e) {
    toast('Failed to save to server: ' + e.message, 'error');
  } finally {
    if (btn) setLoading(btn, false, '<i class="bi bi-floppy me-1"></i>Save Settings');
  }
}

// ─── Generate new signing key ─────────────────────────────────────────────────

async function generateSigningKey() {
  const btn = document.getElementById('genKeyBtn');
  setLoading(btn, true, '<i class="bi bi-shuffle me-1"></i>Generating...');

  if (!confirm('Generate a new signing key? The old key will be replaced — you must register the new JWKS wherever it was in use.')) {
    setLoading(btn, false, '<i class="bi bi-shuffle me-1"></i>Generate New Key');
    return;
  }

  try {
    const res = await fetch('/api/auth/generate-signing-key', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    renderSigningKey({ jwks: data.jwks, hasKey: true });
    toast('New signing key generated', 'warning');
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-shuffle me-1"></i>Generate New Key');
  }
}
