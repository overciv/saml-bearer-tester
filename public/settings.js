'use strict';

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  setupEndpointPreview();
  loadSettings();
});

function setupEndpointPreview() {
  ['oktaDomain', 'authServerId'].forEach(id =>
    document.getElementById(id)?.addEventListener('input', updatePreview));
  updatePreview();
}

function updatePreview() {
  const domain = val('oktaDomain');
  const sid = val('authServerId');
  const ep = domain ? (sid ? `https://${domain}/oauth2/${sid}/v1/token` : `https://${domain}/oauth2/v1/token`) : '—';
  document.getElementById('endpointPreview').textContent = ep;
}

// ─── Load from server + localStorage ─────────────────────────────────────────

async function loadSettings() {
  // Populate from localStorage first (instant)
  const global = JSON.parse(localStorage.getItem('oauthst-global') || '{}');
  if (global.oktaDomain) document.getElementById('oktaDomain').value = global.oktaDomain;
  if (global.authServerId) document.getElementById('authServerId').value = global.authServerId;
  if (global.clientId) document.getElementById('clientId').value = global.clientId;
  updatePreview();

  // Fetch from server (authoritative for auth settings and signing key)
  try {
    const res = await fetch('/api/settings');
    const data = await res.json();
    if (data.oktaDomain) document.getElementById('oktaDomain').value = data.oktaDomain;
    if (data.authServerId !== undefined) document.getElementById('authServerId').value = data.authServerId;
    if (data.clientId) document.getElementById('clientId').value = data.clientId;
    if (data.clientSecret)  document.getElementById('clientSecret').value  = data.clientSecret;
    if (data.adminApiToken) document.getElementById('adminApiToken').value = data.adminApiToken;
    if (data.authEnabled) document.getElementById('authEnabled').checked = data.authEnabled;
    if (data.authClientId) document.getElementById('authClientId').value = data.authClientId;
    if (data.redirectUri) document.getElementById('redirectUri').value = data.redirectUri;
    if (data.authScopes) document.getElementById('authScopes').value = Array.isArray(data.authScopes) ? data.authScopes.join(' ') : data.authScopes;

    renderSigningKey(data.signingKey);
    updatePreview();
  } catch {
    toast('Could not reach server — using localStorage only', 'warning');
    // Still try to show signing key from JWKS endpoint
    try {
      const jwksRes = await fetch('/auth/jwks');
      const jwks = await jwksRes.json();
      renderSigningKey({ jwks, hasKey: jwks.keys?.length > 0 });
    } catch {}
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
  setLoading(btn, true, '<i class="bi bi-floppy me-1"></i>Save Settings');

  const scopesRaw = val('authScopes') || 'openid profile email';
  const authScopes = scopesRaw.split(/\s+/).filter(Boolean);

  const payload = {
    oktaDomain: val('oktaDomain'),
    authServerId: val('authServerId'),
    clientId: val('clientId'),
    clientSecret: document.getElementById('clientSecret')?.value || '',
    adminApiToken: document.getElementById('adminApiToken')?.value || '',
    authEnabled: document.getElementById('authEnabled').checked,
    authClientId: val('authClientId'),
    authScopes,
    redirectUri: val('redirectUri') || 'http://localhost:3000/auth/callback'
  };

  // Save to localStorage
  const existing = JSON.parse(localStorage.getItem('oauthst-global') || '{}');
  localStorage.setItem('oauthst-global', JSON.stringify({
    ...existing,
    oktaDomain: payload.oktaDomain,
    authServerId: payload.authServerId,
    clientId: payload.clientId
  }));

  // Save to server
  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    renderSigningKey(data.signingKey);
    toast('Settings saved — all tester pages will now use these values', 'success');
  } catch (e) {
    toast('Failed to save to server: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-floppy me-1"></i>Save Settings');
  }
}

// ─── Generate new signing key ─────────────────────────────────────────────────

async function generateSigningKey() {
  const btn = document.getElementById('genKeyBtn');
  setLoading(btn, true, '<i class="bi bi-shuffle me-1"></i>Generating...');

  if (!confirm('Generate a new signing key? The old key will be replaced — you must register the new JWKS in Okta before re-enabling authentication.')) {
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
    toast('New signing key generated — register the JWKS in Okta before enabling authentication', 'warning');
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-shuffle me-1"></i>Generate New Key');
  }
}
