'use strict';
const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','redirectUri','scope','clientAuthMethod','clientSecret','clientPrivateJwk'];
let currentFlowId = null;
let pollTimer = null;
let _lastAccessToken = null;
let _lastTokens = null;

document.addEventListener('DOMContentLoaded', () => {
  window._pageSave = () => savePageConfig('authcode', CONFIG_FIELDS);
  initNavAuth();
  loadPageConfig('authcode', CONFIG_FIELDS);
  setupAutoFill();
  // Listen for postMessage from popup
  window.addEventListener('message', (e) => {
    if (e.data?.type === 'oauth-callback') handleCallbackResult(e.data);
  });
});

function setupAutoFill() {
  const ri = document.getElementById('redirectUri');
  if (!ri.value) ri.value = 'http://localhost:3001/oauth/callback';
}

function toggleClientAuth() {
  const m = val('clientAuthMethod');
  document.getElementById('clientSecretRow').style.display = m === 'basic'  ? '' : 'none';
  document.getElementById('pkjwtRow').style.display        = m === 'pkjwt'  ? '' : 'none';
}

async function startAuth() {
  const btn = document.getElementById('authorizeBtn');
  if (!val('oktaDomain') || !val('clientId')) { toast('Fill in Okta Domain and Client ID first', 'warning'); return; }

  setLoading(btn, true, '<i class="bi bi-box-arrow-up-right me-1"></i>Opening…');

  try {
    const authMethod = val('clientAuthMethod') || 'none';
    let privateJwk;
    if (authMethod === 'pkjwt') {
      try { privateJwk = JSON.parse(val('clientPrivateJwk') || document.getElementById('clientPrivateJwk')?.value || ''); }
      catch { toast('Invalid Private JWK JSON', 'error'); setLoading(btn, false, '<i class="bi bi-box-arrow-up-right me-1"></i>Open Okta Login'); return; }
    }
    const res = await post('/api/oauth/start', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      redirectUri: val('redirectUri') || 'http://localhost:3001/oauth/callback',
      scope: val('scope') || 'openid profile email',
      clientAuthMethod: authMethod,
      clientSecret: authMethod === 'basic' ? (document.getElementById('clientSecret')?.value || '') : undefined,
      privateJwk: authMethod === 'pkjwt' ? privateJwk : undefined,
    });

    currentFlowId = res.flowId;

    // Show status
    const statusEl = document.getElementById('authStatus');
    statusEl.style.display = '';
    document.getElementById('authStatusContent').innerHTML =
      `<div class="d-flex align-items-center gap-2">
        <span class="spinner-border spinner-border-sm" style="color:var(--blue)"></span>
        <span style="font-size:0.82rem">Waiting for user to complete login in popup…</span>
      </div>`;

    // Open popup
    const popup = window.open(res.authUrl, 'okta-auth', 'width=600,height=700,left=200,top=100');

    // Polling fallback (in case postMessage is blocked)
    pollTimer = setInterval(async () => {
      const status = await fetch(`/api/oauth/status/${currentFlowId}`).then(r => r.json()).catch(() => null);
      if (!status) return;
      if (status.status === 'success' || status.status === 'error') {
        clearInterval(pollTimer); pollTimer = null;
        handleCallbackResult({ flowId: currentFlowId, status: status.status, tokens: status.tokens, error: status.error,
          tokenEndpoint: status.tokenEndpoint, durationMs: status.durationMs, requestDetails: status.requestDetails });
      }
    }, 1500);

    toast('Okta login popup opened — log in to continue', 'info');
  } catch (e) {
    toast('Failed to start auth: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-box-arrow-up-right me-1"></i>Open Okta Login');
  }
}

function handleCallbackResult(data) {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  document.getElementById('authStatus').style.display = 'none';
  document.getElementById('tokensPlaceholder').style.display = 'none';
  document.getElementById('tokensContent').style.display = '';

  if (data.status === 'success' && data.tokens) {
    // Show HTTP exchange (timing + request/response)
    document.getElementById('httpExchange').innerHTML = renderHttpExchange({
      url: data.tokenEndpoint, statusCode: 200, durationMs: data.durationMs,
      requestDetails: data.requestDetails, response: data.tokens
    });
    document.getElementById('tokenResultStatus').innerHTML =
      `<span class="status-badge status-ok"><i class="bi bi-check-circle me-1"></i>Tokens received</span>`;

    _lastTokens = data.tokens;
    if (data.tokens.access_token) {
      _lastAccessToken = data.tokens.access_token;
      document.getElementById('accessDecoded').innerHTML = renderJwtDecoded(data.tokens.access_token, 'Access Token');
    }
    if (data.tokens.id_token) {
      document.getElementById('idDecoded').innerHTML = renderJwtDecoded(data.tokens.id_token, 'ID Token');
    }
    document.getElementById('rawResponse').textContent = JSON.stringify(data.tokens, null, 2);
    showTTab('access');

    // Store tokens for workflow use
    sessionStorage.setItem('workflow-tokens', JSON.stringify({
      source: 'auth-code',
      clientId: val('clientId'),
      tokens: data.tokens,
      timestamp: Date.now()
    }));

    toast('Tokens received!', 'success');
  } else {
    document.getElementById('tokenResultStatus').innerHTML =
      `<span class="status-badge status-err"><i class="bi bi-x-circle me-1"></i>Auth failed: ${escHtml(data.error || 'unknown')}</span>`;
    toast('Authentication failed: ' + (data.error || 'unknown'), 'error');
  }
}

function showTTab(tab) {
  ['access','id','raw'].forEach((t,i) => {
    document.getElementById(`tTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#tokenTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

function exportToTokenInspector() {
  if (!_lastTokens) { toast('No tokens yet — authorize first', 'warning'); return; }
  // Pick the token matching the currently visible tab
  const tabs = document.querySelectorAll('#tokenTabs .tab-btn');
  const activeIdx = Array.from(tabs).findIndex(t => t.classList.contains('active'));
  const token = activeIdx === 1 ? _lastTokens.id_token  // ID Token tab
               : _lastTokens.access_token;              // Access Token tab (default)
  const name  = activeIdx === 1 ? 'id_token' : 'access_token';
  if (!token) { toast(`No ${name} available`, 'warning'); return; }
  sessionStorage.setItem('authcode-export-inspect-token', token);
  toast(`Exporting ${name} to Token Inspector…`, 'info');
  setTimeout(() => window.location.href = '/token-inspector.html', 400);
}

function exportToTokenExchange() {
  if (!_lastAccessToken) { toast('No access_token yet — authorize first', 'warning'); return; }
  sessionStorage.setItem('authcode-export-access-token', _lastAccessToken);
  toast('Exporting to Token Exchange…', 'info');
  setTimeout(() => window.location.href = '/token-exchange.html', 400);
}

function exportToWorkflow() {
  const stored = sessionStorage.getItem('workflow-tokens');
  if (stored) {
    localStorage.setItem('workflow-import', stored);
    toast('Tokens exported — open the Test Chain builder', 'success');
    setTimeout(() => window.location.href = '/workflow.html', 800);
  }
}
