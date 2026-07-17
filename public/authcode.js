'use strict';
const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','redirectUri','scope'];
let currentFlowId = null;
let pollTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadPageConfig('authcode', CONFIG_FIELDS);
  setupAutoFill();
  // Listen for postMessage from popup
  window.addEventListener('message', (e) => {
    if (e.data?.type === 'oauth-callback') handleCallbackResult(e.data);
  });
});

function setupAutoFill() {
  // Auto-fill redirect URI default
  const ri = document.getElementById('redirectUri');
  if (!ri.value) ri.value = 'http://localhost:3000/oauth/callback';
}

async function startAuth() {
  const btn = document.getElementById('authorizeBtn');
  if (!val('oktaDomain') || !val('clientId')) { toast('Fill in Okta Domain and Client ID first', 'warning'); return; }

  setLoading(btn, true, '<i class="bi bi-box-arrow-up-right me-1"></i>Opening…');

  try {
    const res = await post('/api/oauth/start', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      redirectUri: val('redirectUri') || 'http://localhost:3000/oauth/callback',
      scope: val('scope') || 'openid profile email'
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
        handleCallbackResult({ flowId: currentFlowId, status: status.status, tokens: status.tokens, error: status.error });
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
    document.getElementById('tokenResultStatus').innerHTML =
      `<span class="status-badge status-ok"><i class="bi bi-check-circle me-1"></i>Tokens received</span>`;

    if (data.tokens.access_token) {
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

function exportToWorkflow() {
  const stored = sessionStorage.getItem('workflow-tokens');
  if (stored) {
    localStorage.setItem('workflow-import', stored);
    toast('Tokens exported — open the Test Chain builder', 'success');
    setTimeout(() => window.location.href = '/workflow.html', 800);
  }
}
