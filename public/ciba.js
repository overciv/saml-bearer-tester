'use strict';

const CONFIG_FIELDS = ['oktaDomain', 'authServerId', 'clientId', 'clientSecret', 'clientAuthMethod'];

let scopeMgr;
let hintMode = 'login';

// Polling state
let pollTimer = null;
let pollCountdownTimer = null;
let pollAttempts = 0;
let pollIntervalSec = 5;
let pollExpiresAt = null;
let pollExpiresInSec = 300;
let currentAuthReqId = null;
let currentScope = [];

document.addEventListener('DOMContentLoaded', () => {
  window._pageSave = () => savePageConfig('ciba', CONFIG_FIELDS);
  initNavAuth();
  loadPageConfig('ciba', CONFIG_FIELDS);
  scopeMgr = createScopeManager('scopeTags', 'scopeInput', ['openid', 'email']);
  setupEndpointPreview();
  toggleAuthMethod();
});

function setupEndpointPreview() {
  ['oktaDomain', 'authServerId'].forEach(id =>
    document.getElementById(id)?.addEventListener('input', updateEndpointPreview));
  updateEndpointPreview();
}

function updateEndpointPreview() {
  const domain = val('oktaDomain');
  const sid = val('authServerId');
  const ep = domain
    ? (sid ? `https://${domain}/oauth2/${sid}/v1/bc/authorize` : `https://${domain}/oauth2/v1/bc/authorize`)
    : '—';
  document.getElementById('bcEndpointPreview').textContent = ep;
  document.getElementById('pollIntervalDisplay').textContent = pollIntervalSec;
}

function toggleAuthMethod() {
  const isPkjwt = val('clientAuthMethod') === 'pkjwt';
  document.getElementById('secretRow').style.display = isPkjwt ? 'none' : '';
  document.getElementById('pkjwtRow').style.display = isPkjwt ? '' : 'none';
}

function setHintMode(mode) {
  hintMode = mode;
  document.getElementById('loginHintRow').style.display = mode === 'login' ? '' : 'none';
  document.getElementById('idTokenHintRow').style.display = mode === 'idtoken' ? '' : 'none';
  document.getElementById('hintLoginBtn').classList.toggle('active', mode === 'login');
  document.getElementById('hintIdTokenBtn').classList.toggle('active', mode === 'idtoken');
}

// ─── Step 2: Backchannel Authorization ────────────────────────────────────────

async function sendBackchannelRequest() {
  const btn = document.getElementById('sendAuthBtn');
  setLoading(btn, true, '<i class="bi bi-send-fill me-1"></i>Send Request');

  const isPkjwt = val('clientAuthMethod') === 'pkjwt';

  if (!val('oktaDomain') || !val('clientId')) {
    toast('Missing Okta Domain or Client ID', 'warning');
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send Request');
    return;
  }

  const loginHint = hintMode === 'login' ? val('loginHint') : undefined;
  const idTokenHint = hintMode === 'idtoken' ? val('idTokenHint') : undefined;
  if (!loginHint && !idTokenHint) {
    toast('Enter a login_hint (email) or id_token_hint', 'warning');
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send Request');
    return;
  }

  let privateJwk;
  if (isPkjwt) {
    const raw = val('clientPrivateJwk');
    if (!raw) { toast('Paste a private JWK for PKJWT auth', 'warning'); setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send Request'); return; }
    try { privateJwk = JSON.parse(raw); } catch { toast('Invalid private JWK JSON', 'error'); setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send Request'); return; }
  }

  try {
    const res = await post('/api/ciba/backchannel-authorize', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      clientSecret: isPkjwt ? undefined : (document.getElementById('clientSecret')?.value || ''),
      loginHint,
      idTokenHint,
      bindingMessage: val('bindingMessage'),
      scope: scopeMgr.getAll(),
      requestExpiry: parseInt(val('requestExpiry')) || 300,
      privateJwk
    });

    document.getElementById('authorizeReqDetails').textContent = JSON.stringify(res.requestDetails, null, 2);
    document.getElementById('authorizeResponse').textContent = JSON.stringify(res.response, null, 2);
    document.getElementById('authorizeOutput').style.display = '';

    if (res.success && res.response?.auth_req_id) {
      currentAuthReqId = res.response.auth_req_id;
      pollIntervalSec = res.response.interval || 5;
      pollExpiresInSec = res.response.expires_in || 300;
      currentScope = [...scopeMgr.getAll()];

      document.getElementById('authReqId').value = currentAuthReqId;
      document.getElementById('pollIntervalDisplay').textContent = pollIntervalSec;
      document.getElementById('pollIntervalLabel').textContent = pollIntervalSec + 's';

      toast('Backchannel request sent — push notification dispatched to user device', 'success');
    } else {
      toast('Request failed — see response', 'error');
    }
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Send Request');
  }
}

function scrollToPolling() {
  document.getElementById('step-poll').scrollIntoView({ behavior: 'smooth' });
}

// ─── Step 3: Polling ──────────────────────────────────────────────────────────

function startPolling() {
  const authReqId = val('authReqId') || currentAuthReqId;
  if (!authReqId) { toast('Send a backchannel request first to get an auth_req_id', 'warning'); return; }
  if (pollTimer) { toast('Polling is already running', 'info'); return; }

  currentAuthReqId = authReqId;
  pollAttempts = 0;
  pollExpiresAt = Date.now() + pollExpiresInSec * 1000;

  // Show status area
  document.getElementById('pollStatusArea').style.display = '';
  document.getElementById('tokenResultArea').style.display = 'none';
  document.getElementById('pollTimeline').innerHTML = '';

  // Show binding message if set
  const bm = val('bindingMessage');
  if (bm) {
    document.getElementById('bindingBoxMsg').textContent = bm;
    document.getElementById('bindingBoxDisplay').style.display = '';
  } else {
    document.getElementById('bindingBoxDisplay').style.display = 'none';
  }

  setStatus('waiting');
  document.getElementById('startPollBtn').disabled = true;
  document.getElementById('stopPollBtn').disabled = false;

  // Start countdown timer (updates every second)
  pollCountdownTimer = setInterval(updateCountdown, 1000);

  // Do first poll immediately, then on interval
  doPoll();
  pollTimer = setInterval(doPoll, pollIntervalSec * 1000);
}

function stopPolling(reason) {
  clearInterval(pollTimer);
  clearInterval(pollCountdownTimer);
  pollTimer = null;
  pollCountdownTimer = null;
  document.getElementById('startPollBtn').disabled = false;
  document.getElementById('stopPollBtn').disabled = true;
  if (reason) toast(reason, 'info');
}

async function doPoll() {
  pollAttempts++;
  document.getElementById('pollAttemptCount').textContent = pollAttempts;

  const isPkjwt = val('clientAuthMethod') === 'pkjwt';
  let privateJwk;
  if (isPkjwt) {
    try { privateJwk = JSON.parse(val('clientPrivateJwk')); } catch {}
  }

  let result;
  try {
    result = await post('/api/ciba/poll', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      clientSecret: isPkjwt ? undefined : (document.getElementById('clientSecret')?.value || ''),
      authReqId: currentAuthReqId,
      scope: currentScope.length ? currentScope : scopeMgr.getAll(),
      privateJwk
    });
  } catch (e) {
    addPollEntry({ error: e.message, attempt: pollAttempts });
    return;
  }

  addPollEntry({ ...result, attempt: pollAttempts });

  if (result.slowDown) {
    pollIntervalSec += 5;
    clearInterval(pollTimer);
    pollTimer = setInterval(doPoll, pollIntervalSec * 1000);
    document.getElementById('pollIntervalLabel').textContent = pollIntervalSec + 's';
    toast(`slow_down — polling interval increased to ${pollIntervalSec}s`, 'warning');
    return;
  }

  if (result.pending) {
    // Keep going — just update UI
    return;
  }

  // Terminal states
  stopPolling();

  if (result.success) {
    setStatus('approved');
    showTokenResult(result.response);
    toast('Tokens received!', 'success');
  } else if (result.denied) {
    setStatus('denied');
    toast('Access denied — user rejected the push notification', 'error');
  } else if (result.expired) {
    setStatus('expired');
    toast('auth_req_id has expired — send a new backchannel request', 'warning');
  } else {
    setStatus('denied');
    toast(`Error: ${result.response?.error || 'Unknown error'}`, 'error');
  }
}

function updateCountdown() {
  if (!pollExpiresAt) return;
  const remaining = Math.max(0, pollExpiresAt - Date.now());
  const pct = (remaining / (pollExpiresInSec * 1000)) * 100;
  document.getElementById('expiryBar').style.width = pct + '%';
  document.getElementById('timeRemainingLabel').textContent = Math.ceil(remaining / 1000) + 's remaining';
  if (remaining <= 0 && pollTimer) {
    stopPolling('auth_req_id has expired');
    setStatus('expired');
  }
}

function setStatus(state) {
  const card = document.getElementById('pollStatusCard');
  const icon = document.getElementById('pollStatusIcon');
  const title = document.getElementById('pollStatusTitle');
  card.className = 'poll-status-card mb-3 ' + state;
  const map = {
    waiting: ['⏳', 'Waiting for user approval…'],
    approved: ['✅', 'Approved — tokens received'],
    denied: ['❌', 'Access denied'],
    expired: ['⌛', 'Request expired']
  };
  const [i, t] = map[state] || map.waiting;
  icon.textContent = i;
  title.textContent = t;
}

function addPollEntry({ attempt, pending, slowDown, expired, denied, success, error, statusCode, durationMs, response }) {
  const timeline = document.getElementById('pollTimeline');
  const dotClass = success ? 'dot-success' : denied ? 'dot-denied' : slowDown ? 'dot-slowdown' : expired ? 'dot-expired' : 'dot-pending';
  const label = success ? 'Tokens received' : slowDown ? 'slow_down — interval increased' : expired ? 'expired_token' : denied ? 'access_denied' : error ? 'Error' : 'authorization_pending';

  const entry = document.createElement('div');
  entry.className = 'poll-entry';
  entry.innerHTML = `
    <div class="poll-entry-header" onclick="this.nextElementSibling.classList.toggle('open')">
      <span class="poll-dot ${dotClass}"></span>
      <span style="font-weight:600">#${attempt}</span>
      <span style="color:var(--text-muted)">${escHtml(label)}</span>
      ${statusCode ? `<span class="ms-auto me-2" style="font-size:0.72rem;color:var(--text-muted)">HTTP ${statusCode} · ${durationMs}ms</span>` : ''}
      <i class="bi bi-chevron-down" style="font-size:0.7rem;color:var(--text-muted)"></i>
    </div>
    <div class="poll-entry-body">
      <div class="code-block json" style="max-height:160px">${escHtml(JSON.stringify(response || { error }, null, 2))}</div>
    </div>`;
  timeline.prepend(entry);
}

function showTokenResult(response) {
  document.getElementById('tokenResultArea').style.display = '';
  document.getElementById('rawTokenResponse').textContent = JSON.stringify(response, null, 2);
  if (response?.access_token) document.getElementById('accessTokenDecoded').innerHTML = renderJwtDecoded(response.access_token, 'Access Token');
  if (response?.id_token) document.getElementById('idTokenDecoded').innerHTML = renderJwtDecoded(response.id_token, 'ID Token');
  showTTab('raw');
  document.getElementById('tokenResultArea').scrollIntoView({ behavior: 'smooth' });
}

function showTTab(tab) {
  ['raw', 'access', 'id'].forEach((t, i) => {
    document.getElementById(`tTab${t.charAt(0).toUpperCase() + t.slice(1)}`).style.display = t === tab ? '' : 'none';
    document.querySelectorAll('#tokenTabs .tab-btn')[i].classList.toggle('active', t === tab);
  });
}
