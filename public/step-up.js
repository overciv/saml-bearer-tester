'use strict';
const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','redirectUri','scope','acrValues','clientAuthMethod','clientSecret'];

let baselineTokens = null;
let stepUpTokens   = null;

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadPageConfig('step-up', CONFIG_FIELDS);
  toggleStepUpAuth();
  window.addEventListener('message', (e) => {
    if (e.data?.type === 'oauth-callback') handlePopupResult(e.data);
  });
});

function toggleStepUpAuth() {
  const m = val('clientAuthMethod');
  document.getElementById('suSecretRow').style.display = m === 'basic'  ? '' : 'none';
  document.getElementById('suPkjwtRow').style.display  = m === 'pkjwt'  ? '' : 'none';
}

// ─── Baseline (standard auth, no acr_values) ──────────────────────────────────

async function getBaseline() {
  const btn = document.getElementById('baselineBtn');
  setLoading(btn, true, '<i class="bi bi-box-arrow-up-right me-1"></i>Opening…');
  await _doAuth(null, 'baseline');
  setLoading(btn, false, '<i class="bi bi-box-arrow-up-right me-1"></i>Get Baseline Token');
}

// ─── Step-Up (with acr_values) ────────────────────────────────────────────────

async function requestStepUp() {
  const btn = document.getElementById('stepUpBtn');
  setLoading(btn, true, '<i class="bi bi-box-arrow-up-right me-1"></i>Opening…');
  await _doAuth(val('acrValues'), 'stepup');
  setLoading(btn, false, '<i class="bi bi-box-arrow-up-right me-1"></i>Request Step-Up');
}

// ─── Shared auth flow ─────────────────────────────────────────────────────────

let _pendingFlowId  = null;
let _pendingTarget  = null; // 'baseline' | 'stepup'
let _pollTimer      = null;

async function _doAuth(acrValues, target) {
  if (!val('clientId') || !val('oktaDomain')) { toast('Fill in Okta Domain and Client ID', 'warning'); return; }

  const authMethod = val('clientAuthMethod') || 'none';
  let privateJwk;
  if (authMethod === 'pkjwt') {
    const raw = document.getElementById('clientPrivateJwk')?.value?.trim();
    if (!raw) { toast('Paste a Private JWK for PKJWT auth', 'warning'); return; }
    try { privateJwk = JSON.parse(raw); } catch { toast('Invalid Private JWK JSON', 'error'); return; }
  }

  const body = {
    oktaDomain: val('oktaDomain'), authServerId: val('authServerId'),
    clientId: val('clientId'), redirectUri: val('redirectUri') || 'http://localhost:3000/oauth/callback',
    scope: val('scope') || 'openid profile email',
    clientAuthMethod: authMethod,
    clientSecret: authMethod === 'basic' ? (document.getElementById('clientSecret')?.value || '') : undefined,
    privateJwk:   authMethod === 'pkjwt' ? privateJwk : undefined,
  };
  if (acrValues) body.acrValues = acrValues;

  const { flowId, authUrl } = await fetch('/api/oauth/start', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
  }).then(r=>r.json());

  _pendingFlowId = flowId;
  _pendingTarget = target;

  const statusId = target === 'baseline' ? 'baselineStatus' : 'stepUpStatus';
  document.getElementById(statusId).style.display = '';
  document.getElementById(statusId).innerHTML =
    `<div class="d-flex align-items-center gap-2"><span class="spinner-border spinner-border-sm" style="color:var(--blue)"></span><span style="font-size:0.82rem">Waiting for login in popup${acrValues ? ` (requesting ACR: <code>${escHtml(acrValues)}</code>)` : ''}…</span></div>`;

  window.open(authUrl, 'okta-auth', 'width=600,height=700,left=200,top=100');

  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
  _pollTimer = setInterval(async () => {
    const s = await fetch(`/api/oauth/status/${_pendingFlowId}`).then(r=>r.json()).catch(()=>null);
    if (!s) return;
    if (s.status === 'success' || s.status === 'error') {
      clearInterval(_pollTimer); _pollTimer = null;
      handlePopupResult({ flowId: _pendingFlowId, status: s.status, tokens: s.tokens, error: s.error });
    }
  }, 1500);
}

function handlePopupResult(data) {
  if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
  const target = _pendingTarget;
  _pendingFlowId = null; _pendingTarget = null;

  const statusId = target === 'baseline' ? 'baselineStatus' : 'stepUpStatus';
  const resultId = target === 'baseline' ? 'baselineResult' : 'stepUpResult';
  const acrId    = target === 'baseline' ? 'baselineAcr' : 'stepUpAcr';

  document.getElementById(statusId).style.display = 'none';

  if (data.status === 'success' && data.tokens) {
    if (target === 'baseline') baselineTokens = data.tokens;
    else stepUpTokens = data.tokens;

    const decoded = data.tokens.access_token ? decodeJwt(data.tokens.access_token) : null;
    const acr  = decoded?.payload?.acr  || '—';
    const amr  = decoded?.payload?.amr  ? decoded.payload.amr.join(', ') : '—';
    const atime = decoded?.payload?.auth_time ? new Date(decoded.payload.auth_time*1000).toISOString().replace('T',' ').slice(0,19) : '—';

    document.getElementById(resultId).style.display = '';
    document.getElementById(acrId).innerHTML =
      `<span style="color:var(--text-muted)">acr: </span><strong style="color:var(--blue)">${escHtml(acr)}</strong>
       &nbsp;&nbsp;<span style="color:var(--text-muted)">amr: </span><strong style="color:var(--blue)">[${escHtml(amr)}]</strong>
       &nbsp;&nbsp;<span style="color:var(--text-muted)">auth_time: </span><strong style="color:var(--blue)">${escHtml(atime)}</strong>`
      + renderHttpExchange({ statusCode:200, durationMs:data.durationMs, requestDetails:data.requestDetails, response:data.tokens });

    toast(`${target === 'baseline' ? 'Baseline' : 'Step-Up'} token received!`, 'success');
    updateComparison();
  } else {
    document.getElementById(statusId).style.display = '';
    document.getElementById(statusId).innerHTML =
      `<span class="status-badge status-err">✗ Failed: ${escHtml(data.error || 'unknown')}</span>`;
    toast((target === 'baseline' ? 'Baseline' : 'Step-Up') + ' auth failed: ' + (data.error || 'unknown'), 'error');
  }
}

// ─── Comparison ───────────────────────────────────────────────────────────────

const COMPARE_KEYS = ['acr','amr','auth_time','sub','email','scp','cid','iss','exp'];

function updateComparison() {
  if (!baselineTokens && !stepUpTokens) return;

  const bDec = baselineTokens?.access_token ? decodeJwt(baselineTokens.access_token)?.payload : null;
  const sDec = stepUpTokens?.access_token   ? decodeJwt(stepUpTokens.access_token)?.payload   : null;

  if (!bDec && !sDec) return;

  document.getElementById('comparePlaceholder').style.display = 'none';
  document.getElementById('compareContent').style.display = '';

  document.getElementById('compareLeft').innerHTML  = renderCompareRows(bDec, sDec);
  document.getElementById('compareRight').innerHTML = renderCompareRows(sDec, bDec, true);
}

function renderCompareRows(primary, other, isAfter = false) {
  if (!primary) return '<div style="padding:12px;color:var(--text-muted);font-size:0.78rem">No token</div>';

  const rows = COMPARE_KEYS.filter(k => primary[k] !== undefined || (other && other[k] !== undefined)).map(k => {
    const myVal    = primary[k];
    const otherVal = other ? other[k] : undefined;
    const disp     = myVal === undefined ? '—' : Array.isArray(myVal) ? `[${myVal.join(', ')}]` : (typeof myVal === 'number' && String(myVal).length === 10 ? new Date(myVal*1000).toISOString().replace('T',' ').slice(0,19) : String(myVal));
    const changed  = isAfter && JSON.stringify(myVal) !== JSON.stringify(otherVal);
    return `<div class="compare-row">
      <span class="compare-label">${escHtml(k)}</span>
      <span class="compare-val ${changed?'changed':'same'}">${escHtml(disp)}</span>
    </div>`;
  });

  const extras = Object.keys(primary).filter(k => !COMPARE_KEYS.includes(k)).map(k =>
    `<div class="compare-row"><span class="compare-label" style="opacity:0.5">${escHtml(k)}</span><span class="compare-val same" style="opacity:0.5">${escHtml(String(primary[k])||'—')}</span></div>`
  );

  return rows.join('') + (extras.length ? `<div style="border-top:1px solid var(--border)">${extras.join('')}</div>` : '');
}
