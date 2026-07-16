'use strict';

const CONFIG_FIELDS = ['oktaDomain', 'authServerId', 'clientId', 'clientSecret', 'clientAuthMethod'];

// Key claims to surface in the comparison view
const COMPARE_CLAIMS = ['cid', 'iss', 'sub', 'aud', 'scp', 'scope', 'act', 'exp', 'iat', 'jti'];

let scopeMgr;
let actorVisible = false;
let lastSubjectDecoded = null;
let lastResultDecoded = null;

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadPageConfig('token-exchange', CONFIG_FIELDS);
  scopeMgr = createScopeManager('scopeTags', 'scopeInput', ['openid']);
  setupEndpointPreview();
  toggleAuthMethod();
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

function toggleAuthMethod() {
  const isPkjwt = val('clientAuthMethod') === 'pkjwt';
  document.getElementById('secretRow').style.display = isPkjwt ? 'none' : '';
  document.getElementById('pkjwtRow').style.display = isPkjwt ? '' : 'none';
}

function toggleActorSection() {
  actorVisible = !actorVisible;
  document.getElementById('actorSection').style.display = actorVisible ? '' : 'none';
  document.getElementById('actorToggleBtn').innerHTML = actorVisible
    ? '<i class="bi bi-dash me-1"></i>Remove Actor Token'
    : '<i class="bi bi-plus me-1"></i>Add Actor Token (delegation)';
}

// ─── Subject token decode preview ─────────────────────────────────────────────
function decodeSubjectToken() {
  const token = val('subjectToken');
  if (!token) { toast('Paste a subject token first', 'warning'); return; }
  const decoded = decodeJwt(token);
  if (!decoded) { toast('Not a valid JWT — cannot decode inline', 'warning'); return; }
  lastSubjectDecoded = decoded.payload;
  document.getElementById('subjectDecoded').style.display = '';
  document.getElementById('subjectClaimsTable').innerHTML = renderClaimsTable(decoded.payload, null);
}

// ─── Exchange ──────────────────────────────────────────────────────────────────
async function performExchange() {
  const btn = document.getElementById('exchangeBtn');
  setLoading(btn, true, '<i class="bi bi-arrow-left-right me-1"></i>Exchange Token');

  const isPkjwt = val('clientAuthMethod') === 'pkjwt';
  const missing = [];
  if (!val('oktaDomain')) missing.push('Okta Domain');
  if (!val('clientId'))   missing.push('App B Client ID');
  if (!val('subjectToken')) missing.push('Subject Token');
  if (!isPkjwt && !document.getElementById('clientSecret')?.value) missing.push('Client Secret');
  if (missing.length) { toast('Missing: ' + missing.join(', '), 'warning'); setLoading(btn, false, '<i class="bi bi-arrow-left-right me-1"></i>Exchange Token'); return; }

  let privateJwk;
  if (isPkjwt) {
    try { privateJwk = JSON.parse(val('clientPrivateJwk')); }
    catch { toast('Invalid private JWK JSON', 'error'); setLoading(btn, false, '<i class="bi bi-arrow-left-right me-1"></i>Exchange Token'); return; }
  }

  const reqBody = {
    oktaDomain: val('oktaDomain'),
    authServerId: val('authServerId'),
    clientId: val('clientId'),
    clientSecret: isPkjwt ? undefined : (document.getElementById('clientSecret')?.value || ''),
    privateJwk,
    subjectToken: val('subjectToken'),
    subjectTokenType: val('subjectTokenType'),
    scope: scopeMgr.state.list,
    requestedTokenType: val('requestedTokenType') || undefined,
    audience: val('audience') || undefined,
    resource: val('resource') || undefined,
    actorToken: actorVisible ? val('actorToken') || undefined : undefined,
    actorTokenType: actorVisible ? val('actorTokenType') || undefined : undefined
  };

  try {
    const res = await post('/api/token-exchange/exchange', reqBody);

    // Show result section
    document.getElementById('resultPlaceholder').style.display = 'none';
    document.getElementById('resultContent').style.display = '';

    document.getElementById('resultStatus').innerHTML =
      `${statusBadge(res.statusCode)}<span style="font-size:0.75rem;color:var(--text-muted);margin-left:8px">${res.durationMs}ms · ${res.tokenEndpoint}</span>`;

    document.getElementById('reqDetailsEl').textContent = JSON.stringify(res.requestDetails, null, 2);
    document.getElementById('rawResponseEl').textContent = JSON.stringify(res.response || res.error, null, 2);

    // Comparison
    if (res.subjectDecoded && res.resultDecoded) {
      lastSubjectDecoded = res.subjectDecoded;
      lastResultDecoded  = res.resultDecoded;
      document.getElementById('comparisonSection').style.display = '';
      document.getElementById('subjectCompare').innerHTML = renderClaimsTable(res.subjectDecoded, res.resultDecoded);
      document.getElementById('resultCompare').innerHTML  = renderClaimsTable(res.resultDecoded, res.subjectDecoded, true);

      // Also update Step 2 preview
      document.getElementById('subjectDecoded').style.display = '';
      document.getElementById('subjectClaimsTable').innerHTML = renderClaimsTable(res.subjectDecoded, null);
    } else {
      document.getElementById('comparisonSection').style.display = 'none';
    }

    if (res.response?.access_token) {
      document.getElementById('decodedResultEl').innerHTML = renderJwtDecoded(res.response.access_token, 'Result Access Token');
    } else if (res.success) {
      document.getElementById('decodedResultEl').innerHTML = `<div class="code-block json">${escHtml(JSON.stringify(res.response, null, 2))}</div>`;
    } else {
      document.getElementById('decodedResultEl').innerHTML = `<div class="code-block" style="color:var(--red)">${escHtml(JSON.stringify(res.response || res.error, null, 2))}</div>`;
    }

    showTab('request');
    document.getElementById('step-result').scrollIntoView({ behavior: 'smooth' });
    toast(res.success ? 'Token exchanged successfully!' : 'Exchange failed — see response', res.success ? 'success' : 'error');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-arrow-left-right me-1"></i>Exchange Token');
  }
}

// ─── Claims comparison table ───────────────────────────────────────────────────
function renderClaimsTable(primary, other, isResult = false) {
  if (!primary) return '<div style="padding:12px;color:var(--text-muted);font-size:0.78rem">No JWT payload</div>';

  const rows = COMPARE_CLAIMS
    .filter(k => primary[k] !== undefined || (other && other[k] !== undefined))
    .map(k => {
      const myVal   = primary[k];
      const otherVal = other ? other[k] : undefined;
      const display  = formatClaim(myVal);
      let cls = 'same';

      if (isResult) {
        // This IS the result token — highlight what changed vs subject
        if (myVal === undefined) cls = 'same';
        else if (otherVal === undefined) cls = 'added';
        else if (JSON.stringify(myVal) !== JSON.stringify(otherVal)) cls = 'changed';
        else cls = 'same';
      }

      return `<div class="compare-row">
        <span class="compare-label">${escHtml(k)}</span>
        <span class="compare-val ${cls}">${escHtml(display)}</span>
      </div>`;
    });

  // Add any extra claims from primary not in COMPARE_CLAIMS
  const extraClaims = Object.keys(primary).filter(k => !COMPARE_CLAIMS.includes(k));
  const extras = extraClaims.map(k => {
    const display = formatClaim(primary[k]);
    return `<div class="compare-row">
      <span class="compare-label" style="opacity:0.6">${escHtml(k)}</span>
      <span class="compare-val same" style="opacity:0.6">${escHtml(display)}</span>
    </div>`;
  });

  return rows.join('') + (extras.length ? `<div style="border-top:1px solid var(--border)">${extras.join('')}</div>` : '');
}

function formatClaim(val) {
  if (val === undefined || val === null) return '—';
  if (typeof val === 'number' && (String(val).length === 10)) {
    // likely a unix timestamp
    return `${val} (${new Date(val * 1000).toISOString().replace('T', ' ').slice(0, 19)})`;
  }
  if (Array.isArray(val)) return val.join(' ');
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

// ─── Tabs ──────────────────────────────────────────────────────────────────────
function showTab(tab) {
  ['request', 'raw', 'decoded'].forEach((t, i) => {
    document.getElementById(`tab${t.charAt(0).toUpperCase() + t.slice(1)}`).style.display = t === tab ? '' : 'none';
    document.querySelectorAll('#resultTabs .tab-btn')[i].classList.toggle('active', t === tab);
  });
}
