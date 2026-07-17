'use strict';

const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','pkjwtAlg','validitySeconds'];
let scopeMgr;
let currentAssertion = null;
let currentPublicJwk = null;

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadPageConfig('pkjwt', CONFIG_FIELDS);
  scopeMgr = createScopeManager('scopeTags', 'scopeInput', ['openid']);
  setupEndpointPreview();
});

function setupEndpointPreview() {
  ['oktaDomain','authServerId'].forEach(id =>
    document.getElementById(id)?.addEventListener('input', updateEndpointPreview));
  updateEndpointPreview();
}

function updateEndpointPreview() {
  const domain = val('oktaDomain');
  const sid = val('authServerId');
  const ep = domain ? (sid ? `https://${domain}/oauth2/${sid}/v1/token` : `https://${domain}/oauth2/v1/token`) : '—';
  document.getElementById('endpointPreview').textContent = ep;
  const audEl = document.getElementById('assertionAud');
  if (audEl && ep !== '—') audEl.value = ep;
}

// ─── Step 2: Key Generation ────────────────────────────────────────────────────
async function generateKeys() {
  const btn = document.getElementById('genKeysBtn');
  setLoading(btn, true, '<i class="bi bi-shuffle me-1"></i>Generating... (~2s)');
  try {
    const alg = val('pkjwtAlg') || 'RS256';
    const res = await post('/api/pkjwt/generate-keypair', { alg });
    currentPublicJwk = res.publicJwk;

    document.getElementById('privateJwk').value = JSON.stringify(res.privateJwk, null, 2);
    document.getElementById('jwksOutput').value = JSON.stringify(res.jwks, null, 2);
    document.getElementById('kidDisplay').textContent = res.kid;

    // Pre-fill validator fields
    document.getElementById('valPublicJwk').value = JSON.stringify(res.publicJwk, null, 2);
    document.getElementById('valClientId').value = val('clientId') || '';
    document.getElementById('valAudience').value = document.getElementById('endpointPreview').textContent;

    toast(`Key pair generated (${res.alg}) — copy JWKS to Okta`, 'success');
  } catch (e) {
    toast('Key generation failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-shuffle me-1"></i>Generate Key Pair');
  }
}

// ─── Step 3: Client Assertion ─────────────────────────────────────────────────
async function generateAssertion() {
  const btn = document.getElementById('genAssertBtn');
  setLoading(btn, true, '<i class="bi bi-play-fill me-1"></i>Generating...');

  const clientId = val('clientId');
  const audience = val('assertionAud') || document.getElementById('endpointPreview').textContent;
  const privateJwkRaw = val('privateJwk');

  if (!clientId) { toast('Enter Client ID in Step 1', 'warning'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion'); return; }
  if (!privateJwkRaw) { toast('Generate a signing key in Step 2 first', 'warning'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion'); return; }
  if (!audience || audience === '—') { toast('Enter Okta domain in Step 1 to auto-fill audience', 'warning'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion'); return; }

  let privateJwk;
  try { privateJwk = JSON.parse(privateJwkRaw); } catch { toast('Invalid private JWK JSON', 'error'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion'); return; }

  try {
    const res = await post('/api/pkjwt/generate-assertion', {
      privateJwk,
      clientId,
      audience,
      validitySeconds: parseInt(val('validitySeconds')) || 300
    });

    currentAssertion = res.assertion;

    document.getElementById('rawAssertion').textContent = res.assertion;
    document.getElementById('assertionHeader').textContent = JSON.stringify(res.header, null, 2);
    document.getElementById('assertionPayload').textContent = JSON.stringify(res.claims, null, 2);
    document.getElementById('assertionOutput').style.display = '';

    // Auto-fill exchange + validation
    document.getElementById('exchangeAssertion').value = res.assertion;
    document.getElementById('valAssertionJwt').value = res.assertion;
    document.getElementById('valClientId').value = clientId;
    document.getElementById('valAudience').value = audience;

    showATab('raw');
    toast('Client assertion JWT generated', 'success');
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Generate Assertion');
  }
}

function useAssertionForExchange() {
  if (currentAssertion) {
    document.getElementById('exchangeAssertion').value = currentAssertion;
    document.getElementById('step-exchange').scrollIntoView({ behavior: 'smooth' });
    toast('Assertion loaded into token exchange', 'info');
  }
}

function showATab(tab) {
  document.getElementById('aTabRaw').style.display = tab==='raw'?'':'none';
  document.getElementById('aTabDecoded').style.display = tab==='decoded'?'':'none';
  document.querySelectorAll('#assertionTabs .tab-btn').forEach((btn,i) => btn.classList.toggle('active', (i===0&&tab==='raw')||(i===1&&tab==='decoded')));
}

// ─── Step 4: Token Exchange ────────────────────────────────────────────────────
async function exchangeToken() {
  const btn = document.getElementById('exchangeBtn');
  setLoading(btn, true, '<i class="bi bi-send-fill me-1"></i>Exchanging...');

  const clientAssertion = val('exchangeAssertion');
  if (!clientAssertion) { toast('Generate a client assertion in Step 3 first', 'warning'); setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Exchange Token'); return; }
  if (!val('oktaDomain') || !val('clientId')) { toast('Fill in Okta domain and Client ID', 'warning'); setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Exchange Token'); return; }

  try {
    const res = await post('/api/pkjwt/exchange-token', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      clientAssertion,
      scope: scopeMgr.getAll(),
      grantType: val('grantType')
    });

    document.getElementById('exchangeResult').style.display = '';
    document.getElementById('exchangeStatus').innerHTML =
      renderHttpExchange({ url:res.tokenEndpoint, statusCode:res.statusCode, durationMs:res.durationMs,
        requestDetails:res.requestDetails, response:res.response||res.error });
    document.getElementById('exchangeReqDetails').textContent = JSON.stringify(res.requestDetails, null, 2);
    document.getElementById('exchRawResp').textContent = JSON.stringify(res.response || res.error, null, 2);

    if (res.response?.access_token) {
      document.getElementById('exchAccessDecoded').innerHTML = renderJwtDecoded(res.response.access_token, 'Access Token');
      document.getElementById('introspectToken').value = res.response.access_token;
    }
    if (res.response?.id_token) {
      document.getElementById('exchIdDecoded').innerHTML = renderJwtDecoded(res.response.id_token, 'ID Token');
    }

    showETab('raw');
    toast(res.success ? 'Tokens received!' : 'Exchange failed — see response', res.success ? 'success' : 'error');
  } catch (e) {
    toast('Request failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-send-fill me-1"></i>Exchange Token');
  }
}

function showETab(tab) {
  ['raw','access','id'].forEach((t,i) => {
    document.getElementById(`eTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#exchTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

// ─── Step 5: Validate & Introspect ────────────────────────────────────────────
function showVTab(tab) {
  ['assertion','introspect','decode'].forEach((t,i) => {
    document.getElementById(`vTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#validateTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

async function validateAssertion() {
  const btn = document.getElementById('valAssertBtn');
  setLoading(btn, true, '<i class="bi bi-check2-all me-1"></i>Validating...');
  try {
    const publicJwkRaw = val('valPublicJwk');
    if (!publicJwkRaw) { toast('Paste or generate a public JWK', 'warning'); return; }
    const publicJwk = JSON.parse(publicJwkRaw);

    const res = await post('/api/pkjwt/validate-assertion', {
      assertion: val('valAssertionJwt'),
      publicJwk,
      clientId: val('valClientId'),
      audience: val('valAudience')
    });

    document.getElementById('valAssertResult').style.display = '';
    document.getElementById('valAssertResult').innerHTML = renderValidationResults(res.results, res.valid);
    toast(res.valid ? 'All checks passed!' : 'Some checks failed', res.valid ? 'success' : 'error');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-check2-all me-1"></i>Validate');
  }
}

async function introspectToken() {
  const btn = document.getElementById('introspectBtn');
  setLoading(btn, true, '<i class="bi bi-search me-1"></i>Introspecting...');
  try {
    const res = await post('/api/pkjwt/introspect', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      clientSecret: val('introspectSecret') || undefined,
      clientAssertion: val('exchangeAssertion') || undefined,
      token: val('introspectToken'),
      tokenTypeHint: val('introspectHint')
    });

    document.getElementById('introspectResult').style.display = '';
    document.getElementById('introspectStatus').innerHTML =
      `${statusBadge(res.statusCode)}<span style="font-size:0.75rem;color:var(--text-muted);margin-left:8px">${res.introspectEndpoint}</span>` +
      (res.response?.active ? ` <span class="status-badge status-ok ms-2">active</span>` : res.response?.active === false ? ` <span class="status-badge status-err ms-2">inactive</span>` : '');
    document.getElementById('introspectRaw').textContent = JSON.stringify(res.response || res.error, null, 2);
    toast(res.success ? 'Introspection complete' : 'Introspection failed', res.success ? 'success' : 'error');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-search me-1"></i>Introspect');
  }
}

function decodeTokenManual() {
  const token = val('decodeTokenInput');
  if (!token) { toast('Paste a JWT first', 'warning'); return; }
  document.getElementById('decodeTokenResult').innerHTML = renderJwtDecoded(token, 'Token');
}
