'use strict';

const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','clientSecret','dpopAlg'];
let scopeMgr;
let currentToken = null;
let currentPrivateJwk = null;
let currentPublicJwk = null;

document.addEventListener('DOMContentLoaded', () => {
  window._pageSave = () => savePageConfig('dpop', CONFIG_FIELDS);
  initNavAuth();
  loadPageConfig('dpop', CONFIG_FIELDS);
  scopeMgr = createScopeManager('scopeTags', 'scopeInput', ['openid']);
  setupEndpointPreview();
  updateGrantFields();
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
}

function updateGrantFields() {
  const isRefresh = val('grantType') === 'refresh_token';
  document.getElementById('refreshTokenRow').style.display = isRefresh ? '' : 'none';
}

// ─── Step 2: Key Generation ────────────────────────────────────────────────────
async function generateKeys() {
  const btn = document.getElementById('genKeysBtn');
  setLoading(btn, true, '<i class="bi bi-shuffle me-1"></i>Generate Key Pair');
  try {
    const alg = val('dpopAlg') || 'ES256';
    const res = await post('/api/dpop/generate-keypair', { alg });
    currentPrivateJwk = res.privateJwk;
    currentPublicJwk = res.publicJwk;

    document.getElementById('privateJwk').value = JSON.stringify(res.privateJwk, null, 2);
    document.getElementById('publicJwk').value = JSON.stringify(res.publicJwk, null, 2);
    document.getElementById('jktDisplay').textContent = res.thumbprint;

    toast('DPoP key pair generated (EC/RSA — algorithm: ' + res.alg + ')', 'success');
  } catch (e) {
    toast('Key generation failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-shuffle me-1"></i>Generate Key Pair');
  }
}

function getJwks() {
  try {
    const priv = JSON.parse(val('privateJwk'));
    const pub = JSON.parse(val('publicJwk'));
    return { privateJwk: priv, publicJwk: pub };
  } catch {
    throw new Error('Invalid JWK JSON — generate or paste valid JWKs in Step 2');
  }
}

// ─── Step 3: Token Acquisition ─────────────────────────────────────────────────
async function acquireToken() {
  const btn = document.getElementById('acquireBtn');
  setLoading(btn, true, '<i class="bi bi-play-fill me-1"></i>Acquire Token');

  const required = { 'Okta Domain': val('oktaDomain'), 'Client ID': val('clientId') };
  const missing = Object.entries(required).filter(([,v]) => !v).map(([k]) => k);
  if (missing.length) { toast('Missing: ' + missing.join(', '), 'warning'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Acquire Token'); return; }
  if (!val('privateJwk') || !val('publicJwk')) { toast('Generate a DPoP key pair in Step 2 first', 'warning'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Acquire Token'); return; }

  let jwks;
  try { jwks = getJwks(); } catch (e) { toast(e.message, 'error'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Acquire Token'); return; }

  try {
    const res = await post('/api/dpop/exchange-token', {
      oktaDomain: val('oktaDomain'),
      authServerId: val('authServerId'),
      clientId: val('clientId'),
      clientSecret: val('clientSecret'),
      scope: scopeMgr.getAll(),
      grantType: val('grantType'),
      refreshToken: val('refreshToken'),
      privateJwk: jwks.privateJwk,
      publicJwk: jwks.publicJwk
    });

    renderFlowTimeline(res.steps);
    document.getElementById('flowTimeline').style.display = '';
    document.getElementById('tokenResult').style.display = '';

    const ok = res.success;
    document.getElementById('tokenResultStatus').innerHTML =
      renderHttpExchange({ url:res.tokenEndpoint, statusCode:res.statusCode,
        durationMs: res.steps?.filter(s=>s.type==='request').reduce((t,s)=>t+(s.durationMs||0),0),
        response:res.response })
      + (res.usedNonce ? `<div style="font-size:0.75rem;color:var(--yellow);margin-top:4px"><i class="bi bi-key me-1"></i>Nonce was required and used</div>` : '');

    document.getElementById('rawTokenResp').textContent = JSON.stringify(res.response, null, 2);

    if (ok && res.response?.access_token) {
      currentToken = res.response.access_token;
      document.getElementById('resourceAccessToken').value = currentToken;
      document.getElementById('valToken').value = currentToken;
      document.getElementById('valHtu').value = document.getElementById('endpointPreview').textContent;
      document.getElementById('accessTokenDecoded').innerHTML = renderJwtDecoded(currentToken, 'Access Token');
    }
    if (res.response?.refresh_token) {
      document.getElementById('refreshTokenInfo').textContent = `refresh_token: ${res.response.refresh_token}\n\ntoken_type: ${res.response.token_type}\nexpires_in: ${res.response.expires_in}s`;
    }

    showTTab('raw');
    toast(ok ? 'Token acquired!' : 'Exchange failed — see flow', ok ? 'success' : 'error');
  } catch (e) {
    toast('Request failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Acquire Token');
  }
}

// Thin wrapper — the per-item rendering itself lives in common.js's
// renderNetworkEntry() so the same timeline UI is shared with the Test Chain's
// live network panel (public/workflow.js).
function renderFlowTimeline(steps) {
  const container = document.getElementById('flowItems');
  container.innerHTML = steps.map(renderNetworkEntry).join('');
  // Standalone page behavior: last item starts expanded.
  const bodies = container.querySelectorAll('.flow-item-body');
  if (bodies.length) bodies[bodies.length - 1].classList.add('open');
  container.querySelectorAll('[data-bs-toggle="popover"]').forEach(el => {
    if (!el._popoverInited && window.bootstrap?.Popover) { new bootstrap.Popover(el, { container: 'body' }); el._popoverInited = true; }
  });
}

function showTTab(tab) {
  ['raw','access','refresh'].forEach((t,i) => {
    document.getElementById(`tTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#tokenTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

// ─── Step 4: Resource Access ───────────────────────────────────────────────────
async function generateResourceProof() {
  const btn = document.getElementById('resourceBtn');
  setLoading(btn, true, '<i class="bi bi-shield-fill me-1"></i>Generating...');

  const resourceUrl = val('resourceUrl');
  const htm = val('resourceMethod') || 'GET';
  const accessToken = val('resourceAccessToken');

  if (!resourceUrl) { toast('Enter a resource URL', 'warning'); setLoading(btn, false, '<i class="bi bi-shield-fill me-1"></i>Generate Resource Proof'); return; }
  if (!accessToken) { toast('Paste or acquire an access token first', 'warning'); setLoading(btn, false, '<i class="bi bi-shield-fill me-1"></i>Generate Resource Proof'); return; }

  let jwks;
  try { jwks = getJwks(); } catch (e) { toast(e.message, 'error'); setLoading(btn, false, '<i class="bi bi-shield-fill me-1"></i>Generate Resource Proof'); return; }

  try {
    const res = await post('/api/dpop/resource-proof', {
      privateJwk: jwks.privateJwk, publicJwk: jwks.publicJwk,
      htm, htu: resourceUrl, accessToken
    });

    document.getElementById('resourceOutput').style.display = '';

    document.getElementById('resProofHeader').textContent = JSON.stringify(res.decodedHeader, null, 2);
    document.getElementById('resProofPayload').textContent = JSON.stringify(res.decodedPayload, null, 2);

    const headers = {
      'Authorization': `DPoP ${accessToken.substring(0,30)}...`,
      'DPoP': res.proof.substring(0,60) + '...'
    };
    document.getElementById('resHeaders').textContent = JSON.stringify(headers, null, 2);
    document.getElementById('resCurl').textContent = res.curlCmd;

    // Auto-fill validator
    document.getElementById('valProof').value = res.proof;
    document.getElementById('valToken').value = accessToken;
    document.getElementById('valHtm').value = htm;
    document.getElementById('valHtu').value = resourceUrl;

    showRTab('proof');
    toast('Resource DPoP proof generated (includes ath)', 'success');
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-shield-fill me-1"></i>Generate Resource Proof');
  }
}

function showRTab(tab) {
  ['proof','headers','curl'].forEach((t,i) => {
    document.getElementById(`rTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#resourceTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

// ─── Step 5: Proof Validator ───────────────────────────────────────────────────
async function validateProof() {
  const btn = document.getElementById('validateBtn');
  setLoading(btn, true, '<i class="bi bi-check2-all me-1"></i>Validating...');
  try {
    const res = await post('/api/dpop/validate-proof', {
      proof: val('valProof'),
      accessToken: val('valToken') || undefined,
      htm: val('valHtm') || 'GET',
      htu: val('valHtu')
    });
    document.getElementById('valResult').style.display = '';
    document.getElementById('valResultContent').innerHTML = renderValidationResults(res.results, res.valid);
    toast(res.valid ? 'All checks passed!' : 'Some checks failed', res.valid ? 'success' : 'error');
  } catch (e) {
    toast('Validation error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-check2-all me-1"></i>Validate');
  }
}
