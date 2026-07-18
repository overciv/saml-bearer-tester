'use strict';
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');

const { generateKeyPair: samlGenKeyPair, generateAssertion, decodeAssertionBase64 } = require('./src/saml');
const { generateDpopKeyPair, generateDpopProof, validateDpopProof } = require('./src/dpop');
const { generatePkjwtKeyPair, generateClientAssertion, validateClientAssertion } = require('./src/pkjwt');
const { backchannelAuthorize, pollToken } = require('./src/ciba');
const { exchange: tokenExchange } = require('./src/token-exchange');
const { revokeAndVerify, getTokenLifetime } = require('./src/token-inspector');
const { startFlow, handleCallback, getFlowStatus, clientCredentials, resourceOwnerPassword } = require('./src/auth-code');
const { createApp, getApp, cloneApp, findUser, listFactors, resetFactor, getSystemLog, assignAppOwner, deleteApp, factorChallenge, factorPoll, enrollFactor, activateFactor, pollFactorActivation } = require('./src/admin-api');
const { getConfig, saveConfig, getSigningKey, generateSigningKey, getPublicJwks, getPublicConfig } = require('./src/config');
const { requireAuth, loginHandler, callbackHandler, logoutHandler, meHandler } = require('./src/auth');

// ─── Bootstrap ────────────────────────────────────────────────────────────────

const cfg = getConfig();  // ensure config.json created + session secret available

const app = express();
app.use(express.json({ limit: '2mb' }));

app.use(session({
  secret: cfg.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

// ─── Auth routes (always accessible) ─────────────────────────────────────────

app.get('/auth/login', loginHandler);
app.get('/auth/callback', callbackHandler);
app.get('/auth/logout', logoutHandler);
app.get('/auth/jwks', (req, res) => res.json(getPublicJwks()));
app.get('/api/auth/me', meHandler);

// ─── Settings API (mostly open — see requireAuth for POST restriction) ────────

app.get('/api/settings', (req, res) => {
  const jwks = getPublicJwks();
  res.json({ ...getPublicConfig(), signingKey: { jwks, hasKey: jwks.keys.length > 0 } });
});

app.post('/api/settings', (req, res) => {
  try {
    const saved = saveConfig(req.body);
    const signingKey = getPublicJwks();
    res.json({ ...getPublicConfig(), signingKey: { jwks: signingKey, hasKey: signingKey.keys.length > 0 } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/generate-signing-key', async (req, res) => {
  try {
    const key = await generateSigningKey();
    res.json({ kid: key.kid, alg: key.alg, jwks: { keys: [key.publicJwk] } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Auth guard (protects static files + API routes below) ───────────────────

app.use(requireAuth);

// Root redirect: / → /home.html  (SAML page lives at /index.html)
app.get('/', (req, res) => res.redirect('/home.html'));

app.use(express.static(path.join(__dirname, 'public')));

// ─── Shared helpers ───────────────────────────────────────────────────────────

function tokenEp(domain, sid) {
  return sid?.trim() ? `https://${domain}/oauth2/${sid.trim()}/v1/token` : `https://${domain}/oauth2/v1/token`;
}
function introspectEp(domain, sid) {
  return sid?.trim() ? `https://${domain}/oauth2/${sid.trim()}/v1/introspect` : `https://${domain}/oauth2/v1/introspect`;
}

// ─── SAML routes ──────────────────────────────────────────────────────────────

app.post('/api/generate-keypair', async (req, res) => {
  try { res.json(await samlGenKeyPair()); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/generate-assertion', (req, res) => {
  try { res.json(generateAssertion(req.body)); } catch (e) { res.status(400).json({ error: e.message, detail: e.stack }); }
});
app.post('/api/decode-assertion', (req, res) => {
  try {
    if (!req.body.encoded) return res.status(400).json({ error: 'encoded is required' });
    res.json({ xml: decodeAssertionBase64(req.body.encoded) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, scope, assertion } = req.body;
  const ep = tokenEp(oktaDomain, authServerId);
  const creds = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;
  const params = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer', assertion, scope: scopes });
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` }, validateStatus: () => true });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now() - t0, tokenEndpoint: ep,
      requestDetails: { url: ep, method: 'POST', headers: { 'Authorization': `Basic ${creds.substring(0,8)}...` }, body: { grant_type: params.get('grant_type'), scope: scopes, assertion: assertion.substring(0,40)+'...' } }, response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now() - t0, tokenEndpoint: ep, error: { message: e.message } });
  }
});

// ─── DPoP routes ──────────────────────────────────────────────────────────────

app.post('/api/dpop/generate-keypair', async (req, res) => {
  try { res.json(await generateDpopKeyPair(req.body.alg || 'ES256')); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/dpop/generate-proof', async (req, res) => {
  try { res.json(await generateDpopProof(req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/dpop/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, scope, grantType = 'client_credentials', refreshToken, privateJwk, publicJwk } = req.body;
  const ep = tokenEp(oktaDomain, authServerId);
  const creds = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;
  const steps = [];

  async function attempt(nonce) {
    const proofResult = await generateDpopProof({ privateJwk, publicJwk, htm: 'POST', htu: ep, nonce });
    steps.push({ type: 'proof', label: nonce ? 'DPoP Proof #2 (with nonce)' : 'DPoP Proof #1 (no nonce)', ...proofResult });
    const params = new URLSearchParams({ grant_type: grantType, scope: scopes });
    if (grantType === 'refresh_token' && refreshToken) params.set('refresh_token', refreshToken);
    const t0 = Date.now();
    const response = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}`, 'DPoP': proofResult.proof },
      validateStatus: () => true
    });
    steps.push({ type: 'request', label: nonce ? 'Token Request #2 (retry)' : 'Token Request #1', method: 'POST', url: ep,
      headers: { 'Authorization': `Basic ${creds.substring(0,8)}...`, 'DPoP': proofResult.proof.substring(0,60)+'...' }, body: Object.fromEntries(params), durationMs: Date.now()-t0 });
    steps.push({ type: 'response', label: `Response: HTTP ${response.status}`, statusCode: response.status, data: response.data, responseHeaders: response.headers });
    return response;
  }

  try {
    const r1 = await attempt();
    if (r1.status === 400 && r1.data?.error === 'use_dpop_nonce') {
      const nonce = r1.headers['dpop-nonce'];
      steps.push({ type: 'nonce', label: 'Nonce Required — retrying', nonce, detail: 'Server returned use_dpop_nonce. Regenerating proof with nonce.' });
      const r2 = await attempt(nonce);
      return res.json({ success: r2.status < 300, statusCode: r2.status, steps, response: r2.data, tokenEndpoint: ep, usedNonce: true, nonce });
    }
    res.json({ success: r1.status < 300, statusCode: r1.status, steps, response: r1.data, tokenEndpoint: ep, usedNonce: false });
  } catch (e) {
    res.json({ success: false, steps, error: e.message, tokenEndpoint: ep });
  }
});
app.post('/api/dpop/validate-proof', async (req, res) => {
  try { res.json(await validateDpopProof(req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/dpop/resource-proof', async (req, res) => {
  try {
    const result = await generateDpopProof({ ...req.body });
    const { htm, htu, accessToken } = req.body;
    res.json({ ...result, curlCmd: `curl -X ${htm} '${htu}' \\\n  -H 'Authorization: DPoP ${accessToken}' \\\n  -H 'DPoP: ${result.proof}'` });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ─── Private Key JWT routes ───────────────────────────────────────────────────

app.post('/api/pkjwt/generate-keypair', async (req, res) => {
  try { res.json(await generatePkjwtKeyPair(req.body.alg || 'RS256')); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/pkjwt/generate-assertion', async (req, res) => {
  try { res.json(await generateClientAssertion(req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/pkjwt/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientAssertion, scope, grantType = 'client_credentials', authCode, redirectUri, codeVerifier } = req.body;
  const ep = tokenEp(oktaDomain, authServerId);
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;
  const params = new URLSearchParams({ client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: clientAssertion, grant_type: grantType, scope: scopes });
  if (grantType === 'authorization_code' && authCode) { params.set('code', authCode); params.set('redirect_uri', redirectUri || ''); if (codeVerifier) params.set('code_verifier', codeVerifier); }
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, validateStatus: () => true });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now()-t0, tokenEndpoint: ep,
      requestDetails: { url: ep, method: 'POST', note: 'No Authorization header — client proven via client_assertion', body: { client_assertion_type: params.get('client_assertion_type'), client_assertion: clientAssertion.substring(0,60)+'...', grant_type: grantType, scope: scopes } }, response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now()-t0, tokenEndpoint: ep, error: { message: e.message } });
  }
});
app.post('/api/pkjwt/validate-assertion', async (req, res) => {
  try { res.json(await validateClientAssertion(req.body)); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/pkjwt/introspect', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, clientAssertion, token, tokenTypeHint } = req.body;
  const ep = introspectEp(oktaDomain, authServerId);
  const params = new URLSearchParams({ token });
  if (tokenTypeHint) params.set('token_type_hint', tokenTypeHint);
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' };
  if (clientAssertion) { params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'); params.set('client_assertion', clientAssertion); }
  else if (clientSecret) { headers['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`; }
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers, validateStatus: () => true });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now()-t0, introspectEndpoint: ep, response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now()-t0, introspectEndpoint: ep, error: { message: e.message } });
  }
});

// ─── CIBA routes ──────────────────────────────────────────────────────────────

// ─── Auth Code + PKCE + Client Credentials ────────────────────────────────────

app.post('/api/oauth/start', (req, res) => {
  try { res.json(startFlow(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/oauth/callback', async (req, res) => {
  const result = await handleCallback(req.query);
  const { flowId, status, error } = result;
  const isOk = status === 'success';
  const statusResult = flowId ? getFlowStatus(flowId) : null;
  const tokens = statusResult?.tokens || null;

  res.send(`<!DOCTYPE html><html><head><title>${isOk ? 'Login successful' : 'Login failed'}</title>
<style>body{font-family:system-ui;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:12px}</style>
</head><body>
<div style="font-size:2.5rem">${isOk ? '✅' : '❌'}</div>
<div style="font-weight:600">${isOk ? 'Authentication successful' : 'Authentication failed'}</div>
<div style="font-size:0.82rem;color:#8b949e">${isOk ? 'You can close this window' : escHtmlServer(error || 'Unknown error')}</div>
<script>
  const payload = ${JSON.stringify({ type:'oauth-callback', flowId, status, tokens: isOk ? tokens : null, error: isOk ? null : (error||null), durationMs: statusResult?.durationMs || null, requestDetails: statusResult?.requestDetails || null, tokenEndpoint: statusResult?.tokenEndpoint || null })};
  if (window.opener) { try { window.opener.postMessage(payload, '*'); } catch(e){} }
  if (${isOk}) setTimeout(() => { try { window.close(); } catch(e){} }, 1200);
</script></body></html>`);
});

app.get('/api/oauth/status/:flowId', (req, res) => {
  const s = getFlowStatus(req.params.flowId);
  if (!s) return res.status(404).json({ error: 'Flow not found or expired' });
  res.json(s);
});

app.post('/api/oauth/client-creds', async (req, res) => {
  try { res.json(await clientCredentials(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/oauth/ropc', async (req, res) => {
  try { res.json(await resourceOwnerPassword(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

function escHtmlServer(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ─── Token Inspector routes (Thématique 2) ────────────────────────────────────

app.post('/api/token/revoke-and-verify', async (req, res) => {
  try { res.json(await revokeAndVerify(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/token/lifetime', async (req, res) => {
  try { res.json(await getTokenLifetime(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Admin API routes (Thématique 3) ─────────────────────────────────────────

app.post('/api/admin/create-app', async (req, res) => {
  try { res.json(await createApp(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/get-app', async (req, res) => {
  try { res.json(await getApp(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/clone-app', async (req, res) => {
  try { res.json(await cloneApp(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/find-user', async (req, res) => {
  try { res.json(await findUser(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/list-factors', async (req, res) => {
  try { res.json(await listFactors(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/enroll-factor', async (req, res) => {
  try { res.json(await enrollFactor(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/activate-factor', async (req, res) => {
  try { res.json(await activateFactor(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/poll-factor-activation', async (req, res) => {
  try { res.json(await pollFactorActivation(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/reset-factor', async (req, res) => {
  try { res.json(await resetFactor(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/factor-challenge', async (req, res) => {
  try { res.json(await factorChallenge(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/factor-poll', async (req, res) => {
  try { res.json(await factorPoll(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/delete-app', async (req, res) => {
  try { res.json(await deleteApp(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/assign-app-owner', async (req, res) => {
  try { res.json(await assignAppOwner(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/system-log', async (req, res) => {
  try { res.json(await getSystemLog(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Token Exchange routes (RFC 8693) ────────────────────────────────────────

app.post('/api/token-exchange/exchange', async (req, res) => {
  try { res.json(await tokenExchange(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── CIBA routes ──────────────────────────────────────────────────────────────

app.post('/api/ciba/backchannel-authorize', async (req, res) => {
  try { res.json(await backchannelAuthorize(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ciba/poll', async (req, res) => {
  try { res.json(await pollToken(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/introspect', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, token, tokenTypeHint } = req.body;
  const ep = introspectEp(oktaDomain, authServerId);
  const creds = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const params = new URLSearchParams({ token });
  if (tokenTypeHint) params.set('token_type_hint', tokenTypeHint);
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` }, validateStatus: () => true });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now()-t0, introspectEndpoint: ep, response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now()-t0, introspectEndpoint: ep, error: { message: e.message } });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

(async () => {
  await getSigningKey();  // generate on first run
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`\n⚡ Okta OAuth Super Tester  →  http://localhost:${PORT}`);
    console.log(`   SAML        →  http://localhost:${PORT}/`);
    console.log(`   DPoP        →  http://localhost:${PORT}/dpop.html`);
    console.log(`   Priv Key JWT → http://localhost:${PORT}/pkjwt.html`);
  console.log(`   CIBA         → http://localhost:${PORT}/ciba.html`);
  console.log(`   Token Exch   → http://localhost:${PORT}/token-exchange.html`);
  console.log(`   Token Insp   → http://localhost:${PORT}/token-inspector.html`);
  console.log(`   Admin API    → http://localhost:${PORT}/admin.html`);
    console.log(`   Settings    →  http://localhost:${PORT}/settings.html\n`);
  });
})();
