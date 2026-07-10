'use strict';
const express = require('express');
const axios = require('axios');
const path = require('path');
const { generateKeyPair: samlGenKeyPair, generateAssertion, decodeAssertionBase64 } = require('./src/saml');
const { generateDpopKeyPair, generateDpopProof, validateDpopProof } = require('./src/dpop');
const { generatePkjwtKeyPair, generateClientAssertion, validateClientAssertion } = require('./src/pkjwt');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Shared helpers ────────────────────────────────────────────────────────────

function tokenEndpoint(domain, serverId) {
  return serverId?.trim()
    ? `https://${domain}/oauth2/${serverId.trim()}/v1/token`
    : `https://${domain}/oauth2/v1/token`;
}

function introspectEndpoint(domain, serverId) {
  return serverId?.trim()
    ? `https://${domain}/oauth2/${serverId.trim()}/v1/introspect`
    : `https://${domain}/oauth2/v1/introspect`;
}

// ─── SAML routes ───────────────────────────────────────────────────────────────

app.post('/api/saml/generate-keypair', async (req, res) => {
  try { res.json(await samlGenKeyPair()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/saml/generate-assertion', (req, res) => {
  try { res.json(generateAssertion(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/saml/decode-assertion', (req, res) => {
  try {
    if (!req.body.encoded) return res.status(400).json({ error: 'encoded is required' });
    res.json({ xml: decodeAssertionBase64(req.body.encoded) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/saml/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, scope, assertion } = req.body;
  const ep = tokenEndpoint(oktaDomain, authServerId);
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;
  const params = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer', assertion, scope: scopes });
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${credentials}` },
      validateStatus: () => true
    });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now() - t0, tokenEndpoint: ep,
      requestDetails: { url: ep, headers: { 'Authorization': `Basic ${credentials.substring(0,8)}...`, 'DPoP': undefined }, body: { grant_type: params.get('grant_type'), scope: scopes, assertion: assertion.substring(0,40)+'...' } },
      response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now() - t0, tokenEndpoint: ep, error: { message: e.message } });
  }
});

// Legacy routes (backward compat with existing app.js)
app.post('/api/generate-keypair', async (req, res) => {
  try { res.json(await samlGenKeyPair()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/generate-assertion', (req, res) => {
  try { res.json(generateAssertion(req.body)); }
  catch (e) { res.status(400).json({ error: e.message, detail: e.stack }); }
});
app.post('/api/decode-assertion', (req, res) => {
  try {
    if (!req.body.encoded) return res.status(400).json({ error: 'encoded is required' });
    res.json({ xml: decodeAssertionBase64(req.body.encoded) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, scope, assertion } = req.body;
  const ep = tokenEndpoint(oktaDomain, authServerId);
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;
  const params = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer', assertion, scope: scopes });
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${credentials}` },
      validateStatus: () => true
    });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now() - t0, tokenEndpoint: ep,
      requestDetails: { url: ep, method: 'POST', headers: { 'Authorization': `Basic ${credentials.substring(0,8)}...` }, body: { grant_type: params.get('grant_type'), scope: scopes, assertion: assertion.substring(0,40)+'...' } },
      response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now() - t0, tokenEndpoint: ep, error: { message: e.message } });
  }
});

// ─── DPoP routes ───────────────────────────────────────────────────────────────

app.post('/api/dpop/generate-keypair', async (req, res) => {
  try { res.json(await generateDpopKeyPair(req.body.alg || 'ES256')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/dpop/generate-proof', async (req, res) => {
  try { res.json(await generateDpopProof(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/dpop/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, scope, grantType = 'client_credentials',
    refreshToken, privateJwk, publicJwk } = req.body;

  const ep = tokenEndpoint(oktaDomain, authServerId);
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;
  const steps = [];

  async function attempt(nonce) {
    const proofResult = await generateDpopProof({ privateJwk, publicJwk, htm: 'POST', htu: ep, nonce });
    steps.push({ type: 'proof', label: nonce ? 'DPoP Proof #2 (with nonce)' : 'DPoP Proof #1 (no nonce)', ...proofResult });

    const params = new URLSearchParams({ grant_type: grantType, scope: scopes });
    if (grantType === 'refresh_token' && refreshToken) params.set('refresh_token', refreshToken);

    const reqHeaders = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
      'DPoP': proofResult.proof
    };
    const t0 = Date.now();
    const response = await axios.post(ep, params.toString(), { headers: reqHeaders, validateStatus: () => true });
    const durationMs = Date.now() - t0;

    steps.push({
      type: 'request',
      label: nonce ? 'Token Request #2 (retry)' : 'Token Request #1',
      method: 'POST', url: ep,
      headers: { 'Authorization': `Basic ${credentials.substring(0,8)}...`, 'DPoP': proofResult.proof.substring(0,60)+'...' },
      body: Object.fromEntries(params), durationMs
    });
    steps.push({ type: 'response', label: `Response: HTTP ${response.status}`, statusCode: response.status, data: response.data, responseHeaders: response.headers });
    return response;
  }

  try {
    const r1 = await attempt();

    if (r1.status === 400 && r1.data?.error === 'use_dpop_nonce') {
      const nonce = r1.headers['dpop-nonce'];
      steps.push({ type: 'nonce', label: 'Nonce Required — retrying', nonce, detail: 'Server returned use_dpop_nonce. Regenerating DPoP proof with nonce and retrying.' });
      const r2 = await attempt(nonce);
      return res.json({ success: r2.status < 300, statusCode: r2.status, steps, response: r2.data, tokenEndpoint: ep, usedNonce: true, nonce });
    }

    res.json({ success: r1.status < 300, statusCode: r1.status, steps, response: r1.data, tokenEndpoint: ep, usedNonce: false });
  } catch (e) {
    res.json({ success: false, steps, error: e.message, tokenEndpoint: ep });
  }
});

app.post('/api/dpop/validate-proof', async (req, res) => {
  try { res.json(await validateDpopProof(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/dpop/resource-proof', async (req, res) => {
  // Generate a DPoP proof for a resource server request (includes ath)
  try {
    const result = await generateDpopProof({ ...req.body });
    const { htm, htu, accessToken } = req.body;
    const curlCmd = [
      `curl -X ${htm} '${htu}'`,
      `  -H 'Authorization: DPoP ${accessToken}'`,
      `  -H 'DPoP: ${result.proof}'`
    ].join(' \\\n');
    res.json({ ...result, curlCmd });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ─── Private Key JWT routes ────────────────────────────────────────────────────

app.post('/api/pkjwt/generate-keypair', async (req, res) => {
  try { res.json(await generatePkjwtKeyPair(req.body.alg || 'RS256')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pkjwt/generate-assertion', async (req, res) => {
  try { res.json(await generateClientAssertion(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/pkjwt/exchange-token', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientAssertion, scope,
    grantType = 'client_credentials', authCode, redirectUri, codeVerifier } = req.body;

  const ep = tokenEndpoint(oktaDomain, authServerId);
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;

  const params = new URLSearchParams({
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    grant_type: grantType,
    scope: scopes
  });
  if (grantType === 'authorization_code' && authCode) {
    params.set('code', authCode);
    params.set('redirect_uri', redirectUri || '');
    if (codeVerifier) params.set('code_verifier', codeVerifier);
  }

  const displayParams = {
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion.substring(0, 60) + '...',
    grant_type: grantType,
    scope: scopes
  };

  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      validateStatus: () => true
    });
    res.json({
      success: r.status < 300, statusCode: r.status, durationMs: Date.now() - t0,
      tokenEndpoint: ep,
      requestDetails: { url: ep, method: 'POST', note: 'No Authorization header — client identity proven via client_assertion', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: displayParams },
      response: r.data
    });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now() - t0, tokenEndpoint: ep, error: { message: e.message } });
  }
});

app.post('/api/pkjwt/validate-assertion', async (req, res) => {
  try { res.json(await validateClientAssertion(req.body)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/pkjwt/introspect', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, clientAssertion, token, tokenTypeHint } = req.body;
  const ep = introspectEndpoint(oktaDomain, authServerId);

  const params = new URLSearchParams({ token });
  if (tokenTypeHint) params.set('token_type_hint', tokenTypeHint);

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' };
  if (clientAssertion) {
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', clientAssertion);
  } else if (clientSecret) {
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers, validateStatus: () => true });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now() - t0, introspectEndpoint: ep, response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now() - t0, introspectEndpoint: ep, error: { message: e.message } });
  }
});

// ─── Shared introspect (usable from any page) ─────────────────────────────────
app.post('/api/introspect', async (req, res) => {
  const { oktaDomain, authServerId, clientId, clientSecret, token, tokenTypeHint } = req.body;
  const ep = introspectEndpoint(oktaDomain, authServerId);
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const params = new URLSearchParams({ token });
  if (tokenTypeHint) params.set('token_type_hint', tokenTypeHint);
  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${credentials}` },
      validateStatus: () => true
    });
    res.json({ success: r.status < 300, statusCode: r.status, durationMs: Date.now() - t0, introspectEndpoint: ep, response: r.data });
  } catch (e) {
    res.json({ success: false, statusCode: 0, durationMs: Date.now() - t0, introspectEndpoint: ep, error: { message: e.message } });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n⚡ Okta OAuth Super Tester running at http://localhost:${PORT}`);
  console.log(`   SAML Bearer  → http://localhost:${PORT}/`);
  console.log(`   DPoP         → http://localhost:${PORT}/dpop.html`);
  console.log(`   Private Key JWT → http://localhost:${PORT}/pkjwt.html\n`);
});
