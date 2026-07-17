'use strict';
const crypto = require('crypto');
const axios  = require('axios');

// In-memory flow store. Each entry expires after 10 minutes.
const _store = {};
const FLOW_TTL = 600_000;

function _authorizeEp(domain, sid) {
  return sid?.trim()
    ? `https://${domain}/oauth2/${sid}/v1/authorize`
    : `https://${domain}/oauth2/v1/authorize`;
}

function _tokenEp(domain, sid) {
  return sid?.trim()
    ? `https://${domain}/oauth2/${sid}/v1/token`
    : `https://${domain}/oauth2/v1/token`;
}

function startFlow({ oktaDomain, authServerId, clientId, redirectUri, scope }) {
  const verifier  = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest().toString('base64url');
  const state     = crypto.randomBytes(16).toString('hex');
  const flowId    = crypto.randomBytes(8).toString('hex');
  const scopes    = Array.isArray(scope) ? scope.join(' ') : (scope || 'openid');

  _store[flowId] = {
    verifier, state, status: 'pending',
    oktaDomain, authServerId, clientId, redirectUri, scopes,
    createdAt: Date.now()
  };

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri || 'http://localhost:3000/oauth/callback',
    response_type: 'code',
    scope: scopes,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  const authUrl = `${_authorizeEp(oktaDomain, authServerId)}?${params}`;
  return { flowId, authUrl };
}

async function handleCallback({ code, state, error, error_description }) {
  // Match flow by state
  const flowId = Object.keys(_store).find(id => _store[id]?.state === state);
  if (!flowId) return { error: 'Invalid state — no matching flow found' };

  const flow = _store[flowId];

  if (error) {
    flow.status = 'error';
    flow.error  = error_description || error;
    return { flowId, error: flow.error };
  }

  const ep = _tokenEp(flow.oktaDomain, flow.authServerId);
  const params = new URLSearchParams({
    grant_type:    'authorization_code',
    code,
    redirect_uri:  flow.redirectUri || 'http://localhost:3000/oauth/callback',
    code_verifier: flow.verifier,
    client_id:     flow.clientId
  });

  try {
    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      validateStatus: () => true
    });

    if (r.status === 200 && !r.data?.error) {
      flow.status       = 'success';
      flow.tokens       = r.data;
      flow.tokenEndpoint = ep;
    } else {
      flow.status      = 'error';
      flow.error       = r.data?.error_description || r.data?.error || `HTTP ${r.status}`;
      flow.errorDetail = r.data;
    }
  } catch (e) {
    flow.status = 'error';
    flow.error  = e.message;
  }

  return { flowId, status: flow.status, error: flow.error };
}

function getFlowStatus(flowId) {
  const flow = _store[flowId];
  if (!flow) return null;
  if (Date.now() - flow.createdAt > FLOW_TTL) { delete _store[flowId]; return null; }
  return { flowId, status: flow.status, tokens: flow.tokens, error: flow.error, tokenEndpoint: flow.tokenEndpoint };
}

async function clientCredentials({ oktaDomain, authServerId, clientId, clientSecret, privateJwk, scope }) {
  const ep     = _tokenEp(oktaDomain, authServerId);
  const scopes = Array.isArray(scope) ? scope.join(' ') : (scope || 'openid');
  const params = new URLSearchParams({ grant_type: 'client_credentials', scope: scopes });
  const hdrs   = { 'Content-Type': 'application/x-www-form-urlencoded' };

  if (privateJwk) {
    // PKJWT client auth — delegate to existing module
    const { generateClientAssertion } = require('./pkjwt');
    const { assertion } = await generateClientAssertion({ privateJwk, clientId, audience: ep, validitySeconds: 300 });
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', assertion);
    params.set('client_id', clientId);
  } else {
    hdrs['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  }

  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers: hdrs, validateStatus: () => true });
    return { success: r.status < 300 && !r.data?.error, statusCode: r.status, durationMs: Date.now() - t0, tokenEndpoint: ep, response: r.data };
  } catch (e) {
    return { success: false, statusCode: 0, durationMs: Date.now() - t0, tokenEndpoint: ep, error: e.message };
  }
}

module.exports = { startFlow, handleCallback, getFlowStatus, clientCredentials };
