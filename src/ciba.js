'use strict';
const axios = require('axios');
const { generateClientAssertion } = require('./pkjwt');

function bcAuthorizeEndpoint(domain, serverId) {
  return serverId?.trim()
    ? `https://${domain}/oauth2/${serverId}/v1/bc/authorize`
    : `https://${domain}/oauth2/v1/bc/authorize`;
}

function tokenEndpoint(domain, serverId) {
  return serverId?.trim()
    ? `https://${domain}/oauth2/${serverId}/v1/token`
    : `https://${domain}/oauth2/v1/token`;
}

async function backchannelAuthorize({
  oktaDomain, authServerId, clientId, clientSecret,
  loginHint, idTokenHint, bindingMessage, scope, requestExpiry,
  // PKJWT auth
  privateJwk
}) {
  const ep = bcAuthorizeEndpoint(oktaDomain, authServerId);
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;

  const params = new URLSearchParams({ scope: scopes });
  if (loginHint) params.set('login_hint', loginHint);
  if (idTokenHint) params.set('id_token_hint', idTokenHint);
  if (bindingMessage) params.set('binding_message', bindingMessage);
  if (requestExpiry) params.set('request_expiry', String(requestExpiry));

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

  if (privateJwk) {
    // PKJWT client auth — client_assertion replaces Authorization header
    const audience = ep; // bc/authorize endpoint as audience
    const { assertion } = await generateClientAssertion({ privateJwk, clientId, audience, validitySeconds: 300 });
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', assertion);
    params.set('client_id', clientId);
  } else {
    headers['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  }

  const requestDetails = {
    method: 'POST', url: ep,
    headers: { ...headers, Authorization: headers.Authorization ? `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64').substring(0, 8)}...` : '(via client_assertion)' },
    body: { scope: scopes, login_hint: loginHint, id_token_hint: idTokenHint ? '[id_token_hint present]' : undefined, binding_message: bindingMessage, request_expiry: requestExpiry }
  };

  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers, validateStatus: () => true });
    return {
      success: r.status >= 200 && r.status < 300,
      statusCode: r.status, durationMs: Date.now() - t0,
      endpoint: ep, requestDetails, response: r.data
    };
  } catch (e) {
    return { success: false, statusCode: 0, durationMs: Date.now() - t0, endpoint: ep, requestDetails, error: e.message };
  }
}

async function pollToken({
  oktaDomain, authServerId, clientId, clientSecret,
  authReqId, scope,
  privateJwk
}) {
  const ep = tokenEndpoint(oktaDomain, authServerId);
  const scopes = Array.isArray(scope) ? scope.join(' ') : scope;

  const params = new URLSearchParams({
    grant_type: 'urn:openid:params:grant-type:ciba',
    auth_req_id: authReqId,
    scope: scopes
  });

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

  if (privateJwk) {
    const { assertion } = await generateClientAssertion({ privateJwk, clientId, audience: ep, validitySeconds: 300 });
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', assertion);
    params.set('client_id', clientId);
  } else {
    headers['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  }

  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers, validateStatus: () => true });
    const err = r.data?.error;
    return {
      statusCode: r.status, durationMs: Date.now() - t0,
      endpoint: ep, response: r.data,
      pending:   err === 'authorization_pending',
      slowDown:  err === 'slow_down',
      expired:   err === 'expired_token',
      denied:    err === 'access_denied',
      success:   r.status >= 200 && r.status < 300 && !err
    };
  } catch (e) {
    return { statusCode: 0, durationMs: Date.now() - t0, endpoint: ep, error: e.message, pending: false, success: false };
  }
}

module.exports = { backchannelAuthorize, pollToken };
