'use strict';
const axios = require('axios');
const { generateClientAssertion } = require('./pkjwt');

// RFC 8693 token type URNs
const TOKEN_TYPES = {
  access_token:  'urn:ietf:params:oauth:token-type:access_token',
  id_token:      'urn:ietf:params:oauth:token-type:id_token',
  refresh_token: 'urn:ietf:params:oauth:token-type:refresh_token',
  jwt:           'urn:ietf:params:oauth:token-type:jwt',
  saml1:         'urn:ietf:params:oauth:token-type:saml1',
  saml2:         'urn:ietf:params:oauth:token-type:saml2',
};

function tokenEndpoint(domain, serverId) {
  return serverId?.trim()
    ? `https://${domain}/oauth2/${serverId}/v1/token`
    : `https://${domain}/oauth2/v1/token`;
}

function decodeJwtPayload(token) {
  try {
    const parts = (token || '').split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch { return null; }
}

async function exchange({
  oktaDomain, authServerId,
  clientId, clientSecret, privateJwk,
  subjectToken, subjectTokenType,
  actorToken, actorTokenType,
  requestedTokenType, audience, resource, scope
}) {
  const ep = tokenEndpoint(oktaDomain, authServerId);
  const scopes = Array.isArray(scope) ? scope.join(' ') : (scope || 'openid');

  const params = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: subjectToken,
    subject_token_type: subjectTokenType || TOKEN_TYPES.access_token,
    scope: scopes
  });

  if (actorToken)         params.set('actor_token', actorToken);
  if (actorTokenType)     params.set('actor_token_type', actorTokenType);
  if (requestedTokenType) params.set('requested_token_type', requestedTokenType);
  if (audience)           params.set('audience', audience);
  if (resource)           params.set('resource', resource);

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

  if (privateJwk) {
    const { assertion } = await generateClientAssertion({ privateJwk, clientId, audience: ep, validitySeconds: 300 });
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', assertion);
    params.set('client_id', clientId);
  } else {
    headers['Authorization'] = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  }

  const requestDetails = {
    method: 'POST', url: ep,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(headers.Authorization ? { Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64').substring(0, 8)}...` } : { client_assertion: '(via PKJWT)' })
    },
    body: {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subjectToken.substring(0, 40) + '...',
      subject_token_type: params.get('subject_token_type'),
      scope: scopes,
      ...(audience ? { audience } : {}),
      ...(resource ? { resource } : {}),
      ...(requestedTokenType ? { requested_token_type: requestedTokenType } : {}),
      ...(actorToken ? { actor_token: actorToken.substring(0, 20) + '...', actor_token_type: actorTokenType } : {})
    }
  };

  // Decode subject token regardless of network outcome so the comparison always works
  const subjectDecoded = decodeJwtPayload(subjectToken);

  const t0 = Date.now();
  try {
    const r = await axios.post(ep, params.toString(), { headers, validateStatus: () => true });
    const resultDecoded = r.data?.access_token ? decodeJwtPayload(r.data.access_token) : null;

    return {
      success: r.status >= 200 && r.status < 300 && !r.data?.error,
      statusCode: r.status, durationMs: Date.now() - t0,
      tokenEndpoint: ep, requestDetails,
      response: r.data,
      subjectDecoded,
      resultDecoded
    };
  } catch (e) {
    return { success: false, statusCode: 0, durationMs: Date.now() - t0, tokenEndpoint: ep, requestDetails, error: e.message, subjectDecoded };
  }
}

module.exports = { exchange, TOKEN_TYPES };
