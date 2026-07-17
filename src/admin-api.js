'use strict';
const axios = require('axios');

const json = (token) => ({ Authorization: `SSWS ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' });
const plain = (token) => ({ Authorization: `SSWS ${token}`, Accept: 'application/json' });

async function createApp(params) {
  const { oktaDomain, adminApiToken, _rawPayload, ...rest } = params;

  // If the frontend sends the raw payload (already-built JSON), use it directly
  const payload = _rawPayload
    ? rest  // rest IS the payload (minus oktaDomain / adminApiToken / _rawPayload)
    : (() => {
        const { label, applicationType, tokenEndpointAuthMethod, redirectUris, postLogoutUris, grantTypes } = rest;
        const responseTypes = grantTypes?.includes('authorization_code') ? ['code'] : [];
        return {
          name: 'oidc_client',
          label: label || 'New App via API',
          signOnMode: 'OPENID_CONNECT',
          credentials: { oauthClient: { token_endpoint_auth_method: tokenEndpointAuthMethod || 'client_secret_basic' } },
          settings: {
            oauthClient: {
              redirect_uris: redirectUris?.filter(Boolean) || [],
              post_logout_redirect_uris: postLogoutUris?.filter(Boolean) || [],
              grant_types: grantTypes || ['authorization_code', 'refresh_token'],
              response_types: responseTypes.length ? responseTypes : ['code'],
              application_type: applicationType || 'web'
            }
          }
        };
      })();

  const t0 = Date.now();
  try {
    const r = await axios.post(`https://${oktaDomain}/api/v1/apps`, payload, { headers: json(adminApiToken), validateStatus: () => true });
    return { success: r.status < 300, statusCode: r.status, durationMs: Date.now()-t0, payload, response: r.data };
  } catch (e) { return { success: false, statusCode: 0, durationMs: Date.now()-t0, payload, error: e.message }; }
}

async function assignAppOwner({ oktaDomain, adminApiToken, login, appId, appName }) {
  const base = `https://${oktaDomain}`;
  const hdrs = plain(adminApiToken);
  const steps = [];

  // Step 1: Find user
  const userRes = await axios.get(`${base}/api/v1/users/${encodeURIComponent(login)}`, { headers: hdrs, validateStatus: () => true });
  if (userRes.status !== 200) return { success: false, error: `User not found: ${userRes.data?.errorSummary || `HTTP ${userRes.status}`}`, step: 'find_user' };
  const userId = userRes.data.id;
  steps.push({ step: 'find_user', userId, login: userRes.data.profile?.login });

  // Step 2: Get existing roles — reuse APP_ADMIN if already present
  let roleId = null;
  const rolesRes = await axios.get(`${base}/api/v1/users/${userId}/roles`, { headers: hdrs, validateStatus: () => true });
  if (rolesRes.status === 200) {
    const existing = rolesRes.data.find(r => r.type === 'APP_ADMIN');
    if (existing) { roleId = existing.id; steps.push({ step: 'existing_role', roleId, note: 'APP_ADMIN role already present — reusing' }); }
  }

  // Step 3: Assign APP_ADMIN if not already present
  if (!roleId) {
    const assignRes = await axios.post(`${base}/api/v1/users/${userId}/roles`, { type: 'APP_ADMIN' },
      { headers: { ...hdrs, 'Content-Type': 'application/json' }, validateStatus: () => true });
    if (assignRes.status !== 200 && assignRes.status !== 201) {
      return { success: false, statusCode: assignRes.status, error: assignRes.data?.errorSummary || `HTTP ${assignRes.status}`, step: 'assign_role', steps };
    }
    roleId = assignRes.data.id;
    steps.push({ step: 'assign_role', roleId, statusCode: assignRes.status });
  }

  // Step 4: Scope the role to the specific app instance
  const targetUrl = `${base}/api/v1/users/${userId}/roles/${roleId}/targets/catalog/apps/${appName}/${appId}`;
  const targetRes = await axios.put(targetUrl, {}, { headers: hdrs, validateStatus: () => true });
  steps.push({ step: 'add_app_target', url: targetUrl, statusCode: targetRes.status, success: targetRes.status === 204 || targetRes.status === 200 });

  const ok = targetRes.status === 204 || targetRes.status === 200;
  return { success: ok, statusCode: targetRes.status, roleId, userId, steps };
}

async function getApp({ oktaDomain, adminApiToken, appId }) {
  const t0 = Date.now();
  try {
    const r = await axios.get(`https://${oktaDomain}/api/v1/apps/${appId}`, { headers: plain(adminApiToken), validateStatus: () => true });
    return { success: r.status === 200, statusCode: r.status, durationMs: Date.now()-t0, response: r.data };
  } catch (e) { return { success: false, statusCode: 0, error: e.message }; }
}

async function cloneApp({ oktaDomain, adminApiToken, sourceAppId, newLabel }) {
  const src = await getApp({ oktaDomain, adminApiToken, appId: sourceAppId });
  if (!src.success) return { ...src, step: 'export' };

  const { id, orn, _links, lastUpdated, created, ...clean } = src.response;
  clean.label = newLabel || `${src.response.label} (Clone)`;
  if (clean.credentials?.oauthClient) delete clean.credentials.oauthClient.client_id;

  const t0 = Date.now();
  try {
    const r = await axios.post(`https://${oktaDomain}/api/v1/apps`, clean, { headers: json(adminApiToken), validateStatus: () => true });
    return { success: r.status < 300, statusCode: r.status, durationMs: Date.now()-t0, sourceApp: src.response, clonedPayload: clean, response: r.data };
  } catch (e) { return { success: false, statusCode: 0, durationMs: Date.now()-t0, error: e.message, step: 'create' }; }
}

async function findUser({ oktaDomain, adminApiToken, login }) {
  const t0 = Date.now();
  try {
    const r = await axios.get(`https://${oktaDomain}/api/v1/users/${encodeURIComponent(login)}`, { headers: plain(adminApiToken), validateStatus: () => true });
    return { success: r.status === 200, statusCode: r.status, durationMs: Date.now()-t0, response: r.data };
  } catch (e) { return { success: false, statusCode: 0, error: e.message }; }
}

async function listFactors({ oktaDomain, adminApiToken, userId }) {
  const t0 = Date.now();
  try {
    const r = await axios.get(`https://${oktaDomain}/api/v1/users/${userId}/factors`, { headers: plain(adminApiToken), validateStatus: () => true });
    return { success: r.status === 200, statusCode: r.status, durationMs: Date.now()-t0, response: r.data };
  } catch (e) { return { success: false, statusCode: 0, error: e.message }; }
}

async function resetFactor({ oktaDomain, adminApiToken, userId, factorId }) {
  const t0 = Date.now();
  try {
    const r = await axios.delete(`https://${oktaDomain}/api/v1/users/${userId}/factors/${factorId}`, { headers: plain(adminApiToken), validateStatus: () => true });
    return { success: r.status === 204 || r.status === 200, statusCode: r.status, durationMs: Date.now()-t0 };
  } catch (e) { return { success: false, statusCode: 0, error: e.message }; }
}

async function getSystemLog({ oktaDomain, adminApiToken, since, until, limit = 25, filter, q }) {
  const params = new URLSearchParams({ limit: String(Math.min(limit, 100)) });
  if (since)  params.set('since', since);
  if (until)  params.set('until', until);
  if (filter) params.set('filter', filter);
  if (q)      params.set('q', q);

  const t0 = Date.now();
  try {
    const r = await axios.get(`https://${oktaDomain}/api/v1/logs?${params}`, { headers: plain(adminApiToken), validateStatus: () => true });
    return { success: r.status === 200, statusCode: r.status, durationMs: Date.now()-t0, response: r.data, nextLink: r.headers?.link };
  } catch (e) { return { success: false, statusCode: 0, error: e.message }; }
}

module.exports = { createApp, getApp, cloneApp, findUser, listFactors, resetFactor, getSystemLog, assignAppOwner };
