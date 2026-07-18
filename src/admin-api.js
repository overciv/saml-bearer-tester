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

async function factorChallenge({ oktaDomain, adminApiToken, userId, factorId, passCode }) {
  const url  = `https://${oktaDomain}/api/v1/users/${userId}/factors/${factorId}/verify`;
  const body = passCode ? { passCode } : {};
  const hdrs = { ...plain(adminApiToken), 'Content-Type': 'application/json' };
  const t0   = Date.now();
  try {
    const r = await axios.post(url, body, { headers: hdrs, validateStatus: () => true });
    const result = r.data?.factorResult;
    return {
      success:      r.status === 200 && (result === 'SUCCESS' || result === 'WAITING'),
      statusCode:   r.status,
      durationMs:   Date.now() - t0,
      factorResult: result,
      pollHref:     r.data?._links?.poll?.href,
      response:     r.data
    };
  } catch (e) { return { success: false, statusCode: 0, error: e.message }; }
}

async function factorPoll({ adminApiToken, pollHref }) {
  const hdrs = { 'Authorization': `SSWS ${adminApiToken}`, 'Accept': 'application/json' };
  const t0   = Date.now();
  try {
    const r = await axios.get(pollHref, { headers: hdrs, validateStatus: () => true });
    return { statusCode: r.status, durationMs: Date.now() - t0, factorResult: r.data?.factorResult, response: r.data };
  } catch (e) { return { statusCode: 0, factorResult: 'ERROR', error: e.message }; }
}

async function deleteApp({ oktaDomain, adminApiToken, appId }) {
  const base = `https://${oktaDomain}/api/v1/apps/${appId}`;
  const hdrs = plain(adminApiToken);
  const steps = [];

  // Step 1: deactivate (Okta requires INACTIVE before DELETE)
  const t0 = Date.now();
  const deact = await axios.post(`${base}/lifecycle/deactivate`, {}, { headers: hdrs, validateStatus: () => true });
  steps.push({ step: 'deactivate', statusCode: deact.status, ok: deact.status === 200, durationMs: Date.now() - t0 });
  if (deact.status !== 200) {
    return { success: false, statusCode: deact.status, error: deact.data?.errorSummary || `Deactivate failed HTTP ${deact.status}`, steps };
  }

  // Step 2: delete
  const t1 = Date.now();
  const del = await axios.delete(base, { headers: hdrs, validateStatus: () => true });
  steps.push({ step: 'delete', statusCode: del.status, ok: del.status === 204, durationMs: Date.now() - t1 });

  return { success: del.status === 204, statusCode: del.status, steps };
}

async function enrollFactor({ oktaDomain, adminApiToken, userId, factorType, provider }) {
  const t0 = Date.now();
  // activate=false: let the user complete enrollment (scan QR / tap security key)
  // rather than Okta attempting immediate activation
  const url = `https://${oktaDomain}/api/v1/users/${userId}/factors?activate=false`;
  try {
    const r = await axios.post(url, { factorType, provider },
      { headers: json(adminApiToken), validateStatus: () => true }
    );
    const d = r.data;
    return {
      success: r.status < 300,
      statusCode: r.status, durationMs: Date.now()-t0,
      factorId:      d?.id,
      // Push: QR code image URL + activation polling URL
      qrCodeUrl:     d?._links?.activation?.qrcode?.href,
      activationUrl: d?._links?.activation?.href,
      // WebAuthn: challenge data + activate URL
      webauthnActivation: d?._embedded?.activation,
      activateHref:  d?._links?.activate?.href,
      response: d
    };
  } catch (e) { return { success:false, statusCode:0, durationMs:Date.now()-t0, error:e.message }; }
}

async function activateFactor({ oktaDomain, adminApiToken, activateUrl, activationData }) {
  const t0 = Date.now();
  try {
    const r = await axios.post(activateUrl, activationData,
      { headers: json(adminApiToken), validateStatus: () => true });
    return { success: r.status < 300, statusCode: r.status, durationMs: Date.now()-t0, response: r.data };
  } catch (e) { return { success:false, statusCode:0, durationMs:Date.now()-t0, error:e.message }; }
}

async function pollFactorActivation({ adminApiToken, activationUrl }) {
  const t0 = Date.now();
  try {
    const r = await axios.get(activationUrl,
      { headers: plain(adminApiToken), validateStatus: () => true });
    return { statusCode: r.status, durationMs: Date.now()-t0, factorResult: r.data?.factorResult, response: r.data };
  } catch (e) { return { statusCode:0, factorResult:'ERROR', error:e.message }; }
}

module.exports = { createApp, getApp, cloneApp, findUser, listFactors, resetFactor, getSystemLog, assignAppOwner, deleteApp, factorChallenge, factorPoll, enrollFactor, activateFactor, pollFactorActivation };
