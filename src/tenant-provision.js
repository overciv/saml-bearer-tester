'use strict';
// Uses idp.management_credentials from the tenant webhook to obtain an
// access token, then grants the OAuth API scopes needed to use the
// component's own client_id for admin-style Okta Management API calls
// (policies, users, MFA, apps, API Access Management).

const axios = require('axios');
const { generateClientAssertion } = require('./pkjwt');

// Scopes needed to check policies / MFA policies / users / apps / API access
// management via the Okta Management API on behalf of the demo tenant.
// NOTE: only requested when explicitly asked for (see grantApiScopes callers) —
// the management_credentials service app must already have these granted on
// its own Okta API Scopes tab, or the client_credentials token request itself
// fails with consent_required (Okta rejects the whole request, not just the
// ungranted scopes).
const DEFAULT_SCOPES = [
  'okta.apps.read', 'okta.apps.manage',
  'okta.policies.read', 'okta.policies.manage',
  'okta.users.read', 'okta.users.manage',
  'okta.factors.read', 'okta.factors.manage',
  'okta.authenticators.read', 'okta.authenticators.manage',
  'okta.authorizationServers.read', 'okta.authorizationServers.manage',
  'okta.identityProviders.read', 'okta.identityProviders.manage',
  'okta.logs.read'
];

// Minimal scopes actually needed today: just enough to look up and update the
// tenant's Okta app object (redirect_uris). Kept separate from DEFAULT_SCOPES
// so the management-token request only asks for what's granted right now.
const REDIRECT_URI_SCOPES = ['okta.apps.read', 'okta.apps.manage'];

function normalizeUrl(u) {
  if (!u) return u;
  return /^https?:\/\//i.test(u) ? u : `https://${u}`;
}

function domainOf(u) {
  try { return new URL(normalizeUrl(u)).host; } catch { return u; }
}

// Obtain an access token using whichever credential shape the webhook sent:
// OktaIdpManagementCredentials (clientJWKS -> private_key_jwt) or
// CICIdpManagementCredentials (clientSecret -> client_secret_basic).
// `scopes` MUST be passed — Okta's org authorization server requires an
// explicit scope list on client_credentials requests; omitting it entirely
// gets rejected with consent_required rather than falling back to "whatever
// is granted".
async function getManagementToken(managementCredentials, scopes) {
  const { tokenEndpoint, clientId, clientJWKS, clientSecret } = managementCredentials || {};
  if (!tokenEndpoint || !clientId) throw new Error('management_credentials missing tokenEndpoint/clientId');
  if (!scopes?.length) throw new Error('getManagementToken requires an explicit, non-empty scopes list');
  const ep = normalizeUrl(tokenEndpoint);

  const params = new URLSearchParams({ grant_type: 'client_credentials', scope: scopes.join(' ') });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

  if (clientJWKS) {
    const privateJwk = clientJWKS.keys ? clientJWKS.keys[0] : clientJWKS;
    const { assertion } = await generateClientAssertion({ privateJwk, clientId, audience: ep, validitySeconds: 300 });
    params.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    params.set('client_assertion', assertion);
  } else if (clientSecret) {
    headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  } else {
    throw new Error('management_credentials has neither clientJWKS nor clientSecret');
  }

  const r = await axios.post(ep, params.toString(), { headers, validateStatus: () => true });
  if (r.status >= 300) throw new Error(`Management token request failed: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  return r.data.access_token;
}

// Grants each scope in `scopes` to `clientId` on the org identified by
// `oidcConfiguration.issuer`, via Okta's scope-consent-grant endpoint
// (`POST /oauth2/v1/clients/{clientId}/grants`). Best-effort per scope —
// a failure on one scope doesn't abort the others.
async function grantApiScopes({ oidcConfiguration, accessToken, scopes = DEFAULT_SCOPES }) {
  const oktaDomain = domainOf(oidcConfiguration.issuer);
  const clientId = oidcConfiguration.client_id;
  const base = `https://${oktaDomain}/oauth2/v1/clients/${clientId}/grants`;
  const headers = { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', Accept: 'application/json' };

  const results = [];
  for (const scopeId of scopes) {
    try {
      const r = await axios.post(base, { scopeId, issuer: `https://${oktaDomain}` }, { headers, validateStatus: () => true });
      results.push({ scope: scopeId, ok: r.status < 300, statusCode: r.status, detail: r.status >= 300 ? r.data : undefined });
    } catch (e) {
      results.push({ scope: scopeId, ok: false, statusCode: 0, detail: e.message });
    }
  }
  return results;
}

// This app's own OIDC callback — the redirect_uri that must be registered on
// the tenant's Okta app for login (src/auth.js) to work.
function expectedRedirectUri() {
  const base = process.env.APP_BASE_URL;
  return base ? `${base.replace(/\/+$/, '')}/auth/callback` : null;
}

// Fetches the Okta app instance directly by its ID via the standard
// Management API (Apps), using the Bearer token from management_credentials
// rather than an SSWS admin token (see src/admin-api.js for the SSWS variant).
// For OIDC apps, the app's `id` IS its client_id (both are the same "0oa..."
// value) — no search/filter needed, just GET /api/v1/apps/{clientId}.
async function getAppById({ oktaDomain, accessToken, appId }) {
  const url = `https://${oktaDomain}/api/v1/apps/${appId}`;
  const r = await axios.get(url, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }, validateStatus: () => true });
  if (r.status >= 300) throw new Error(`Get app ${appId} failed: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

// Ensures this app's redirect_uri is registered on the tenant's Okta app,
// adding it alongside whatever redirect_uris are already configured (never
// removes existing ones — other integrations may rely on them).
async function ensureRedirectUri({ oktaDomain, accessToken, clientId }) {
  const redirectUri = expectedRedirectUri();
  if (!redirectUri) return { ok: false, skipped: true, reason: 'APP_BASE_URL is not set — cannot compute redirect_uri' };

  const app = await getAppById({ oktaDomain, accessToken, appId: clientId });
  const oauthClient = app.settings?.oauthClient || {};
  const existing = oauthClient.redirect_uris || [];

  if (existing.includes(redirectUri)) {
    return { ok: true, changed: false, appId: app.id, redirectUri, redirectUris: existing };
  }

  const updated = {
    ...app,
    settings: { ...app.settings, oauthClient: { ...oauthClient, redirect_uris: [...existing, redirectUri] } }
  };

  const r = await axios.put(`https://${oktaDomain}/api/v1/apps/${app.id}`, updated,
    { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', Accept: 'application/json' }, validateStatus: () => true });

  if (r.status >= 300) throw new Error(`Update app redirect_uris failed: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  return { ok: true, changed: true, appId: app.id, redirectUri, redirectUris: r.data.settings?.oauthClient?.redirect_uris };
}

// Full flow, run on every create/update webhook: get a management token
// scoped to just what's needed to update the app object, then make sure
// this app's redirect_uri is registered on the tenant's Okta app. Does NOT
// request the broader DEFAULT_SCOPES grant-to-tenant-client flow — that's a
// separate, opt-in step (see grantDefaultApiScopes) since it requires scopes
// that may not be pre-granted to the management_credentials service app.
// Never throws — errors are captured in the result so tenant creation itself
// isn't blocked by a provisioning failure.
async function provisionTenantScopes(tenant) {
  const oktaDomain = domainOf(tenant.oidcConfiguration.issuer);
  const clientId = tenant.oidcConfiguration.client_id;

  try {
    const accessToken = await getManagementToken(tenant.managementCredentials, REDIRECT_URI_SCOPES);
    const redirectUri = await ensureRedirectUri({ oktaDomain, accessToken, clientId });
    return { ok: redirectUri.ok, managementTokenOk: true, results: [], redirectUri, ranAt: new Date().toISOString() };
  } catch (e) {
    return {
      ok: false, managementTokenOk: false, error: e.message, results: [],
      redirectUri: { ok: false, error: e.message },
      ranAt: new Date().toISOString()
    };
  }
}

// Opt-in, broader admin-API scope grant to the tenant's OIDC client — only
// call this if the management_credentials service app is confirmed to have
// DEFAULT_SCOPES pre-granted on its own Okta API Scopes tab; otherwise the
// token request itself fails with consent_required.
async function grantDefaultApiScopes(tenant) {
  try {
    const accessToken = await getManagementToken(tenant.managementCredentials, DEFAULT_SCOPES);
    const results = await grantApiScopes({ oidcConfiguration: tenant.oidcConfiguration, accessToken });
    return { ok: results.every(r => r.ok), managementTokenOk: true, results, ranAt: new Date().toISOString() };
  } catch (e) {
    return { ok: false, managementTokenOk: false, error: e.message, results: [], ranAt: new Date().toISOString() };
  }
}

module.exports = {
  DEFAULT_SCOPES, REDIRECT_URI_SCOPES,
  getManagementToken, grantApiScopes, grantDefaultApiScopes,
  expectedRedirectUri, getAppById, ensureRedirectUri,
  provisionTenantScopes
};
