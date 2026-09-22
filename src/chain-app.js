'use strict';
// Auto-provisions a single Okta OIDC app per Test Chain workspace (public/workflow.js),
// so the chain builder doesn't require a manually pre-created app before you can run it.
// Reuses the same management_credentials / scope machinery as src/tenant-provision.js.

const axios = require('axios');
const { getManagementToken, REDIRECT_URI_SCOPES } = require('./tenant-provision');
const { upsertTenant } = require('./tenant-store');

function normalizeUrl(u) {
  if (!u) return u;
  return /^https?:\/\//i.test(u) ? u : `https://${u}`;
}

function domainOf(u) {
  try { return new URL(normalizeUrl(u)).host; } catch { return u; }
}

function chainAppRedirectUri() {
  const base = process.env.APP_BASE_URL || 'http://localhost:3001';
  return `${base.replace(/\/+$/, '')}/oauth/callback`;
}

// Pure read — no Okta calls. `tenant` is expected already-decrypted (as
// returned by tenant-store.getTenant).
function getChainApp(tenant, chainId) {
  const entry = tenant?.chainApps?.[chainId];
  if (!entry) return { exists: false };
  return { exists: true, ...entry };
}

// Idempotent: if this workspace already has an app on record, return it
// without calling Okta again.
async function createChainApp({ tenant, chainId, chainLabel, user }) {
  if (!chainId) throw new Error('chainId is required');
  const existing = tenant?.chainApps?.[chainId];
  if (existing) return { exists: true, ...existing };

  const oktaDomain = domainOf(tenant.oidcConfiguration.issuer);
  const accessToken = await getManagementToken(tenant.managementCredentials, REDIRECT_URI_SCOPES);
  const redirectUri = chainAppRedirectUri();

  const payload = {
    name: 'oidc_client',
    label: chainLabel || `Test Chain (${chainId})`,
    signOnMode: 'OPENID_CONNECT',
    credentials: { oauthClient: { token_endpoint_auth_method: 'client_secret_basic' } },
    settings: {
      oauthClient: {
        redirect_uris: [redirectUri],
        grant_types: [
          'authorization_code', 'refresh_token', 'client_credentials', 'password',
          'urn:ietf:params:oauth:grant-type:saml2-bearer', 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        ],
        response_types: ['code'],
        application_type: 'web'
      }
    }
  };

  const headers = { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', Accept: 'application/json' };
  const r = await axios.post(`https://${oktaDomain}/api/v1/apps`, payload, { headers, validateStatus: () => true });
  if (r.status >= 300) throw new Error(`Create app failed: HTTP ${r.status} ${JSON.stringify(r.data)}`);

  const oauthClient = r.data.credentials?.oauthClient || {};
  const appId = r.data.id;
  const clientId = oauthClient.client_id;
  const clientSecret = oauthClient.client_secret;

  // Best-effort: assign the current logged-in user so they can log into this
  // app immediately (Auth Code / ROPC / Step-Up steps need a real user).
  let userAssigned = false;
  if (user?.sub) {
    try {
      const ar = await axios.post(`https://${oktaDomain}/api/v1/apps/${appId}/users`,
        { id: user.sub, scope: 'USER' },
        { headers, validateStatus: () => true });
      userAssigned = ar.status < 300;
    } catch { /* best-effort — app creation still succeeds */ }
  }

  const entry = { appId, clientId, clientSecret, redirectUri, createdAt: new Date().toISOString() };
  await upsertTenant({ id: tenant.id, chainApps: { ...tenant.chainApps, [chainId]: entry } });

  return { exists: true, ...entry, userAssigned };
}

// No-op success if no app is on record for this workspace.
async function deleteChainApp({ tenant, chainId }) {
  const entry = tenant?.chainApps?.[chainId];
  if (!entry) return { exists: false, deleted: false };

  const oktaDomain = domainOf(tenant.oidcConfiguration.issuer);
  const accessToken = await getManagementToken(tenant.managementCredentials, REDIRECT_URI_SCOPES);
  const headers = { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' };
  const base = `https://${oktaDomain}/api/v1/apps/${entry.appId}`;

  const deact = await axios.post(`${base}/lifecycle/deactivate`, {}, { headers, validateStatus: () => true });
  if (deact.status !== 200) throw new Error(`Deactivate app failed: HTTP ${deact.status} ${JSON.stringify(deact.data)}`);

  const del = await axios.delete(base, { headers, validateStatus: () => true });
  if (del.status !== 204) throw new Error(`Delete app failed: HTTP ${del.status} ${JSON.stringify(del.data)}`);

  const chainApps = { ...tenant.chainApps };
  delete chainApps[chainId];
  await upsertTenant({ id: tenant.id, chainApps });

  return { exists: false, deleted: true };
}

module.exports = { getChainApp, createChainApp, deleteChainApp };
