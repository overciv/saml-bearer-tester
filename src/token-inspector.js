'use strict';
const axios = require('axios');

function revokeEp(domain, sid) {
  return sid?.trim() ? `https://${domain}/oauth2/${sid}/v1/revoke` : `https://${domain}/oauth2/v1/revoke`;
}
function introspectEp(domain, sid) {
  return sid?.trim() ? `https://${domain}/oauth2/${sid}/v1/introspect` : `https://${domain}/oauth2/v1/introspect`;
}

async function revokeAndVerify({ oktaDomain, authServerId, clientId, clientSecret, token, tokenTypeHint }) {
  const revEp  = revokeEp(oktaDomain, authServerId);
  const intEp  = introspectEp(oktaDomain, authServerId);
  const creds  = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const hdrs   = { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` };
  const steps  = [];

  // Step 1: Revoke
  const params1 = new URLSearchParams({ token });
  if (tokenTypeHint) params1.set('token_type_hint', tokenTypeHint);
  let t0 = Date.now();
  try {
    const r1 = await axios.post(revEp, params1.toString(), { headers: hdrs, validateStatus: () => true });
    steps.push({ label: 'Revoke (RFC 7009)', method: 'POST', url: revEp, statusCode: r1.status, durationMs: Date.now()-t0,
      body: Object.fromEntries(params1), success: r1.status === 200,
      note: 'RFC 7009: server returns 200 regardless of whether token existed' });
  } catch (e) {
    steps.push({ label: 'Revoke', url: revEp, error: e.message, success: false });
    return { success: false, steps };
  }

  // Step 2: Verify with introspect
  const params2 = new URLSearchParams({ token });
  if (tokenTypeHint) params2.set('token_type_hint', tokenTypeHint);
  t0 = Date.now();
  try {
    const r2 = await axios.post(intEp, params2.toString(), { headers: hdrs, validateStatus: () => true });
    const active = r2.data?.active === true;
    steps.push({ label: 'Verify revocation (introspect)', method: 'POST', url: intEp, statusCode: r2.status, durationMs: Date.now()-t0,
      response: r2.data, success: !active,
      note: active ? '⚠️ Token still active — revocation may have failed' : '✅ active: false — token successfully revoked' });
    return { success: !active, revoked: !active, steps };
  } catch (e) {
    steps.push({ label: 'Verify', url: intEp, error: e.message, success: false });
    return { success: false, steps };
  }
}

async function getTokenLifetime({ oktaDomain, authServerId, adminApiToken }) {
  const sid = authServerId?.trim() || 'default';
  const base = `https://${oktaDomain}`;
  const hdrs = { 'Authorization': `SSWS ${adminApiToken}`, 'Accept': 'application/json' };

  try {
    const [serverRes, policiesRes] = await Promise.all([
      axios.get(`${base}/api/v1/authorizationServers/${sid}`, { headers: hdrs, validateStatus: () => true }),
      axios.get(`${base}/api/v1/authorizationServers/${sid}/policies`, { headers: hdrs, validateStatus: () => true })
    ]);

    if (policiesRes.status !== 200) {
      return { success: false, statusCode: policiesRes.status, error: policiesRes.data?.errorSummary || `HTTP ${policiesRes.status}` };
    }

    // For each policy fetch its rules
    const policies = await Promise.all(policiesRes.data.map(async p => {
      const rulesRes = await axios.get(`${base}/api/v1/authorizationServers/${sid}/policies/${p.id}/rules`,
        { headers: hdrs, validateStatus: () => true });
      return {
        id: p.id, name: p.name, status: p.status, priority: p.priority,
        conditions: p.conditions,
        rules: (rulesRes.data || []).map(r => ({
          name: r.name, status: r.status,
          conditions: r.conditions,
          accessTokenLifetime:  r.actions?.token?.accessTokenLifetimeMinutes,
          refreshTokenLifetime: r.actions?.token?.refreshTokenLifetimeMinutes,
          refreshTokenWindow:   r.actions?.token?.refreshTokenWindowMinutes,
          inlineHook:           r.actions?.token?.inlineHook
        }))
      };
    }));

    return {
      success: true,
      server: serverRes.status === 200 ? { name: serverRes.data.name, status: serverRes.data.status, issuer: serverRes.data.issuer } : null,
      policies
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

module.exports = { revokeAndVerify, getTokenLifetime };
