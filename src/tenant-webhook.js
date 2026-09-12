'use strict';
// POST /api/tenant?secret=... — Demo Platform webhook receiver.
// Handles ComponentInstanceCreateHook / UpdateHook / DeleteHook payloads:
// upserts (or removes) a tenant record, provisions Okta API scopes for the
// tenant's OIDC client, and reports lifecycle status back to event.callback.

const crypto = require('crypto');
const axios = require('axios');
const { slugify, upsertTenant, deleteTenant } = require('./tenant-store');
const { provisionTenantScopes } = require('./tenant-provision');

const SECRET_KEYS = new Set(['client_secret', 'clientSecret', 'clientJWKS', 'clientPEM', 'initialConfigurationToken', 'management_credentials', 'managementCredentials']);

// Allowlist, not a blocklist: Vercel's proxy injects several headers that carry
// live bearer tokens/signatures (x-vercel-oidc-token, x-vercel-proxy-signature,
// forwarded's embedded sig=...) that are impossible to fully enumerate up front.
// Only these are safe to write to persistent logs; everything else is redacted.
const SAFE_HEADERS = new Set([
  'host', 'user-agent', 'content-type', 'content-length', 'accept', 'accept-encoding',
  'x-vercel-id', 'x-vercel-ip-country', 'x-vercel-ip-country-region', 'x-vercel-ip-city',
  'x-forwarded-for', 'x-real-ip', 'x-demoeng-correlation-id'
]);

// Deep-clones the payload, redacting anything secret-shaped so it's safe to
// dump into Vercel logs while still showing the object's shape.
function redact(value, keyHint) {
  if (Array.isArray(value)) return value.map(v => redact(v));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEYS.has(k) ? redactLeaf(v) : redact(v, k);
    }
    return out;
  }
  return value;
}
function redactLeaf(v) {
  if (v === undefined || v === null) return v;
  if (typeof v === 'object') return `[REDACTED ${Array.isArray(v) ? 'array' : 'object'}]`;
  const s = String(v);
  return s.length <= 4 ? '[REDACTED]' : `${s.slice(0, 2)}…${s.slice(-2)} [REDACTED, len=${s.length}]`;
}

function log(reqId, ...args) { console.log(`[tenant-webhook ${reqId}]`, ...args); }
function logErr(reqId, ...args) { console.error(`[tenant-webhook ${reqId}]`, ...args); }

function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k] = SAFE_HEADERS.has(k.toLowerCase()) ? v : '[REDACTED]';
  }
  return out;
}

function secretIsValid(req, reqId) {
  const expected = process.env.TENANT_WEBHOOK_SECRET;
  const provided = req.query.secret;
  if (!expected) { log(reqId, 'REJECT: TENANT_WEBHOOK_SECRET env var is not set on this deployment'); return false; }
  if (typeof provided !== 'string') { log(reqId, 'REJECT: no ?secret= query param provided'); return false; }
  if (provided.length !== expected.length) {
    log(reqId, `REJECT: secret length mismatch (got ${provided.length} chars, expected ${expected.length})`);
    return false;
  }
  const ok = crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
  log(reqId, ok ? 'Secret OK' : 'REJECT: secret value does not match TENANT_WEBHOOK_SECRET');
  return ok;
}

// Per the Demo Platform spec, /demonstration/lifecycle/{callbackId} is a
// PATCH endpoint (operationId: updateComponentLifecycleState) — POSTing to it
// hits no route in their API Gateway and 404s, which is why every callback
// above was silently failing.
async function reportLifecycle(reqId, callbackUrl, { message, state, launchUrl }) {
  log(reqId, `Lifecycle callback -> state=${state} message="${message}"${launchUrl ? ` launchUrl=${launchUrl}` : ''} callback=${callbackUrl || '(none)'}`);
  if (!callbackUrl) { log(reqId, 'Skipping lifecycle callback — no event.callback in payload'); return; }
  try {
    const r = await axios.patch(callbackUrl, { message, state, ...(launchUrl ? { launchUrl } : {}) },
      { headers: { 'Content-Type': 'application/json' }, validateStatus: () => true, timeout: 10000 });
    log(reqId, `Lifecycle callback response: HTTP ${r.status}${r.status >= 300 ? ` body=${JSON.stringify(r.data)}` : ''}`);
  } catch (e) {
    logErr(reqId, 'Lifecycle callback failed:', e.message);
  }
}

function launchUrlFor(id) {
  const base = process.env.APP_BASE_URL;
  return base ? `${base.replace(/\/+$/, '')}/?tenant=${encodeURIComponent(id)}` : undefined;
}

async function handleTenantWebhook(req, res) {
  const reqId = crypto.randomBytes(4).toString('hex');
  // Strip the secret query param from the logged URL too — it's a credential, same as the headers below.
  log(reqId, `Incoming ${req.method} ${req.originalUrl.replace(/([?&]secret=)[^&]*/i, '$1[REDACTED]')}`);
  log(reqId, 'Headers (sensitive values redacted):', JSON.stringify(redactHeaders(req.headers)));
  log(reqId, 'Body (secrets redacted):', JSON.stringify(redact(req.body), null, 2));

  if (!secretIsValid(req, reqId)) return res.status(401).json({ error: 'Invalid or missing secret' });

  const { event, demonstration, idp, component } = req.body || {};
  const callbackUrl = event?.callback;

  log(reqId, `event.type = ${event?.type ?? '(missing)'}`);
  if (!event?.type) {
    log(reqId, 'REJECT 400: event.type is required — check the payload shape above');
    return res.status(400).json({ error: 'event.type is required' });
  }

  if (event.type === 'request') {
    log(reqId, 'event.type=request — pre-attachment check (ComponentInstanceRequestHook), no tenant action needed. Accepting.');
    return res.status(202).json({ ok: true });
  }

  try {
    if (event.type === 'delete') {
      const id = slugify(demonstration?.name);
      log(reqId, `Deleting tenant id=${id}`);
      await deleteTenant(id);
      await reportLifecycle(reqId, callbackUrl, { message: 'Tenant removed', state: 'finish' });
      log(reqId, `DONE: tenant ${id} deleted`);
      return res.json({ ok: true, id, deleted: true });
    }

    // create | update
    if (!demonstration?.name) {
      log(reqId, 'REJECT 400: demonstration.name is required — check the payload shape above');
      return res.status(400).json({ error: 'demonstration.name is required' });
    }
    if (!component?.oidcConfiguration) {
      log(reqId, 'REJECT 400: component.oidcConfiguration is required — check the payload shape above');
      return res.status(400).json({ error: 'component.oidcConfiguration is required' });
    }

    const id = slugify(demonstration.name);
    log(reqId, `event.type=${event.type} demonstration.name="${demonstration.name}" -> tenant id="${id}"`);
    log(reqId, 'oidcConfiguration (redacted):', JSON.stringify(redact(component.oidcConfiguration)));
    log(reqId, 'idp.management_credentials present:', !!idp?.management_credentials, idp?.management_credentials ? `(shape: ${Object.keys(idp.management_credentials).join(', ')})` : '');

    await reportLifecycle(reqId, callbackUrl, { message: `Configuring tenant "${demonstration.name}"`, state: 'update' });

    log(reqId, `Upserting tenant id=${id}...`);
    let tenant = await upsertTenant({
      id,
      title: demonstration.name,
      owner: demonstration.owner,
      idp: idp ? { name: idp.name, type: idp.type, variant: idp.variant, state: idp.state, source: idp.source } : undefined,
      oidcConfiguration: component.oidcConfiguration,
      managementCredentials: idp?.management_credentials
    });
    log(reqId, `Tenant upserted OK: id=${tenant.id} title="${tenant.title}"`);

    if (tenant.managementCredentials) {
      log(reqId, 'Ensuring redirect_uri is registered on the tenant Okta app...');
      await reportLifecycle(reqId, callbackUrl, { message: 'Updating Okta app redirect URI', state: 'update' });
      const provisioning = await provisionTenantScopes(tenant);
      log(reqId, 'Provisioning result:', JSON.stringify(provisioning, null, 2));
      tenant = await upsertTenant({ id, provisioning });
      if (!provisioning.ok) {
        const detail = provisioning.error || provisioning.redirectUri?.error || provisioning.redirectUri?.reason || 'unknown error';
        log(reqId, `Provisioning had issues: ${detail}`);
        await reportLifecycle(reqId, callbackUrl, { message: `Tenant created, but redirect_uri update failed: ${detail}`, state: 'update' });
      } else if (provisioning.redirectUri?.changed) {
        log(reqId, `redirect_uri registered on Okta app ${provisioning.redirectUri.appId}: ${provisioning.redirectUri.redirectUri}`);
      } else {
        log(reqId, 'redirect_uri already present on the Okta app — no update needed');
      }
    } else {
      log(reqId, 'No management_credentials in payload — skipping redirect_uri provisioning');
    }

    await reportLifecycle(reqId, callbackUrl, { message: 'Tenant ready', state: 'finish', launchUrl: launchUrlFor(id) });
    log(reqId, `DONE 200: tenant id=${id} ready`);
    res.json({ ok: true, id, title: tenant.title });
  } catch (e) {
    logErr(reqId, 'FAILED:', e.message);
    logErr(reqId, e.stack);
    await reportLifecycle(reqId, callbackUrl, { message: `Tenant provisioning failed: ${e.message}`, state: 'fail' });
    res.status(500).json({ error: e.message });
  }
}

module.exports = { handleTenantWebhook };
