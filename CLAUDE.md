# CLAUDE.md

## Project Overview

Multi-tenant Node.js/Express app (deployed on Vercel) that bundles a suite of Okta OAuth/OIDC
grant-flow testers — SAML 2.0 Bearer Assertion (`urn:ietf:params:oauth:grant-type:saml2-bearer`),
Authorization Code + PKCE, Client Credentials, ROPC, CIBA, DPoP, Private Key JWT, Token Exchange,
Step-up Auth, Token Inspector, and Admin API testing.

SAML spec: https://developer.okta.com/docs/guides/implement-grant-type/saml2assert/main/

## Multi-tenancy & auth

Authentication is **always required**. Each "tenant" is a demo/customer instance provisioned by
Okta's Demo Platform webhook, with its own Okta/CIC IdP used to log users into *this app*:

- **Tenant provisioning**: `POST /api/tenant?secret=<TENANT_WEBHOOK_SECRET>` receives
  `ComponentInstanceCreateHook` / `UpdateHook` / `DeleteHook` payloads (see
  https://docs.demo.okta.com/spec/openapi-310-spec.yaml). `demonstration.name` becomes the tenant's
  title and id (slugified); `component.oidcConfiguration` becomes the tenant's login IdP config.
  `idp.management_credentials` (either `{clientJWKS}` → private_key_jwt, or `{clientSecret}` →
  basic) is used to fetch a management token and grant the OAuth API scopes needed to drive the
  Okta Management API (policies, users, MFA, apps, API Access Management) on `oidcConfiguration.client_id`
  — see `src/tenant-provision.js`. Lifecycle status is reported back to `event.callback`.
- **Selecting a tenant**: append `?tenant=<id>` once; it's remembered in a `tenant_id` cookie for
  subsequent requests (`src/tenant.js`).
- **Login**: standard Authorization Code + PKCE + `client_secret_basic` against the tenant's own
  `oidcConfiguration` (`src/auth.js`) — not the app's own credentials. Sessions are tenant-bound
  (`req.session.tenantId`) so one browser can hold logins for multiple tenants without bleed.
- **Storage**: Upstash Redis (via `@upstash/redis`, using Vercel's `KV_REST_API_URL`/`KV_REST_API_TOKEN`
  or `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN`) — falls back to a local JSON file
  (`.data/store.json`, gitignored) when unset, so `npm run dev` needs no cloud account. Sessions
  use a small custom `express-session` Store on the same backend (`src/session-store.js`). Secrets
  (OIDC client secrets, management credentials) are encrypted at rest with AES-256-GCM
  (`src/crypto.js`) when `TENANT_ENCRYPTION_KEY` is set.
- **Per-page settings**: every tester page's saved config (previously browser `localStorage` only)
  is now stored server-side per tenant via `GET/POST /api/tenant-settings/:page`
  (`src/tenant-settings.js`); `localStorage` remains only as an instant-paint cache.

Required env vars: `TENANT_WEBHOOK_SECRET`, `SESSION_SECRET`, `APP_BASE_URL`, `TENANT_ENCRYPTION_KEY`
(recommended), plus the Redis vars above.

## Architecture

```
server.js               — Express app (exported; only listens when run directly — see api/index.js)
api/index.js            — Vercel serverless entry point
vercel.json             — Catch-all rewrite to api/index
src/store.js            — KV abstraction (Upstash Redis / local JSON fallback)
src/crypto.js           — AES-256-GCM encrypt/decrypt for secrets at rest
src/tenant-store.js     — Tenant CRUD (encrypts secrets on write)
src/tenant-settings.js  — Per-tenant, per-page settings storage
src/tenant.js           — resolveTenant middleware (?tenant= query / cookie)
src/tenant-webhook.js   — POST /api/tenant webhook handler
src/tenant-provision.js — Okta API scope granting via idp.management_credentials
src/auth.js             — Always-on, per-tenant login (PKCE + client_secret_basic)
src/session-store.js    — KV-backed express-session Store
src/config.js           — App-wide RS256 signing key (for private_key_jwt test pages)
src/saml.js             — SAML assertion XML generation + RSA/XML-DSIG signing
public/index.html       — SAML tester UI (Bootstrap 5, dark theme)
public/*.html, *.js     — One page per OAuth grant/testing tool
public/common.js        — Shared frontend helpers: nav auth, per-tenant settings persistence
```

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/tenant?secret=...` | Demo Platform webhook — create/update/delete a tenant |
| `GET/POST` | `/api/tenant-settings/:page` | Per-tenant, per-page settings (replaces localStorage as source of truth) |
| `GET` | `/auth/login`, `/auth/callback`, `/auth/logout` | Tenant-scoped login flow |
| `GET` | `/auth/jwks` | This app's own JWKS (for private_key_jwt test pages) |
| `GET` | `/api/auth/me` | Current session user + tenant |
| `POST` | `/api/generate-keypair` | Generate RSA-2048 key + self-signed cert via node-forge |
| `POST` | `/api/generate-assertion` | Build + sign SAML 2.0 assertion XML |
| `POST` | `/api/decode-assertion` | Base64(URL) decode an assertion to XML |
| `POST` | `/api/exchange-token` | Proxy token exchange request to Okta |

## Key Dependencies

- `xml-crypto@3.x` — XML digital signatures (enveloped, RSA-SHA256, exc-C14N)
- `node-forge` — RSA key pair + self-signed X.509 certificate generation
- `@xmldom/xmldom` — DOM implementation required by xml-crypto
- `@upstash/redis` — Tenant/session/settings storage on Vercel
- `express` + `express-session` + `cookie-parser` — HTTP server, sessions, cookies
- `axios` — Proxy HTTP calls to Okta token endpoints and the Demo Platform callback

## SAML Assertion Structure

The generated assertion uses:
- **Signature algorithm**: `rsa-sha256`
- **Digest algorithm**: `sha-256`
- **Canonicalization**: `exc-c14n` (exclusive C14N without comments)
- **Signature placement**: after `<saml:Issuer>` (enveloped, standard SAML 2.0 position)
- **Reference**: `URI="#_<assertionId>"` pointing to the Assertion element

## Running Locally

```bash
npm install
npm start          # or: node --watch server.js
# open http://localhost:3001/?tenant=<id>   (create a tenant first via POST /api/tenant)
```

No cloud account is required for local dev — `src/store.js` falls back to a local JSON file
when `KV_REST_API_URL`/`UPSTASH_REDIS_REST_URL` aren't set.

## Okta Setup Checklist

1. Enable **SAML 2.0 Assertion** grant type on the Okta app  
   (Apps → app → General → Grant types → Advanced → SAML 2.0 Assertion)
2. Add an external **SAML 2.0 Identity Provider**  
   (Security → Identity Providers → Add IdP → SAML 2.0)
3. Upload the generated **certificate** to the IdP configuration
4. Note the **SP Entity ID** (Audience) and configure it in Step 3 of the UI  
   (`GET https://{domain}/api/v1/idps/{idpId}/metadata.xml`)
5. The assertion **Issuer** must match the IdP Entity ID configured in Okta
6. The assertion **Recipient** must match the Okta token endpoint URL

## Common Errors

| Error | Likely Cause |
|-------|-------------|
| `invalid_client` | Wrong client ID / secret |
| `invalid_grant` | Certificate mismatch, expired assertion, wrong Audience/Recipient, Issuer mismatch |
| `unsupported_grant_type` | SAML 2.0 Assertion grant not enabled on the app or auth server policy |
| `access_denied` | Auth server policy rule doesn't allow this grant type |
