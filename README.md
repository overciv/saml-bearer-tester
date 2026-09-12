# Okta OAuth Super Tester

A multi-tenant Node.js/Express app (deployed on Vercel) bundling a full suite of Okta OAuth/OIDC
grant-flow testers — no real end-user app or IdP setup required beyond an Okta org.

Each "tenant" is a demo/customer instance with its own Okta/CIC identity provider, provisioned via
a webhook. Access is always authenticated: pick a tenant with `?tenant=<id>`, log in against that
tenant's own IdP, and every tester page below is scoped to it.

---

## Testers included

| Category | Page | What it tests |
|----------|------|----------------|
| Grant Flows | Auth Code + PKCE (`/authcode.html`) | Human login via `authorization_code` + PKCE |
| | Client Credentials (`/client-creds.html`) | M2M token — service-to-service, no user |
| | SAML 2.0 Bearer (`/index.html`) | Sign a SAML assertion, exchange it via `urn:ietf:params:oauth:grant-type:saml2-bearer` |
| | DPoP (`/dpop.html`) | Sender-constrained tokens, RFC 9449 proof of possession |
| | Private Key JWT (`/pkjwt.html`) | Client auth via signed JWT instead of a client secret |
| | CIBA (`/ciba.html`) | Backchannel auth — push to the user's device |
| | Token Exchange (`/token-exchange.html`) | RFC 8693 cross-app delegation |
| | ROPC (`/ropc.html`) | Resource Owner Password (legacy) |
| Token Tools | Token Inspector (`/token-inspector.html`) | RFC-annotated claims, revoke + lifetime checks |
| | Step-Up Auth (`/step-up.html`) | `acr_values` MFA escalation, before/after ACR comparison |
| MFA & Admin | MFA Manager (`/mfa.html`) | List factors, trigger live push/OTP/TOTP challenges |
| | Admin API (`/admin.html`) | App lifecycle, audit log, Terraform export |
| Chaining | Test Chain (`/workflow.html`) | Chain testers together with output-to-input binding |

**Spec references:**
[SAML 2.0 Assertion grant](https://developer.okta.com/docs/guides/implement-grant-type/saml2assert/main/) ·
[DPoP (RFC 9449)](https://developer.okta.com/docs/guides/dpop/main/) ·
[Token Exchange (RFC 8693)](https://developer.okta.com/docs/guides/set-up-token-exchange/main/)

---

## Multi-tenancy & auth

- **Tenant provisioning** — `POST /api/tenant?secret=<TENANT_WEBHOOK_SECRET>` accepts Okta Demo
  Platform webhook payloads (`ComponentInstanceCreateHook` / `UpdateHook` / `DeleteHook`).
  `demonstration.name` becomes the tenant's title/id; `component.oidcConfiguration` becomes its
  login IdP config. If `idp.management_credentials` is present, the app also syncs its own
  `redirect_uri` onto the tenant's Okta app automatically. Lifecycle progress is reported back to
  `event.callback`.
- **Selecting a tenant** — append `?tenant=<id>` once; it's remembered in a cookie afterward.
- **Login** — Authorization Code + PKCE + `client_secret_basic` against the *tenant's own* IdP, not
  the app's own credentials. Sessions are tenant-bound so one browser can hold logins for multiple
  tenants at once.
- **Per-page settings** — every tester page's config is saved server-side, scoped to the current
  tenant, so it's consistent across devices/browsers for that tenant (not just `localStorage`).

---

## Quick Start (local dev)

```bash
git clone https://github.com/overciv/saml-bearer-tester.git
cd saml-bearer-tester
npm install
npm start          # or: npm run dev  (auto-restart on change)
```

No cloud account is required locally — storage falls back to a JSON file
(`.data/store.json`, gitignored) when no database/Redis env vars are set.

Create a tenant, then open the app scoped to it:

```bash
curl -X POST "http://localhost:3001/api/tenant?secret=<TENANT_WEBHOOK_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{
    "event": { "type": "create" },
    "demonstration": { "name": "my-demo" },
    "component": { "version": "1.0.0", "oidcConfiguration": {
      "issuer": "https://{yourOktaDomain}/oauth2/default",
      "authorizeUrl": "https://{yourOktaDomain}/oauth2/default/v1/authorize",
      "tokenUrl": "https://{yourOktaDomain}/oauth2/default/v1/token",
      "userInfoUrl": "https://{yourOktaDomain}/oauth2/default/v1/userinfo",
      "client_id": "...", "client_secret": "..."
    }}
  }'
```

```
open http://localhost:3001/?tenant=my-demo
```

---

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `TENANT_WEBHOOK_SECRET` | Yes | Shared secret gating `POST /api/tenant` |
| `SESSION_SECRET` | Yes (prod) | Signs session cookies — must be stable across instances |
| `APP_BASE_URL` | Yes | Used to build `redirect_uri` and the webhook `launchUrl` |
| `TENANT_ENCRYPTION_KEY` | Recommended | AES-256-GCM key encrypting stored client secrets at rest |
| `DATABASE_URL` | Recommended | Postgres (e.g. [Neon](https://neon.tech)) — preferred storage backend |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` | Alternative | Upstash Redis (via Vercel KV integration) |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | Alternative | Upstash Redis (direct) |

Storage picks the first available backend in this order: Postgres → Redis → local JSON file.
With none of the above set, everything still works locally via the JSON file fallback.

---

## Deploying to Vercel

```bash
vercel link
vercel install neon         # or: vercel install upstash/upstash-kv
vercel env add TENANT_WEBHOOK_SECRET production
vercel env add SESSION_SECRET production
vercel env add TENANT_ENCRYPTION_KEY production
vercel env add APP_BASE_URL production   # e.g. https://your-app.vercel.app
vercel deploy --prod
```

`api/index.js` + `vercel.json` route every request through the same Express app used locally —
no separate serverless handlers to maintain.

---

## Architecture

```
server.js               — Express app (exported; only listens when run directly — see api/index.js)
api/index.js            — Vercel serverless entry point
vercel.json             — Catch-all rewrite to api/index
src/store.js            — Storage abstraction: Postgres (Neon) → Redis (Upstash) → local JSON file
src/crypto.js           — AES-256-GCM encrypt/decrypt for secrets at rest
src/tenant-store.js     — Tenant CRUD (encrypts secrets on write)
src/tenant-settings.js  — Per-tenant, per-page settings storage
src/tenant.js           — resolveTenant middleware (?tenant= query / cookie)
src/tenant-webhook.js   — POST /api/tenant webhook handler
src/tenant-provision.js — Syncs this app's redirect_uri onto the tenant's Okta app
src/auth.js             — Always-on, per-tenant login (PKCE + client_secret_basic)
src/session-store.js    — Storage-backed express-session Store
src/config.js           — App-wide RS256 signing key (for private_key_jwt test pages)
src/saml.js             — SAML assertion XML generation + RSA/XML-DSIG signing
public/index.html       — SAML tester UI (Bootstrap 5, dark theme)
public/*.html, *.js     — One page per OAuth grant/testing tool
public/common.js        — Shared frontend helpers: nav auth, per-tenant settings persistence
public/nav.js           — Shared top navigation, injected into every page
```

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/tenant?secret=...` | Demo Platform webhook — create/update/delete a tenant |
| `GET/POST` | `/api/tenant-settings/:page` | Per-tenant, per-page settings |
| `GET` | `/auth/login`, `/auth/callback`, `/auth/logout` | Tenant-scoped login flow |
| `GET` | `/auth/jwks` | This app's own JWKS (for private_key_jwt test pages) |
| `GET` | `/api/auth/me` | Current session user + tenant |
| `POST` | `/api/generate-keypair` | Generate RSA-2048 key + self-signed cert |
| `POST` | `/api/generate-assertion` | Build + sign a SAML 2.0 assertion XML |
| `POST` | `/api/decode-assertion` | Base64(URL) decode an assertion to XML |
| `POST` | `/api/exchange-token` | Proxy a SAML bearer token exchange to Okta |

Every grant-flow tester page has its own set of `/api/<flow>/...` endpoints (DPoP, PKJWT, CIBA,
Token Exchange, Admin API, etc.) — see the page's own JS file in `public/` for the exact calls.

---

## Okta Setup (SAML 2.0 Bearer tester)

1. Enable **SAML 2.0 Assertion** grant type on the Okta app
   (Apps → app → General → Grant types → Advanced → SAML 2.0 Assertion)
2. Add an external **SAML 2.0 Identity Provider**
   (Security → Identity Providers → Add IdP → SAML 2.0)
3. Upload the generated **certificate** to the IdP configuration
4. Note the **SP Entity ID** (Audience) and configure it in the tester UI:
   `GET https://{yourOktaDomain}/api/v1/idps/{idpId}/metadata.xml`
5. The assertion **Issuer** must match the IdP Entity ID configured in Okta
6. The assertion **Recipient** must match the Okta token endpoint URL

Other testers (DPoP, Private Key JWT, CIBA, etc.) each document their own Okta app requirements
inline on their page.

---

## Common Errors

| Error | Likely Cause |
|-------|-------------|
| `invalid_client` | Wrong client ID / secret |
| `invalid_grant` | Certificate mismatch, expired assertion, wrong Audience/Recipient/Issuer |
| `unsupported_grant_type` | Grant type not enabled on the app or auth server policy |
| `access_denied` | Auth server policy rule doesn't allow this grant type |
| `consent_required` | A `client_credentials` request omitted a required `scope` param |

---

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `express` + `express-session` + `cookie-parser` | HTTP server, sessions, cookies |
| `xml-crypto` + `@xmldom/xmldom` | XML digital signatures (RSA-SHA256, enveloped, exc-C14N) |
| `node-forge` | RSA key pair + self-signed X.509 certificate generation |
| `jose` | JWT/JWK signing and verification |
| `@neondatabase/serverless` | Postgres storage backend (Neon) |
| `@upstash/redis` | Redis storage backend (alternative to Postgres) |
| `axios` | HTTP calls to Okta endpoints and the Demo Platform callback |

Frontend: Bootstrap 5 + vanilla JS, no build step required.

---

## License

MIT
