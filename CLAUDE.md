# CLAUDE.md

## Project Overview

Local Node.js/Express app for testing Okta's **SAML 2.0 Bearer Assertion** OAuth grant flow (`urn:ietf:params:oauth:grant-type:saml2-bearer`).

Spec: https://developer.okta.com/docs/guides/implement-grant-type/saml2assert/main/

## Architecture

```
server.js          — Express server (port 3000), API routes
src/saml.js        — SAML assertion XML generation + RSA/XML-DSIG signing
public/index.html  — Dark-themed single-page WebUI (Bootstrap 5)
public/app.js      — Frontend logic (vanilla JS, localStorage persistence)
```

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/generate-keypair` | Generate RSA-2048 key + self-signed cert via node-forge |
| `POST` | `/api/generate-assertion` | Build + sign SAML 2.0 assertion XML |
| `POST` | `/api/decode-assertion` | Base64(URL) decode an assertion to XML |
| `POST` | `/api/exchange-token` | Proxy token exchange request to Okta |

## Key Dependencies

- `xml-crypto@3.x` — XML digital signatures (enveloped, RSA-SHA256, exc-C14N)
- `node-forge` — RSA key pair + self-signed X.509 certificate generation
- `@xmldom/xmldom` — DOM implementation required by xml-crypto
- `express` — HTTP server
- `axios` — Proxy HTTP calls to Okta token endpoint

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
# open http://localhost:3000
```

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
