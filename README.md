# SAML Bearer Token Tester

A local Node.js web app for testing Okta's **SAML 2.0 Bearer Assertion** OAuth grant flow end-to-end — without needing a real Identity Provider.

Self-generates a signed SAML 2.0 assertion using your own RSA key pair, then exchanges it for OAuth tokens via Okta's token endpoint.

**Spec:** [Okta — Implement the SAML 2.0 Assertion grant type](https://developer.okta.com/docs/guides/implement-grant-type/saml2assert/main/)

---

## Features

- **Key pair generator** — creates an RSA-2048 private key + self-signed X.509 certificate in-browser, ready to register in Okta
- **SAML assertion builder** — configurable issuer, subject, audience, recipient, validity window, NameID format, AuthnContext, and custom attributes
- **XML digital signing** — enveloped RSA-SHA256 signature with exclusive C14N, exactly as a real IdP would produce
- **Token exchange** — proxies the `saml2-bearer` grant request to Okta and displays the full token response
- **JWT decoder** — inline decode of `access_token` and `id_token` with expiry status
- **Assertion decoder** — paste any Base64/Base64URL assertion to inspect its XML
- **Config persistence** — all fields saved to `localStorage`; survives page refreshes

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/saml-bearer-tester.git
cd saml-bearer-tester
npm install
npm start
```

Open **http://localhost:3000**

---

## Okta Setup

Before testing, configure Okta once:

### 1. Enable the grant type on your OAuth app

Apps → your app → **General** → Grant types → **Advanced** → check **SAML 2.0 Assertion**  
Also enable **Refresh Token** if you want `offline_access`.

### 2. Add a SAML 2.0 Identity Provider

**Security → Identity Providers → Add Identity Provider → SAML 2.0**

| Field | Value |
|-------|-------|
| Name | Anything (e.g. `SAML Test IdP`) |
| IdP Issuer URI | Must match the **Issuer** you'll set in Step 3 of the UI |
| IdP Single Sign-On URL | Can be a placeholder (not used in bearer flow) |
| IdP Signature Certificate | Paste the **certificate** generated in Step 2 of the UI |

### 3. Get the SP metadata

After saving the IdP, fetch its metadata to get the **Audience URI** (SP Entity ID):

```
GET https://{yourOktaDomain}/api/v1/idps/{idpId}/metadata.xml
```

Paste the `entityID` value into the **Audience** field in Step 3 of the UI.

### 4. Update the auth server policy (custom auth servers)

Security → API → your auth server → Access Policies → policy rule → Edit  
Under **IF Grant type is** → **Advanced** → enable **SAML 2.0 Assertion**

---

## Usage

Follow the 4 steps in the UI:

| Step | What to do |
|------|-----------|
| **1 — Okta Config** | Enter your Okta domain, optional custom auth server ID, client ID, and client secret |
| **2 — Keys** | Click **Generate New Key Pair**, then copy the certificate to your Okta IdP config |
| **3 — Assertion** | Fill in Issuer, Subject, Audience (from Okta metadata), confirm Recipient is the token endpoint, then click **Generate Assertion** |
| **4 — Token Exchange** | Add scopes (`openid`, `profile`, etc.), click **Exchange Token** |

---

## Request Format

The app sends a standard `saml2-bearer` token request:

```
POST https://{domain}/oauth2/{authServerId}/v1/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(clientId:clientSecret)>

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer
&assertion=<base64url-encoded-signed-saml-assertion>
&scope=openid+offline_access
```

---

## Tech Stack

| Package | Purpose |
|---------|---------|
| `express` | HTTP server |
| `xml-crypto` | XML digital signatures (RSA-SHA256 + enveloped) |
| `@xmldom/xmldom` | XML DOM for xml-crypto |
| `node-forge` | RSA key pair + self-signed certificate generation |
| `uuid` | Unique assertion IDs |
| `axios` | Proxy token exchange requests to Okta |

Frontend: Bootstrap 5 + vanilla JS (no build step required)

---

## Troubleshooting

| Okta error | Likely cause |
|------------|-------------|
| `invalid_client` | Wrong client ID or secret |
| `invalid_grant` | Certificate not matching, assertion expired, wrong Audience/Recipient/Issuer |
| `unsupported_grant_type` | Grant type not enabled on app or auth server policy |
| `access_denied` | Auth server policy rule doesn't permit this grant type |

**Tips:**
- The `Issuer` must exactly match the **IdP Issuer URI** configured in Okta
- The `Audience` must be the Okta SP Entity ID (from the metadata XML)
- The `Recipient` must be the Okta token endpoint URL
- Assertion validity window should be reasonable (60 min default); shorter = shorter refresh token lifetime

---

## License

MIT
