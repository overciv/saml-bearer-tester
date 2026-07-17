'use strict';
const crypto = require('crypto');
const axios = require('axios');
const { getConfig, getSigningKey } = require('./config');
const { generateClientAssertion } = require('./pkjwt');

const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function authorizeEndpoint(cfg) {
  return cfg.authServerId?.trim()
    ? `https://${cfg.oktaDomain}/oauth2/${cfg.authServerId}/v1/authorize`
    : `https://${cfg.oktaDomain}/oauth2/v1/authorize`;
}

function tokenEndpoint(cfg) {
  return cfg.authServerId?.trim()
    ? `https://${cfg.oktaDomain}/oauth2/${cfg.authServerId}/v1/token`
    : `https://${cfg.oktaDomain}/oauth2/v1/token`;
}

function logoutEndpoint(cfg) {
  return cfg.authServerId?.trim()
    ? `https://${cfg.oktaDomain}/oauth2/${cfg.authServerId}/v1/logout`
    : `https://${cfg.oktaDomain}/oauth2/v1/logout`;
}

// Paths that bypass auth even when authEnabled = true
const FREE_PATHS = new Set(['/settings.html', '/settings.js', '/common.js', '/favicon.ico', '/auth/jwks', '/oauth/callback', '/home.html']);
const FREE_PREFIXES = ['/auth/', '/api/auth/', '/api/settings', '/api/oauth/'];

function requireAuth(req, res, next) {
  const cfg = getConfig();
  if (!cfg.authEnabled) return next();
  if (FREE_PATHS.has(req.path)) return next();
  if (FREE_PREFIXES.some(p => req.path.startsWith(p))) return next();
  if (req.session?.user) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized', authEnabled: true });
  req.session.returnTo = req.originalUrl;
  res.redirect('/auth/login');
}

async function loginHandler(req, res) {
  const cfg = getConfig();
  const clientId = cfg.authClientId?.trim() || cfg.clientId;

  if (!cfg.oktaDomain || !clientId) {
    return res.status(400).send(`<!DOCTYPE html>
<html><body style="font-family:system-ui;padding:2rem;background:#0d1117;color:#c9d1d9">
  <h2 style="color:#f85149">⚠️ Auth not configured</h2>
  <p>Configure Okta Domain and Client ID in <a href="/settings.html" style="color:#58a6ff">Settings</a>, then enable authentication.</p>
  <p style="color:#8b949e;font-size:0.85rem">Make sure the app signing key JWKS is registered in the Okta app.</p>
</body></html>`);
  }

  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest().toString('base64url');
  const state = crypto.randomBytes(16).toString('hex');

  req.session.pkce = { verifier, state };
  req.session.returnTo = req.query.returnTo || '/';

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: cfg.redirectUri || 'http://localhost:3000/auth/callback',
    response_type: 'code',
    scope: (cfg.authScopes || ['openid', 'profile', 'email']).join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`${authorizeEndpoint(cfg)}?${params}`);
}

async function callbackHandler(req, res) {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`<!DOCTYPE html>
<html><body style="font-family:system-ui;padding:2rem;background:#0d1117;color:#c9d1d9">
  <h2 style="color:#f85149">Auth Error: ${esc(error)}</h2>
  <p style="color:#8b949e">${esc(error_description || '')}</p>
  <a href="/settings.html" style="color:#58a6ff">← Settings</a>
</body></html>`);
  }

  if (!code) return res.status(400).send('Missing authorization code');

  const pkce = req.session?.pkce;
  if (!pkce || pkce.state !== state) {
    return res.status(403).send('Invalid state — possible CSRF. Try logging in again.');
  }

  const cfg = getConfig();
  const clientId = cfg.authClientId?.trim() || cfg.clientId;
  const ep = tokenEndpoint(cfg);
  const redirectUri = cfg.redirectUri || 'http://localhost:3000/auth/callback';

  try {
    const signingKey = await getSigningKey();
    const { assertion } = await generateClientAssertion({
      privateJwk: signingKey.privateJwk,
      clientId,
      audience: ep,
      validitySeconds: 300
    });

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      code_verifier: pkce.verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion
    });

    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      validateStatus: () => true
    });

    if (r.status !== 200) {
      return res.status(400).send(`<!DOCTYPE html>
<html><body style="font-family:system-ui;padding:2rem;background:#0d1117;color:#c9d1d9">
  <h2 style="color:#f85149">Token Exchange Failed  HTTP ${r.status}</h2>
  <pre style="color:#ffa657;background:#161b22;padding:1rem;border-radius:8px;overflow:auto;font-size:0.82rem">${esc(JSON.stringify(r.data, null, 2))}</pre>
  <p style="color:#8b949e;font-size:0.82rem">Common fixes:
    <ul style="color:#8b949e">
      <li>JWKS not registered in Okta app — paste from <a href="/settings.html" style="color:#58a6ff">Settings → App Signing Key</a></li>
      <li>Okta app client authentication must be set to <strong>Public key / Private key</strong></li>
      <li>Grant type <strong>Authorization Code</strong> must be enabled on the app</li>
    </ul>
  </p>
  <a href="/settings.html" style="color:#58a6ff">← Settings</a>
</body></html>`);
    }

    // Decode id_token for user info
    let user = { sub: 'unknown' };
    if (r.data.id_token) {
      try {
        const p = JSON.parse(Buffer.from(r.data.id_token.split('.')[1], 'base64url').toString());
        user = { sub: p.sub, email: p.email || p.preferred_username, name: p.name || p.email || p.preferred_username };
      } catch {}
    }

    delete req.session.pkce;
    req.session.user = user;
    req.session.tokens = {
      access_token: r.data.access_token,
      id_token: r.data.id_token,
      refresh_token: r.data.refresh_token
    };

    const returnTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(returnTo);

  } catch (e) {
    res.status(500).send(`Auth callback error: ${esc(e.message)}`);
  }
}

function logoutHandler(req, res) {
  const cfg = getConfig();
  const idToken = req.session?.tokens?.id_token;
  req.session.destroy(() => {});

  if (cfg.oktaDomain && idToken) {
    const params = new URLSearchParams({
      id_token_hint: idToken,
      post_logout_redirect_uri: 'http://localhost:3000/'
    });
    return res.redirect(`${logoutEndpoint(cfg)}?${params}`);
  }
  res.redirect('/');
}

function meHandler(req, res) {
  const cfg = getConfig();
  if (!cfg.authEnabled) return res.json({ authEnabled: false, user: null });
  if (!req.session?.user) return res.status(401).json({ authEnabled: true, user: null });
  res.json({ authEnabled: true, user: req.session.user });
}

module.exports = { requireAuth, loginHandler, callbackHandler, logoutHandler, meHandler };
