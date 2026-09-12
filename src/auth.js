'use strict';
// Always-on, per-tenant login. Each tenant carries its own OIDC config
// (component.oidcConfiguration from the webhook) — login uses standard
// Authorization Code + PKCE with client_secret_basic against that tenant's
// own Okta/CIC org, not the app's own credentials.

const crypto = require('crypto');
const axios = require('axios');
const { getTenant } = require('./tenant-store');

const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function normalizeUrl(u) {
  if (!u) return u;
  return /^https?:\/\//i.test(u) ? u : `https://${u}`;
}

function redirectUri(req) {
  const base = process.env.APP_BASE_URL || `${req.protocol}://${req.get('host')}`;
  return `${base.replace(/\/+$/, '')}/auth/callback`;
}

function page(title, bodyHtml) {
  return `<!DOCTYPE html><html><head><title>${esc(title)}</title></head>
<body style="font-family:system-ui;padding:2rem;background:#0d1117;color:#c9d1d9">${bodyHtml}</body></html>`;
}

// Paths that bypass auth entirely.
const FREE_PATHS = new Set(['/favicon.ico']);
const FREE_PREFIXES = ['/auth/', '/api/auth/me', '/api/tenant'];

function requireAuth(req, res, next) {
  if (FREE_PATHS.has(req.path) || FREE_PREFIXES.some(p => req.path.startsWith(p))) return next();

  if (!req.tenant) {
    const msg = page('Unknown tenant', `<h2 style="color:#f85149">⚠️ Unknown tenant</h2>
      <p>Access this app with <code>?tenant=&lt;your-tenant-id&gt;</code> in the URL.</p>`);
    return req.path.startsWith('/api/')
      ? res.status(400).json({ error: 'Unknown tenant — pass ?tenant=<id>' })
      : res.status(400).send(msg);
  }

  if (req.session?.user && req.session.tenantId === req.tenant.id) return next();

  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized', tenant: req.tenant.id });
  req.session.returnTo = req.originalUrl;
  res.redirect(`/auth/login?tenant=${encodeURIComponent(req.tenant.id)}`);
}

async function loginHandler(req, res) {
  const tenant = req.tenant;
  if (!tenant) return res.status(400).send(page('Unknown tenant', `<h2 style="color:#f85149">⚠️ Unknown tenant</h2><p>Pass <code>?tenant=&lt;your-tenant-id&gt;</code>.</p>`));

  const cfg = tenant.oidcConfiguration || {};
  if (!cfg.authorizeUrl || !cfg.client_id) {
    return res.status(400).send(page('Auth not configured', `<h2 style="color:#f85149">⚠️ Tenant OIDC config incomplete</h2>
      <p>Tenant "${esc(tenant.title)}" is missing authorizeUrl / client_id.</p>`));
  }

  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest().toString('base64url');
  const state = crypto.randomBytes(16).toString('hex');

  req.session.pkce = { verifier, state, tenantId: tenant.id };
  req.session.returnTo = req.query.returnTo || `/?tenant=${tenant.id}`;

  const params = new URLSearchParams({
    client_id: cfg.client_id,
    redirect_uri: redirectUri(req),
    response_type: 'code',
    scope: 'openid profile email',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`${normalizeUrl(cfg.authorizeUrl)}?${params}`);
}

async function callbackHandler(req, res) {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(page('Auth error', `<h2 style="color:#f85149">Auth Error: ${esc(error)}</h2><p style="color:#8b949e">${esc(error_description || '')}</p>`));
  }
  if (!code) return res.status(400).send('Missing authorization code');

  const pkce = req.session?.pkce;
  if (!pkce || pkce.state !== state) {
    return res.status(403).send('Invalid state — possible CSRF. Try logging in again.');
  }

  const tenant = await getTenant(pkce.tenantId);
  if (!tenant) return res.status(400).send('Tenant no longer exists');

  const cfg = tenant.oidcConfiguration || {};
  const ep = normalizeUrl(cfg.tokenUrl);
  const creds = Buffer.from(`${cfg.client_id}:${cfg.client_secret}`).toString('base64');

  try {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri(req),
      code_verifier: pkce.verifier
    });

    const r = await axios.post(ep, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${creds}` },
      validateStatus: () => true
    });

    if (r.status !== 200) {
      return res.status(400).send(page('Token exchange failed', `<h2 style="color:#f85149">Token Exchange Failed — HTTP ${r.status}</h2>
        <pre style="color:#ffa657;background:#161b22;padding:1rem;border-radius:8px;overflow:auto;font-size:0.82rem">${esc(JSON.stringify(r.data, null, 2))}</pre>`));
    }

    let user = { sub: 'unknown' };
    if (r.data.id_token) {
      try {
        const p = JSON.parse(Buffer.from(r.data.id_token.split('.')[1], 'base64url').toString());
        user = { sub: p.sub, email: p.email || p.preferred_username, name: p.name || p.email || p.preferred_username };
      } catch {}
    }

    delete req.session.pkce;
    req.session.user = user;
    req.session.tenantId = tenant.id;
    req.session.tokens = { access_token: r.data.access_token, id_token: r.data.id_token, refresh_token: r.data.refresh_token };

    res.cookie('tenant_id', tenant.id, { httpOnly: true, sameSite: 'lax', secure: !!process.env.VERCEL, maxAge: 180 * 24 * 60 * 60 * 1000 });

    const returnTo = req.session.returnTo || `/?tenant=${tenant.id}`;
    delete req.session.returnTo;
    res.redirect(returnTo);
  } catch (e) {
    res.status(500).send(`Auth callback error: ${esc(e.message)}`);
  }
}

function logoutHandler(req, res) {
  const tenantId = req.tenant?.id || req.session?.tenantId;
  req.session.destroy(() => {});
  res.redirect(tenantId ? `/?tenant=${encodeURIComponent(tenantId)}` : '/');
}

function meHandler(req, res) {
  if (!req.tenant) return res.status(400).json({ error: 'Unknown tenant' });
  if (!req.session?.user || req.session.tenantId !== req.tenant.id) {
    return res.status(401).json({ user: null, tenant: { id: req.tenant.id, title: req.tenant.title } });
  }
  res.json({ user: req.session.user, tenant: { id: req.tenant.id, title: req.tenant.title } });
}

module.exports = { requireAuth, loginHandler, callbackHandler, logoutHandler, meHandler };
