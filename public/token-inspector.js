'use strict';

// ─── RFC claim metadata ────────────────────────────────────────────────────────
const CLAIM_META = {
  // RFC 7519 — JWT
  sub:  { std:'RFC 7519', type:'native',       desc:'Subject — principal identified by this token. User email/login for user tokens, client_id for machine (M2M) tokens.' },
  iss:  { std:'RFC 7519', type:'native',       desc:'Issuer — the authorization server that issued the token.' },
  aud:  { std:'RFC 7519', type:'native',       desc:'Audience — intended recipient(s). Must be validated by the resource server.' },
  exp:  { std:'RFC 7519', type:'configurable', desc:'Expiration time (Unix timestamp). Configurable via auth server access policy (default 1 hour).' },
  iat:  { std:'RFC 7519', type:'native',       desc:'Issued at (Unix timestamp). Set at generation time.' },
  nbf:  { std:'RFC 7519', type:'native',       desc:'Not before — token must not be accepted before this time.' },
  jti:  { std:'RFC 7519', type:'native',       desc:'JWT ID — unique identifier. Enables replay protection; each token has a globally unique JTI.' },

  // OIDC Core 1.0
  azp:  { std:'OIDC Core', type:'native',      desc:'Authorized party — client_id of the party to which the token was issued. Present when the audience includes other parties.' },
  nonce:{ std:'OIDC Core', type:'native',      desc:'Nonce — value passed in the /authorize request. Binds id_token to the session; prevents replay attacks.' },
  auth_time: { std:'OIDC Core', type:'native', desc:'Authentication time — when the user last authenticated. Critical for max_age enforcement.' },
  acr:  { std:'OIDC Core', type:'native',      desc:'Authentication Context Class Reference — Level of Assurance (LoA) of the authentication performed.' },
  at_hash: { std:'OIDC Core', type:'native',   desc:'Access token hash — left-most half of SHA-256 of the access_token, base64url encoded. Binds id_token to access_token.' },
  c_hash:  { std:'OIDC Core', type:'native',   desc:'Code hash — left-most half of SHA-256 of the authorization code. Prevents code substitution attacks.' },

  // RFC 8176 — AMR
  amr:  { std:'RFC 8176', type:'native',       desc:'Authentication Methods References — ordered list of how the user authenticated (pwd=password, mfa=multi-factor, otp=one-time-password, hwk=hardware key, swk=software key, user=user presence test).' },

  // OIDC profile/email scope claims (mappable via claim mapping)
  name: { std:'OIDC Core', type:'mappable',    desc:'Full name. Populated via profile scope + attribute mapping. Configurable in Okta via custom claims or profile mappings.' },
  given_name:  { std:'OIDC Core', type:'mappable', desc:'Given (first) name. Profile scope required. Mapped from Okta user profile.' },
  family_name: { std:'OIDC Core', type:'mappable', desc:'Family (last) name. Profile scope required. Mapped from Okta user profile.' },
  email: { std:'OIDC Core', type:'mappable',   desc:'Email address. Email scope required. Can be customized to map to any user attribute.' },
  email_verified: { std:'OIDC Core', type:'mappable', desc:'Whether email address is verified. Email scope required.' },
  preferred_username: { std:'OIDC Core', type:'native', desc:'Login / preferred username. Populated from the Okta user\'s login attribute.' },
  phone_number: { std:'OIDC Core', type:'mappable', desc:'Phone number. Requires phone scope. Mapped from Okta user profile.' },
  locale: { std:'OIDC Core', type:'mappable',  desc:'User locale (BCP 47 format). Mapped from Okta user profile.' },
  zoneinfo: { std:'OIDC Core', type:'mappable',desc:'Time zone. Mapped from Okta user profile.' },

  // Okta-specific native
  ver:  { std:'Okta',     type:'native',       desc:'Token schema version. Indicates the Okta token format version.' },
  cid:  { std:'Okta',     type:'native',       desc:'Client ID — the application (client_id) that requested this token. Useful to identify the origin app in token exchange flows.' },
  uid:  { std:'Okta',     type:'native',       desc:'User ID — Okta internal user identifier. ONLY present in user tokens; ABSENT in machine (client_credentials / M2M) tokens.' },
  scp:  { std:'OAuth 2.0', type:'configurable', desc:'Scopes granted. Standard scopes (openid, profile…) are native; custom scopes are defined on the authorization server and assigned via policies.' },
  groups: { std:'Okta (custom)', type:'mappable', desc:'Group memberships. Populated via a custom claim mapping groups to Okta groups or roles. Not present by default — must be explicitly configured.' },

  // DPoP — RFC 9449
  cnf:  { std:'RFC 9449', type:'native',       desc:'Confirmation claim — contains the DPoP key binding. Its jkt sub-claim is the SHA-256 thumbprint of the DPoP public key used when the token was issued.' },

  // RFC 8693 — Token Exchange
  act:  { std:'RFC 8693', type:'native',       desc:'Actor — identifies the party acting on behalf of the subject. Populated in delegation token exchange flows; creates an auditable chain of trust.' },
};

const TYPE_HTML = {
  native:       '<span class="type-native">● native</span>',
  configurable: '<span class="type-configurable">◐ configurable</span>',
  mappable:     '<span class="type-mappable">○ mappable</span>',
  custom:       '<span class="type-custom">✦ custom</span>',
};

// ─── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  // Pre-fill from server settings
  fetch('/api/settings').then(r => r.json()).then(s => {
    if (s.oktaDomain)    { document.getElementById('revOktaDomain').value = s.oktaDomain; document.getElementById('ltOktaDomain').value = s.oktaDomain; }
    if (s.authServerId)  { document.getElementById('revAuthServerId').value = s.authServerId; document.getElementById('ltAuthServerId').value = s.authServerId; }
    if (s.clientId)      document.getElementById('revClientId').value = s.clientId;
    if (s.clientSecret)  document.getElementById('revClientSecret').value = s.clientSecret;
    if (s.adminApiToken) document.getElementById('ltAdminToken').value = s.adminApiToken;
  }).catch(() => {});
});

// ─── Token Inspect ─────────────────────────────────────────────────────────────
function inspectToken() {
  const raw = val('inspectTokenInput').trim();
  if (!raw) { toast('Paste a token first', 'warning'); return; }
  const decoded = decodeJwt(raw);
  if (!decoded) { toast('Not a valid JWT — cannot decode', 'error'); return; }

  const p = decoded.payload;
  const h = decoded.header;

  // Determine token type
  const isIdToken     = h.typ === 'JWT' && (p.nonce !== undefined || p.at_hash !== undefined || p.c_hash !== undefined);
  const isMachine     = !p.uid;
  const hasDpop       = !!p.cnf?.jkt;
  const hasAct        = !!p.act;

  // Summary badges
  const typeBadge = isIdToken
    ? '<span class="token-type-badge badge-id"><i class="bi bi-person-badge me-1"></i>ID Token</span>'
    : isMachine
      ? '<span class="token-type-badge badge-machine"><i class="bi bi-robot me-1"></i>Machine Token (M2M)</span>'
      : '<span class="token-type-badge badge-user"><i class="bi bi-person me-1"></i>User Token</span>';
  const dpopBadge = hasDpop ? '<span class="token-type-badge" style="background:rgba(45,217,198,0.1);color:var(--teal);border:1px solid rgba(45,217,198,0.25)"><i class="bi bi-fingerprint me-1"></i>DPoP-bound</span>' : '';
  const actBadge  = hasAct  ? '<span class="token-type-badge" style="background:rgba(247,129,102,0.1);color:var(--coral,#f78166);border:1px solid rgba(247,129,102,0.25)"><i class="bi bi-people me-1"></i>Delegation (act)</span>' : '';

  const exp = p.exp ? new Date(p.exp * 1000) : null;
  const expired = exp && exp < new Date();
  const expBadge = exp
    ? `<span class="status-badge ${expired ? 'status-err' : 'status-ok'}">${expired ? '⚠ Expired' : '✓ Valid'} · ${exp.toLocaleString()}</span>`
    : '';

  document.getElementById('tokenSummary').innerHTML = `${typeBadge}${dpopBadge}${actBadge}${expBadge}
    <span style="font-size:0.78rem;color:var(--text-muted);margin-left:auto">alg: <code>${escHtml(h.alg||'—')}</code></span>`;

  // Build claims table
  const allClaims = { ...p };
  const tbody = document.getElementById('claimsTableBody');
  tbody.innerHTML = '';

  // Known claims first (in CLAIM_META order), then unknowns
  const known = Object.keys(CLAIM_META).filter(k => allClaims[k] !== undefined);
  const unknown = Object.keys(allClaims).filter(k => !CLAIM_META[k]);

  [...known, ...unknown].forEach(k => {
    const meta = CLAIM_META[k];
    const rawVal = allClaims[k];
    const displayVal = formatClaimValue(k, rawVal);
    const typeHtml = meta ? TYPE_HTML[meta.type] : TYPE_HTML.custom;
    const std = meta ? `<span class="claim-std">${escHtml(meta.std)}</span>` : '<span class="claim-std" style="opacity:0.5">Custom</span>';
    const desc = meta ? escHtml(meta.desc) : '<span style="color:var(--text-muted)">User-defined custom claim</span>';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="claim-name">${escHtml(k)}</span></td>
      <td><span class="claim-val">${displayVal}</span></td>
      <td>${std}</td>
      <td>${typeHtml}</td>
      <td class="claim-desc">${desc}</td>`;
    tbody.appendChild(tr);
  });

  document.getElementById('inspectOutput').style.display = '';
  toast('Token decoded — ' + (known.length + unknown.length) + ' claims', 'success');
}

function formatClaimValue(key, val) {
  if (val === undefined || val === null) return '<span style="opacity:0.4">—</span>';
  if (key === 'exp' || key === 'iat' || key === 'nbf' || key === 'auth_time') {
    const d = new Date(val * 1000);
    return `<span style="color:var(--orange)">${val}</span> <span style="color:var(--text-muted);font-size:0.7rem">(${d.toISOString().replace('T',' ').slice(0,19)})</span>`;
  }
  if (key === 'amr' && Array.isArray(val)) {
    const amrLabels = { pwd:'password', mfa:'multi-factor', otp:'one-time-password', hwk:'hardware key', swk:'software key', pop:'proof-of-possession', sms:'SMS' };
    return val.map(v => `<span style="background:rgba(227,179,65,0.1);color:var(--amber);border-radius:3px;padding:1px 5px;font-size:0.72rem;margin-right:2px">${escHtml(v)}${amrLabels[v] ? ` <span style="opacity:0.6;font-size:0.65rem">${escHtml(amrLabels[v])}</span>` : ''}</span>`).join('');
  }
  if (key === 'cnf' && typeof val === 'object') {
    return `<span style="color:var(--teal)">jkt: ${escHtml(val.jkt || JSON.stringify(val))}</span>`;
  }
  if (key === 'act' && typeof val === 'object') {
    return `<span style="color:var(--orange)">sub: ${escHtml(val.sub || JSON.stringify(val))}</span>`;
  }
  if (Array.isArray(val)) return val.map(v => `<span style="background:var(--surface2);border-radius:3px;padding:1px 5px;margin-right:2px">${escHtml(String(v))}</span>`).join('');
  if (typeof val === 'object') return `<span style="color:var(--text-muted);font-size:0.75rem">${escHtml(JSON.stringify(val))}</span>`;
  const s = String(val);
  return escHtml(s.length > 80 ? s.slice(0, 80) + '…' : s);
}

function useInInspectRevoke() {
  const token = val('inspectTokenInput');
  if (token) document.getElementById('revToken').value = token;
  document.getElementById('sec-revoke').scrollIntoView({ behavior: 'smooth' });
}

// ─── Revocation ────────────────────────────────────────────────────────────────
async function revokeToken() {
  const btn = document.getElementById('revokeBtn');
  setLoading(btn, true, '<i class="bi bi-x-circle me-1"></i>Revoking…');
  try {
    const res = await post('/api/token/revoke-and-verify', {
      oktaDomain: val('revOktaDomain'), authServerId: val('revAuthServerId'),
      clientId: val('revClientId'), clientSecret: document.getElementById('revClientSecret')?.value || '',
      token: val('revToken'), tokenTypeHint: val('revTokenTypeHint')
    });

    document.getElementById('revokeOutput').style.display = '';
    const stepsEl = document.getElementById('revokeSteps');
    stepsEl.innerHTML = '';

    res.steps?.forEach((step, i) => {
      const ok = step.success !== false && !step.error;
      const div = document.createElement('div');
      div.className = 'flow-step';
      div.innerHTML = `
        <div class="flow-step-hdr" onclick="this.nextElementSibling.classList.toggle('open')">
          <span class="step-dot ${ok ? 'dot-ok' : 'dot-err'}"></span>
          <span style="font-weight:600">${escHtml(step.label)}</span>
          ${step.statusCode ? `<span style="font-size:0.72rem;color:var(--text-muted);margin-left:auto">HTTP ${step.statusCode} · ${step.durationMs}ms</span>` : ''}
          ${step.note ? `<span style="font-size:0.72rem;color:var(--text-muted);margin-left:8px">— ${escHtml(step.note)}</span>` : ''}
          <i class="bi bi-chevron-down ms-2" style="font-size:0.7rem;color:var(--text-muted)"></i>
        </div>
        <div class="flow-step-body${i === res.steps.length - 1 ? ' open' : ''}">
          <div class="code-block json" style="max-height:160px">${escHtml(JSON.stringify(step.response || step.body || step.error || {}, null, 2))}</div>
        </div>`;
      stepsEl.appendChild(div);
    });

    const finalEl = document.getElementById('revokeFinalStatus');
    if (res.revoked) {
      finalEl.innerHTML = '<i class="bi bi-check-circle-fill me-2" style="color:var(--green)"></i><strong style="color:var(--green)">Token successfully revoked</strong> — introspect confirmed <code>active: false</code>. Any in-flight request using this token will now be rejected.';
    } else {
      finalEl.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-2" style="color:var(--yellow)"></i><strong style="color:var(--yellow)">Revocation sent</strong> — but introspect may still show active (propagation delay, or refresh token revoked access token separately).';
    }
    toast(res.revoked ? 'Token revoked and verified!' : 'Revoked (verify may still be pending)', res.revoked ? 'success' : 'warning');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-x-circle me-1"></i>Revoke Token');
  }
}

// ─── Token Lifetime ────────────────────────────────────────────────────────────
async function fetchLifetime() {
  const btn = document.getElementById('lifetimeBtn');
  setLoading(btn, true, '<i class="bi bi-arrow-clockwise me-1"></i>Fetching…');
  try {
    const res = await post('/api/token/lifetime', {
      oktaDomain: val('ltOktaDomain'), authServerId: val('ltAuthServerId'),
      adminApiToken: document.getElementById('ltAdminToken')?.value || ''
    });

    document.getElementById('lifetimeOutput').style.display = '';

    if (res.server) {
      document.getElementById('lifetimeServerInfo').innerHTML =
        `<strong>${escHtml(res.server.name)}</strong> · ${escHtml(res.server.status)} · <code style="font-size:0.75rem;color:var(--orange)">${escHtml(res.server.issuer || '')}</code>`;
    }

    const policiesEl = document.getElementById('lifetimePolicies');
    policiesEl.innerHTML = '';
    (res.policies || []).forEach(policy => {
      const div = document.createElement('div');
      div.className = 'mb-4';
      div.innerHTML = `<div style="font-size:0.82rem;font-weight:600;margin-bottom:8px">
        <span class="status-badge ${policy.status === 'ACTIVE' ? 'status-ok' : 'status-err'}">${escHtml(policy.status)}</span>
        <span class="ms-2">${escHtml(policy.name)}</span>
        <span style="color:var(--text-muted);font-size:0.72rem;margin-left:6px">priority ${policy.priority}</span>
      </div>
      <div class="table-responsive">
        <table class="lifetime-table">
          <thead><tr><th>Rule</th><th>Status</th><th>Access Token TTL</th><th>Refresh Token TTL</th><th>Refresh Window</th><th>Conditions</th></tr></thead>
          <tbody>${(policy.rules || []).map(r => `<tr>
            <td>${escHtml(r.name)}</td>
            <td><span class="status-badge ${r.status === 'ACTIVE' ? 'status-ok' : 'status-err'}">${escHtml(r.status)}</span></td>
            <td><span class="ttl-val">${r.accessTokenLifetime != null ? fmtMinutes(r.accessTokenLifetime) : '—'}</span></td>
            <td><span class="ttl-val">${r.refreshTokenLifetime != null ? fmtMinutes(r.refreshTokenLifetime) : '—'}</span></td>
            <td><span class="ttl-val">${r.refreshTokenWindow != null ? fmtMinutes(r.refreshTokenWindow) : '—'}</span></td>
            <td style="font-size:0.72rem;color:var(--text-muted)">${escHtml(JSON.stringify(r.conditions?.grantTypes?.include || 'All'))}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>`;
      policiesEl.appendChild(div);
    });

    if (!res.policies?.length) policiesEl.innerHTML = '<div style="color:var(--text-muted);font-size:0.82rem">No policies found</div>';
    toast('Policies loaded', 'success');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-arrow-clockwise me-1"></i>Fetch Policies');
  }
}

function fmtMinutes(min) {
  if (min == null) return '—';
  if (min < 60) return `${min}m`;
  if (min < 1440) return `${min/60}h (${min}m)`;
  return `${Math.round(min/1440)}d (${min}m)`;
}
