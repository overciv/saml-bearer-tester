'use strict';
// CLAIM_META, TYPE_HTML, formatClaimValue, renderClaimsTable, renderTokenBadges
// are defined in common.js so the workflow chain modal can reuse the EXACT same rendering.

// ─── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
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

  // Summary badges — uses renderTokenBadges from common.js
  document.getElementById('tokenSummary').innerHTML = renderTokenBadges(decoded);

  // Claims table — uses renderClaimsTable from common.js (SAME as workflow modal)
  document.getElementById('claimsTableBody').innerHTML = '';
  // Re-use the shared function but inject rows into the existing <table> DOM
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = renderClaimsTable(decoded.payload);
  const sharedRows = tempDiv.querySelector('tbody')?.innerHTML || '';
  document.getElementById('claimsTableBody').innerHTML = sharedRows;

  document.getElementById('inspectOutput').style.display = '';
  const count = Object.keys(decoded.payload).length;
  toast(`Token decoded — ${count} claim${count!==1?'s':''}`, 'success');
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
      finalEl.innerHTML = '<i class="bi bi-check-circle-fill me-2" style="color:var(--green)"></i><strong style="color:var(--green)">Token successfully revoked</strong> — introspect confirmed <code>active: false</code>.';
    } else {
      finalEl.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-2" style="color:var(--yellow)"></i><strong style="color:var(--yellow)">Revocation sent</strong> — introspect may still show active (propagation delay).';
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
