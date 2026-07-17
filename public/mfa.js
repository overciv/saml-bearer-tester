'use strict';

let _currentUserId = null;
let _factorCache   = [];
let _challengeState = { factorId: null, pollHref: null, pollTimer: null, attempts: 0 };

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  fetch('/api/settings').then(r => r.json()).then(s => {
    if (s.oktaDomain)    document.getElementById('oktaDomain').value = s.oktaDomain;
    if (s.adminApiToken) document.getElementById('adminToken').value  = s.adminApiToken;
  }).catch(() => {});
});

function adminP(extra = {}) {
  return { oktaDomain: val('oktaDomain'), adminApiToken: document.getElementById('adminToken')?.value || '', ...extra };
}

// ─── Find user + list factors ─────────────────────────────────────────────────

async function findUser() {
  const btn = document.getElementById('findBtn');
  const login = val('userLogin');
  if (!login) { toast('Enter a user login or email', 'warning'); return; }
  setLoading(btn, true, '<i class="bi bi-search me-1"></i>Finding…');
  try {
    const res = await fetch('/api/admin/find-user', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(adminP({ login }))
    }).then(r => r.json());

    if (!res.success) { toast('User not found: ' + (res.response?.errorSummary || `HTTP ${res.statusCode}`), 'error'); return; }

    const u = res.response;
    _currentUserId = u.id;
    document.getElementById('userCard').style.display = '';
    document.getElementById('userCard').innerHTML =
      `<div class="d-flex align-items-center gap-3 p-3" style="background:var(--surface2);border-radius:8px;font-size:0.82rem">
        <i class="bi bi-person-circle" style="font-size:1.5rem;color:var(--emerald)"></i>
        <div>
          <div style="font-weight:600">${escHtml(u.profile?.displayName || u.profile?.login)}</div>
          <div style="color:var(--text-muted)">${escHtml(u.profile?.login)}</div>
        </div>
        <span class="ms-auto status-badge ${u.status==='ACTIVE'?'status-ok':'status-err'}">${escHtml(u.status)}</span>
        <code style="font-size:0.7rem;color:var(--text-muted)">${escHtml(u.id)}</code>
      </div>`;
    document.getElementById('factorSection').style.display = '';
    await refreshFactors();
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-search me-1"></i>Find User');
  }
}

async function refreshFactors() {
  if (!_currentUserId) return;
  const res = await fetch('/api/admin/list-factors', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(adminP({ userId: _currentUserId }))
  }).then(r => r.json()).catch(() => null);
  if (res?.success) renderFactors(res.response || []);
}

// ─── Factor rendering (shared with admin.js pattern) ─────────────────────────

const FACTOR_META = {
  'push':                { label:'Okta Verify Push',    icon:'bi-phone-vibrate', challengeMode:'push' },
  'token:software:totp': { label:'TOTP Authenticator',  icon:'bi-phone',         challengeMode:'totp' },
  'token:hardware':      { label:'Hardware Token',      icon:'bi-usb-symbol',    challengeMode:'totp' },
  'email':               { label:'Email OTP',           icon:'bi-envelope',      challengeMode:'otp'  },
  'token:software:sms':  { label:'SMS OTP',             icon:'bi-chat-text',     challengeMode:'otp'  },
  'call':                { label:'Voice Call OTP',      icon:'bi-telephone',     challengeMode:'otp'  },
  'webauthn':            { label:'WebAuthn / FIDO2',    icon:'bi-fingerprint',   challengeMode:null   },
  'question':            { label:'Security Question',   icon:'bi-question-circle',challengeMode:null  },
  'signed_nonce':        { label:'Okta FastPass',       icon:'bi-lightning',     challengeMode:null   },
  'password':            { label:'Password',            icon:'bi-key',           challengeMode:null   },
};

function _fid(f) {
  const p = f.profile||{};
  switch(f.factorType){
    case 'push': return p.name||p.credentialId||'—';
    case 'email': return p.email||'—';
    case 'token:software:sms': return p.phoneNumber||'—';
    case 'call': return p.phoneNumber||'—';
    case 'token:software:totp': return p.credentialId||'—';
    case 'token:hardware': return p.credentialId||'—';
    case 'webauthn': return p.authenticatorName||(p.credentialId?p.credentialId.slice(0,20)+'…':'—');
    default: return p.credentialId||p.email||p.phoneNumber||'—';
  }
}

function _fdesc(f) {
  const p = f.profile||{};
  switch(f.factorType){
    case 'push': return [p.platform,p.deviceType,p.version].filter(Boolean).join(' · ')||'Mobile push';
    case 'email': return 'OTP via email';
    case 'token:software:sms': return 'OTP via SMS';
    case 'token:software:totp': return `${f.provider} authenticator (RFC 6238 TOTP)`;
    case 'token:hardware': return `${f.vendorName||f.provider} hardware token`;
    case 'webauthn': return `${f.provider} — WebAuthn / FIDO2`;
    default: return f.factorType?.replace(/[:_]/g,' ')||'—';
  }
}

function renderFactors(factors) {
  _factorCache = factors;
  document.getElementById('challengePanel').style.display = 'none';
  const tbody = document.getElementById('factorTableBody');
  if (!factors.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:20px">No factors enrolled</td></tr>';
    return;
  }
  tbody.innerHTML = factors.map(f => {
    const meta = FACTOR_META[f.factorType] || { label:f.factorType, icon:'bi-shield', challengeMode:null };
    const canChallenge = meta.challengeMode !== null && f.status === 'ACTIVE';
    const challengeLabel = { push:'Send Push', otp:'Send OTP', totp:'Verify OTP' }[meta.challengeMode] || 'Challenge';
    const challengeIcon  = { push:'bi-phone-vibrate', otp:'bi-send', totp:'bi-key' }[meta.challengeMode] || 'bi-play';
    return `<tr>
      <td><div class="d-flex align-items-center gap-2">
        <i class="bi ${meta.icon}" style="color:var(--emerald)"></i>
        <div><div style="font-weight:600;font-size:0.82rem">${escHtml(meta.label)}</div><div style="font-size:0.7rem;color:var(--text-muted)">${escHtml(f.provider)}</div></div>
      </div></td>
      <td style="font-family:monospace;font-size:0.78rem;color:var(--orange)">${escHtml(_fid(f))}</td>
      <td style="font-size:0.75rem;color:var(--text-muted);max-width:180px">${escHtml(_fdesc(f))}</td>
      <td><span class="${f.status==='ACTIVE'?'factor-status-active':'factor-status-inactive'}">${escHtml(f.status)}</span></td>
      <td style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap">${f.created?new Date(f.created).toLocaleDateString():'—'}</td>
      <td>
        ${canChallenge ? `<button class="btn btn-outline-secondary btn-sm" style="color:var(--emerald);border-color:rgba(61,203,122,0.4);font-size:0.72rem" onclick="startChallenge('${escHtml(f.id)}')">
          <i class="bi ${challengeIcon} me-1"></i>${challengeLabel}</button>` : `<span style="font-size:0.7rem;color:var(--text-muted)">N/A</span>`}
      </td>
    </tr>`;
  }).join('');
}

// ─── Challenge (same pattern as admin.js) ─────────────────────────────────────

function _factor(id) { return _factorCache.find(f => f.id === id) || {}; }

async function startChallenge(factorId) {
  const f    = _factor(factorId);
  const meta = FACTOR_META[f.factorType] || {};
  cancelChallenge(true);
  _challengeState.factorId = factorId;

  const panel = document.getElementById('challengePanel');
  panel.style.display = '';
  document.getElementById('challengeTitle').textContent = `${meta.label||f.factorType} — ${_fid(f)}`;
  document.getElementById('challengeFactorIdLabel').textContent = factorId;
  ['challengePushState','challengeOtpState','challengeTotpState','challengeResultState'].forEach(id => document.getElementById(id).style.display='none');
  panel.scrollIntoView({ behavior:'smooth', block:'nearest' });

  if (meta.challengeMode === 'totp') {
    document.getElementById('challengeTotpState').style.display = '';
    document.getElementById('totpInput').value = '';
    document.getElementById('totpInput').focus();
    return;
  }

  try {
    const res = await fetch('/api/admin/factor-challenge', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(adminP({ userId: _currentUserId, factorId }))
    }).then(r => r.json());

    if (!res.success && !res.factorResult) { showChallengeResult('error', `Challenge failed: ${escHtml(res.error||`HTTP ${res.statusCode}`)}`); return; }

    if (meta.challengeMode === 'push') {
      _challengeState.pollHref = res.pollHref;
      document.getElementById('challengePushState').style.display = '';
      _startPushPoll();
    } else {
      document.getElementById('otpHint').innerHTML = `OTP sent to <strong>${escHtml(_fid(f))}</strong> — enter the code:`;
      document.getElementById('challengeOtpState').style.display = '';
      document.getElementById('otpInput').value = '';
      document.getElementById('otpInput').focus();
    }
  } catch(e) { showChallengeResult('error', escHtml(e.message)); }
}

function _startPushPoll() {
  _challengeState.attempts = 0;
  _challengeState.pollTimer = setInterval(async () => {
    _challengeState.attempts++;
    document.getElementById('pushMeta').textContent = `Attempt ${_challengeState.attempts}/20 · ${(20-_challengeState.attempts)*3}s remaining`;
    if (_challengeState.attempts >= 20) { clearInterval(_challengeState.pollTimer); showChallengeResult('timeout','⌛ Timed out'); return; }
    const res = await fetch('/api/admin/factor-poll', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(adminP({ pollHref: _challengeState.pollHref }))
    }).then(r=>r.json()).catch(()=>null);
    if (!res) return;
    if (res.factorResult === 'WAITING') return;
    clearInterval(_challengeState.pollTimer);
    if (res.factorResult === 'SUCCESS')   showChallengeResult('success','✅ Push approved — challenge SUCCEEDED');
    else if (res.factorResult==='REJECTED') showChallengeResult('denied','❌ Push rejected — user denied');
    else showChallengeResult('timeout',`⌛ ${res.factorResult||'No response'}`);
  }, 3000);
}

async function verifyOtp() {
  const btn = document.getElementById('verifyOtpBtn');
  const code = document.getElementById('otpInput').value.trim();
  if (!code) { toast('Enter the code first', 'warning'); return; }
  setLoading(btn, true, '<i class="bi bi-check-circle me-1"></i>Verifying…');
  await _doVerify(code);
  setLoading(btn, false, '<i class="bi bi-check-circle me-1"></i>Verify');
}

async function verifyTotp() {
  const btn = document.getElementById('verifyTotpBtn');
  const code = document.getElementById('totpInput').value.trim();
  if (!code) { toast('Enter the code first', 'warning'); return; }
  setLoading(btn, true, '<i class="bi bi-check-circle me-1"></i>Verifying…');
  await _doVerify(code);
  setLoading(btn, false, '<i class="bi bi-check-circle me-1"></i>Verify');
}

async function _doVerify(passCode) {
  document.getElementById('challengeOtpState').style.display='none';
  document.getElementById('challengeTotpState').style.display='none';
  try {
    const res = await fetch('/api/admin/factor-challenge', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(adminP({ userId: _currentUserId, factorId: _challengeState.factorId, passCode }))
    }).then(r=>r.json());
    if (res.factorResult === 'SUCCESS' || res.success) showChallengeResult('success','✅ OTP verified — challenge SUCCEEDED');
    else showChallengeResult('denied',`❌ Failed: ${escHtml(res.response?.errorSummary||res.error||res.factorResult||'invalid code')}`);
  } catch(e) { showChallengeResult('error', escHtml(e.message)); }
}

function showChallengeResult(type, html) {
  ['challengePushState','challengeOtpState','challengeTotpState'].forEach(id => document.getElementById(id).style.display='none');
  const colors = { success:'var(--green)', denied:'var(--red)', timeout:'var(--yellow)', error:'var(--red)' };
  const textEl = document.getElementById('challengeResultText');
  textEl.style.color = colors[type]||'var(--text)';
  textEl.innerHTML = html;
  document.getElementById('challengeResultState').style.display='';
  if (type === 'success') toast('Challenge succeeded!', 'success');
  else if (type === 'denied') toast('Challenge failed', 'error');
}

function cancelChallenge(silent=false) {
  if (_challengeState.pollTimer) { clearInterval(_challengeState.pollTimer); _challengeState.pollTimer=null; }
  _challengeState = { factorId:null, pollHref:null, pollTimer:null, attempts:0 };
  document.getElementById('challengePanel').style.display='none';
  if (!silent) toast('Challenge cancelled', 'info');
}
