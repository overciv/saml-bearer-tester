'use strict';
const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','clientSecret','scope'];

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadPageConfig('ropc', CONFIG_FIELDS);
  ['oktaDomain','authServerId'].forEach(id =>
    document.getElementById(id)?.addEventListener('input', updatePreview));
  updatePreview();
});

function updatePreview() {
  const d = val('oktaDomain'), s = val('authServerId');
  const ep = d ? (s ? `https://${d}/oauth2/${s}/v1/token` : `https://${d}/oauth2/v1/token`) : '—';
  document.getElementById('endpointPreview').textContent = ep;
}

async function getToken() {
  const btn = document.getElementById('getTokenBtn');
  const missing = [['oktaDomain','Okta Domain'],['clientId','Client ID'],['username','Username'],['password','Password']]
    .filter(([id]) => !val(id) && !(id==='password'&&document.getElementById(id)?.value))
    .map(([,l]) => l);
  if (missing.length) { toast('Missing: ' + missing.join(', '), 'warning'); return; }

  setLoading(btn, true, '<i class="bi bi-play-fill me-1"></i>Getting…');
  try {
    const res = await fetch('/api/oauth/ropc', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        oktaDomain: val('oktaDomain'), authServerId: val('authServerId'),
        clientId: val('clientId'), clientSecret: document.getElementById('clientSecret')?.value || '',
        username: val('username'), password: document.getElementById('password')?.value || '',
        scope: (val('scope') || 'openid').split(/\s+/)
      })
    }).then(r => r.json());

    document.getElementById('resultSection').style.display = '';
    document.getElementById('resultStatus').innerHTML =
      `${statusBadge(res.statusCode)}<span style="font-size:0.75rem;color:var(--text-muted);margin-left:8px">${res.durationMs}ms · ${res.tokenEndpoint}</span>`;
    document.getElementById('rawResponse').textContent = JSON.stringify(res.response || res.error, null, 2);

    if (res.success) {
      if (res.response?.access_token) document.getElementById('accessDecoded').innerHTML = renderJwtDecoded(res.response.access_token, 'Access Token');
      if (res.response?.id_token)     document.getElementById('idDecoded').innerHTML     = renderJwtDecoded(res.response.id_token, 'ID Token');
      sessionStorage.setItem('workflow-tokens', JSON.stringify({ source:'ropc', clientId:val('clientId'), tokens:res.response, timestamp:Date.now() }));
      toast('Token received!', 'success');
    } else {
      document.getElementById('accessDecoded').innerHTML = `<div style="color:var(--red);font-size:0.82rem">${escHtml(res.response?.error_description || res.response?.error || `HTTP ${res.statusCode}`)}</div>`;
      toast('Token request failed', 'error');
    }
    showRTab('access');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Get Token');
  }
}

function showRTab(tab) {
  ['access','id','raw'].forEach((t,i) => {
    document.getElementById(`rTab${t.charAt(0).toUpperCase()+t.slice(1)}`).style.display = t===tab?'':'none';
    document.querySelectorAll('#resTabs .tab-btn')[i].classList.toggle('active', t===tab);
  });
}

function exportToWorkflow() {
  localStorage.setItem('workflow-import', sessionStorage.getItem('workflow-tokens') || '{}');
  toast('Exported to Test Chain', 'success');
  setTimeout(() => window.location.href = '/workflow.html', 600);
}
