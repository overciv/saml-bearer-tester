'use strict';
const CONFIG_FIELDS = ['oktaDomain','authServerId','clientId','clientSecret','authMethod','scope'];

document.addEventListener('DOMContentLoaded', () => {
  window._pageSave = () => savePageConfig('client-creds', CONFIG_FIELDS);
  initNavAuth();
  loadPageConfig('client-creds', CONFIG_FIELDS);
  setupPreview();
  togglePkjwt();
});

function setupPreview() {
  ['oktaDomain','authServerId'].forEach(id =>
    document.getElementById(id)?.addEventListener('input', updatePreview));
  updatePreview();
}

function updatePreview() {
  const d = val('oktaDomain'), s = val('authServerId');
  const ep = d ? (s ? `https://${d}/oauth2/${s}/v1/token` : `https://${d}/oauth2/v1/token`) : '—';
  document.getElementById('endpointPreview').textContent = ep;
}

function togglePkjwt() {
  const isPkjwt = val('authMethod') === 'pkjwt';
  document.getElementById('secretRow').style.display = isPkjwt ? 'none' : '';
  document.getElementById('pkjwtRow').style.display = isPkjwt ? '' : 'none';
}

async function getToken() {
  const btn = document.getElementById('getTokenBtn');
  setLoading(btn, true, '<i class="bi bi-play-fill me-1"></i>Getting…');
  const isPkjwt = val('authMethod') === 'pkjwt';

  let privateJwk;
  if (isPkjwt) {
    try { privateJwk = JSON.parse(val('privateJwk')); }
    catch { toast('Invalid private JWK JSON', 'error'); setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Get Token'); return; }
  }

  try {
    const res = await fetch('/api/oauth/client-creds', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        oktaDomain: val('oktaDomain'), authServerId: val('authServerId'),
        clientId: val('clientId'),
        clientSecret: isPkjwt ? undefined : (document.getElementById('clientSecret')?.value || ''),
        privateJwk,
        scope: val('scope') ? val('scope').split(/\s+/) : ['openid']
      })
    }).then(r => r.json());

    document.getElementById('resultSection').style.display = '';
    document.getElementById('resultStatus').innerHTML =
      renderHttpExchange({ url:res.tokenEndpoint, statusCode:res.statusCode, durationMs:res.durationMs,
        requestDetails:res.requestDetails, response:res.response||res.error });
    document.getElementById('rawResponse').textContent = JSON.stringify(res.response || res.error, null, 2);

    if (res.success && res.response?.access_token) {
      document.getElementById('accessDecoded').innerHTML = renderJwtDecoded(res.response.access_token, 'Access Token');
      sessionStorage.setItem('workflow-tokens', JSON.stringify({
        source: 'client-creds', clientId: val('clientId'), tokens: res.response, timestamp: Date.now()
      }));
      toast('Token received!', 'success');
    } else {
      document.getElementById('accessDecoded').innerHTML = `<div style="color:var(--red);font-size:0.82rem">${escHtml(res.response?.error_description || res.response?.error || `HTTP ${res.statusCode}`)}</div>`;
      toast('Token request failed', 'error');
    }
    showRTab('decoded');
  } catch (e) {
    toast('Error: ' + e.message, 'error');
  } finally {
    setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Get Token');
  }
}

function showRTab(tab) {
  document.getElementById('rTabDecoded').style.display = tab==='decoded'?'':'none';
  document.getElementById('rTabRaw').style.display = tab==='raw'?'':'none';
  document.querySelectorAll('#resTabs .tab-btn').forEach((b,i) => b.classList.toggle('active', ['decoded','raw'][i]===tab));
}

function exportToWorkflow() {
  localStorage.setItem('workflow-import', sessionStorage.getItem('workflow-tokens') || '{}');
  toast('Exported to Test Chain', 'success');
  setTimeout(() => window.location.href = '/workflow.html', 600);
}
