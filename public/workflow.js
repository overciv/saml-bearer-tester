'use strict';

// ─── Step Schema ──────────────────────────────────────────────────────────────

const STEP_DEFS = {
  'auth-code': {
    label:'Auth Code + PKCE', icon:'bi-person-badge', color:'var(--blue)',
    bg:'rgba(88,166,255,0.12)',
    inputs:[], outputs:['access_token','id_token','refresh_token'],
    configFields:[
      {k:'clientId',        label:'Client ID',         type:'text',     ph:'0oa...'},
      {k:'scope',           label:'Scope',             type:'text',     ph:'openid profile email'},
      {k:'redirectUri',     label:'Redirect URI',      type:'text',     def:'http://localhost:3000/oauth/callback'},
      {k:'clientAuthMethod',label:'Client Auth',       type:'select',   options:[
        {value:'none',  label:'None (public client)'},
        {value:'basic', label:'Client Secret (Basic)'},
        {value:'pkjwt', label:'Private Key JWT'},
      ]},
      {k:'clientSecret',    label:'Client Secret',     type:'password', ph:'(if Basic auth)'},
      {k:'privateJwk',      label:'Private JWK (JSON)', type:'textarea', ph:'{"kty":"RSA",...} (if PKJWT)'},
    ]
  },
  'client-creds': {
    label:'Client Credentials', icon:'bi-robot', color:'var(--emerald)',
    bg:'rgba(61,203,122,0.1)',
    inputs:[], outputs:['access_token'],
    configFields:[
      {k:'clientId',    label:'Client ID',     type:'text',     ph:'0oa...'},
      {k:'clientSecret',label:'Client Secret', type:'password', ph:''},
      {k:'scope',       label:'Scope',         type:'text',     ph:'openid'},
    ]
  },
  'saml-bearer': {
    label:'SAML 2.0 Bearer', icon:'bi-file-earmark-code', color:'var(--blue)',
    bg:'rgba(88,166,255,0.08)',
    inputs:[], outputs:['access_token','refresh_token'],
    configFields:[
      {k:'clientId',    label:'Client ID',     type:'text'},
      {k:'clientSecret',label:'Client Secret', type:'password'},
      {k:'scope',       label:'Scope',         type:'text', ph:'openid'},
    ]
  },
  'pkjwt-token': {
    label:'Private Key JWT', icon:'bi-key', color:'var(--purple)',
    bg:'rgba(188,140,255,0.1)',
    inputs:[], outputs:['access_token','refresh_token'],
    configFields:[
      {k:'clientId',  label:'Client ID', type:'text'},
      {k:'scope',     label:'Scope',     type:'text', ph:'openid'},
    ]
  },
  'dpop-token': {
    label:'DPoP Token', icon:'bi-fingerprint', color:'var(--blue)',
    bg:'rgba(88,166,255,0.08)',
    inputs:[], outputs:['access_token','refresh_token'],
    configFields:[
      {k:'clientId',    label:'Client ID',         type:'text'},
      {k:'clientSecret',label:'Client Secret',     type:'password'},
      {k:'scope',       label:'Scope',             type:'text',   ph:'openid'},
      {k:'grantType',   label:'Grant Type',        type:'select', options:[
        {value:'client_credentials', label:'client_credentials'},
        {value:'refresh_token',      label:'refresh_token'},
      ]},
      {k:'refreshToken',label:'Refresh Token',     type:'text',   ph:'(required when grant = refresh_token)'},
      {k:'dpopAlg',     label:'DPoP Key Algorithm',type:'select', options:[
        {value:'ES256', label:'ES256 — EC P-256 (recommended)'},
        {value:'ES384', label:'ES384 — EC P-384'},
        {value:'RS256', label:'RS256 — RSA 2048'},
        {value:'PS256', label:'PS256 — RSA-PSS 2048'},
      ]},
    ]
  },
  'ropc': {
    label:'ROPC (Resource Owner Password)', icon:'bi-person-lock', color:'var(--orange)',
    bg:'rgba(255,166,87,0.1)',
    inputs:[], outputs:['access_token','id_token','refresh_token'],
    configFields:[
      {k:'clientId',    label:'Client ID',     type:'text'},
      {k:'clientSecret',label:'Client Secret', type:'password'},
      {k:'username',    label:'Username',      type:'email',    ph:'user@example.com'},
      {k:'password',    label:'Password',      type:'password'},
      {k:'scope',       label:'Scope',         type:'text',     ph:'openid profile email'},
    ]
  },
  'ciba': {
    label:'CIBA', icon:'bi-phone-vibrate', color:'var(--teal)',
    bg:'rgba(45,217,198,0.1)',
    inputs:[], outputs:['access_token','id_token'],
    configFields:[
      {k:'loginHint',     label:'Login Hint (email)', type:'email'},
      {k:'bindingMessage',label:'Binding Message',    type:'text'},
      {k:'clientId',      label:'Client ID',          type:'text'},
      {k:'clientSecret',  label:'Client Secret',      type:'password'},
      {k:'scope',         label:'Scope',              type:'text', ph:'openid'},
    ]
  },
  'token-exchange': {
    label:'Token Exchange', icon:'bi-arrow-left-right', color:'var(--coral)',
    bg:'rgba(247,129,102,0.1)',
    inputs:[{name:'subject_token', accepts:['access_token','id_token']}],
    outputs:['access_token','id_token','refresh_token'],
    configFields:[
      {k:'clientId',    label:'App B Client ID',     type:'text'},
      {k:'clientSecret',label:'App B Client Secret', type:'password'},
      {k:'scope',       label:'Scope',               type:'text', ph:'openid'},
    ]
  },
  'mfa-list-factors': {
    label:'MFA: List Factors', icon:'bi-shield-lock', color:'var(--emerald)',
    bg:'rgba(61,203,122,0.1)',
    inputs:[],
    outputs:['user_id'],
    configFields:[
      {k:'userLogin',   label:'User Login/Email', type:'email', ph:'user@example.com'},
      {k:'adminToken',  label:'Admin API Token',  type:'password', ph:'00YXSE_...'},
    ]
  },
  'mfa-challenge': {
    label:'MFA: Challenge', icon:'bi-shield-check', color:'var(--emerald)',
    bg:'rgba(61,203,122,0.1)',
    inputs:[{name:'user_id', accepts:['user_id']}],
    outputs:['challenge_result'],
    configFields:[
      {k:'userLogin',   label:'User Login (if no input bound)', type:'email', ph:'user@example.com'},
      {k:'factorType',  label:'Factor type to challenge',       type:'text', ph:'push (or leave empty for first active factor)'},
      {k:'adminToken',  label:'Admin API Token', type:'password', ph:'00YXSE_...'},
    ]
  },
  'step-up-auth': {
    label:'Step-Up Auth', icon:'bi-arrow-up-circle', color:'var(--blue)',
    bg:'rgba(88,166,255,0.12)',
    inputs:[],
    outputs:['access_token','id_token'],
    configFields:[
      {k:'clientId',   label:'Client ID',     type:'text'},
      {k:'acrValues',  label:'ACR Values',    type:'text', def:'urn:okta:loa:2fa:any', ph:'urn:okta:loa:2fa:any'},
      {k:'scope',      label:'Scope',         type:'text', ph:'openid profile email'},
      {k:'redirectUri',label:'Redirect URI',  type:'text', def:'http://localhost:3000/oauth/callback'},
    ]
  },
  'token-inspect': {
    label:'Token Inspector', icon:'bi-search', color:'var(--amber)',
    bg:'rgba(227,179,65,0.1)',
    inputs:[{name:'token', accepts:['access_token','id_token','refresh_token']}],
    outputs:[],
    configFields:[]
  },
  'token-revoke': {
    label:'Token Revoke + Verify', icon:'bi-x-circle', color:'var(--red)',
    bg:'rgba(248,81,73,0.1)',
    inputs:[{name:'token', accepts:['access_token','refresh_token']}],
    outputs:[],
    configFields:[
      {k:'clientId',    label:'Client ID',     type:'text'},
      {k:'clientSecret',label:'Client Secret', type:'password'},
    ]
  },
};

// ─── State ────────────────────────────────────────────────────────────────────

let chain = [];  // array of step objects
let outputStore = {};  // { 'stepId.outputName': value }
let dragType = null;

const G = () => JSON.parse(localStorage.getItem('oauthst-global') || '{}');

// ─── Named chain saves ────────────────────────────────────────────────────────

const SAVED_KEY = 'workflow-saved-chains';

function getSavedChains() {
  try { return JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch { return []; }
}
function _writeSavedChains(chains) { localStorage.setItem(SAVED_KEY, JSON.stringify(chains)); }

function openSaveDialog() {
  if (!chain.length) { toast('Add some steps first', 'warning'); return; }
  const def = chain.map(s => STEP_DEFS[s.type]?.label || s.type).join(' → ').slice(0, 50);
  document.getElementById('saveChainName').value = def;
  document.getElementById('saveChainModal').style.display = 'flex';
  setTimeout(() => { const i = document.getElementById('saveChainName'); i.focus(); i.select(); }, 50);
}

function closeSaveModal() {
  document.getElementById('saveChainModal').style.display = 'none';
}

function confirmSave() {
  const name = document.getElementById('saveChainName').value.trim();
  if (!name) { toast('Enter a name', 'warning'); return; }
  const chains = getSavedChains();
  chains.unshift({
    id: 'chain_' + Date.now(),
    name,
    steps: chain.map(s => ({ id: s.id, type: s.type, config: { ...s.config }, bindings: { ...s.bindings } })),
    stepCount: chain.length,
    savedAt: new Date().toISOString()
  });
  _writeSavedChains(chains);
  closeSaveModal();
  _updateSavedBadge();
  toast(`"${name}" saved`, 'success');
}

function toggleSavedPanel() {
  const p = document.getElementById('savedChainsPanel');
  if (p.style.display === 'none') { _renderSavedList(); p.style.display = ''; }
  else closeSavedPanel();
}
function closeSavedPanel() { document.getElementById('savedChainsPanel').style.display = 'none'; }

function _renderSavedList() {
  const chains = getSavedChains();
  const list = document.getElementById('savedChainsList');
  if (!chains.length) {
    list.innerHTML = '<div style="text-align:center;color:var(--text-muted);font-size:0.82rem;padding:24px 12px">No saved chains yet.<br>Build a chain and click <strong>Save</strong>.</div>';
    return;
  }
  list.innerHTML = chains.map(c => {
    const d = new Date(c.savedAt);
    const ago = _timeAgo(d);
    return `<div style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;background:var(--surface2)">
      <div style="font-weight:600;font-size:0.83rem;margin-bottom:2px">${escHtml(c.name)}</div>
      <div style="font-size:0.7rem;color:var(--text-muted)">${c.stepCount} step${c.stepCount!==1?'s':''} · ${escHtml(ago)}</div>
      <div class="d-flex gap-2 mt-2 align-items-center">
        <button class="btn btn-sm" style="background:var(--blue);color:#0d1117;font-weight:600;border:none;font-size:0.72rem" onclick="loadSavedChain('${c.id}')">
          <i class="bi bi-arrow-right-circle me-1"></i>Load
        </button>
        <button class="btn btn-outline-secondary btn-sm" style="font-size:0.72rem" onclick="duplicateSavedChain('${c.id}')">
          <i class="bi bi-copy"></i>
        </button>
        <button class="btn btn-sm ms-auto" style="color:var(--red);border:1px solid rgba(248,81,73,0.4);background:rgba(248,81,73,0.06);font-size:0.72rem" onclick="deleteSavedChain('${c.id}')">
          <i class="bi bi-trash"></i>
        </button>
      </div>
    </div>`;
  }).join('');
}

function loadSavedChain(id) {
  const saved = getSavedChains().find(c => c.id === id);
  if (!saved) { toast('Chain not found', 'error'); return; }
  if (chain.length && !confirm(`Load "${saved.name}"?\nThe current chain will be replaced.`)) return;

  chain = saved.steps.map(s => ({
    ...makeStep(s.type, s.id),
    config: s.config || {},
    bindings: s.bindings || {}
  }));
  outputStore = {};
  saveChain();
  renderPipeline();
  closeSavedPanel();
  toast(`Loaded "${saved.name}"`, 'success');
}

function duplicateSavedChain(id) {
  const all    = getSavedChains();
  const saved  = all.find(c => c.id === id);
  if (!saved) return;

  // Build old→new ID map so bindings stay correct
  const idMap = {};
  saved.steps.forEach(s => { idMap[s.id] = 's_' + Date.now() + '_' + Math.random().toString(36).slice(2,6); });

  const newSteps = saved.steps.map(s => {
    const newBindings = {};
    Object.entries(s.bindings || {}).forEach(([inp, b]) => {
      newBindings[inp] = { ...b, stepId: idMap[b.stepId] || b.stepId,
        value: b.value ? b.value.replace(b.stepId, idMap[b.stepId] || b.stepId) : b.value };
    });
    return { id: idMap[s.id], type: s.type, config: { ...s.config }, bindings: newBindings };
  });

  all.unshift({ id: 'chain_' + Date.now(), name: saved.name + ' (copy)', steps: newSteps,
    stepCount: newSteps.length, savedAt: new Date().toISOString() });
  _writeSavedChains(all);
  _renderSavedList();
  _updateSavedBadge();
  toast(`Duplicated as "${saved.name} (copy)"`, 'success');
}

function deleteSavedChain(id) {
  const chains = getSavedChains();
  const c = chains.find(x => x.id === id);
  if (!confirm(`Delete "${c?.name}"?`)) return;
  _writeSavedChains(chains.filter(x => x.id !== id));
  _renderSavedList();
  _updateSavedBadge();
  toast('Deleted', 'info');
}

function _updateSavedBadge() {
  const count = getSavedChains().length;
  const btn = document.getElementById('loadChainsBtn');
  if (!btn) return;
  btn.innerHTML = `<i class="bi bi-bookmark-star me-1"></i>Saved${count
    ? ` <span style="background:var(--blue);color:#0d1117;border-radius:10px;padding:0 5px;font-size:0.65rem;font-weight:700;margin-left:2px">${count}</span>`
    : ''}`;
}

function _timeAgo(date) {
  const s = (Date.now() - date) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  if (s < 86400*7) return `${Math.floor(s/86400)}d ago`;
  return date.toLocaleDateString('en', { month:'short', day:'numeric' });
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadChain();
  _updateSavedBadge();

  // Import tokens from auth-code or client-creds pages
  const imported = localStorage.getItem('workflow-import');
  if (imported) {
    try {
      const data = JSON.parse(imported);
      if (data.tokens && data.source) {
        const stepType = data.source === 'auth-code' ? 'auth-code' : 'client-creds';
        if (!chain.find(s => s.type === stepType)) {
          const s = makeStep(stepType);
          if (data.clientId) s.config.clientId = data.clientId;
          chain.unshift(s);
          // Pre-store the outputs
          if (data.tokens.access_token) outputStore[`${s.id}.access_token`] = data.tokens.access_token;
          if (data.tokens.id_token)     outputStore[`${s.id}.id_token`]     = data.tokens.id_token;
          if (data.tokens.refresh_token) outputStore[`${s.id}.refresh_token`] = data.tokens.refresh_token;
          s.result = { success: true, outputs: data.tokens };
          s.status = 'success';
          saveChain();
          toast('Imported tokens from ' + (data.source === 'auth-code' ? 'Auth Code' : 'Client Credentials') + ' tester', 'success');
        }
        localStorage.removeItem('workflow-import');
      }
    } catch {}
  }

  renderPipeline();
});

// ─── Chain persistence ────────────────────────────────────────────────────────

function saveChain() {
  localStorage.setItem('workflow-chain', JSON.stringify(chain.map(s => ({
    id: s.id, type: s.type, config: s.config, bindings: s.bindings
  }))));
}

function loadChain() {
  try {
    const saved = JSON.parse(localStorage.getItem('workflow-chain') || '[]');
    chain = saved.map(s => ({ ...makeStep(s.type, s.id), config: s.config || {}, bindings: s.bindings || {} }));
  } catch { chain = []; }
}

function clearChain() {
  if (chain.length && !confirm('Clear the entire chain?')) return;
  chain = []; outputStore = {};
  localStorage.removeItem('workflow-chain');
  renderPipeline();
  document.getElementById('runLog').style.display = 'none';
}

// ─── Step management ──────────────────────────────────────────────────────────

function makeStep(type, id) {
  const def = STEP_DEFS[type];
  const g = G();
  const config = {};
  // Pre-fill common fields from global settings
  if (def?.configFields) {
    def.configFields.forEach(f => {
      if (f.def) config[f.k] = f.def;
      if (f.k === 'clientId' && g.clientId)     config[f.k] = g.clientId;
      if (f.k === 'clientSecret' && g.clientSecret) config[f.k] = g.clientSecret;
    });
  }
  return { id: id || ('s_' + Date.now() + '_' + Math.random().toString(36).slice(2,6)), type, config, bindings: {}, result: null, status: 'idle' };
}

function addStep(type) {
  if (!STEP_DEFS[type]) return;
  chain.push(makeStep(type));
  saveChain();
  renderPipeline();
}

function removeStep(id) {
  chain = chain.filter(s => s.id !== id);
  // Remove bindings that reference removed step
  chain.forEach(s => {
    Object.keys(s.bindings).forEach(k => {
      if (s.bindings[k]?.stepId === id) delete s.bindings[k];
    });
  });
  saveChain();
  renderPipeline();
}

function moveStep(id, dir) {
  const i = chain.findIndex(s => s.id === id);
  if (i < 0) return;
  const j = i + dir;
  if (j < 0 || j >= chain.length) return;
  [chain[i], chain[j]] = [chain[j], chain[i]];
  saveChain();
  renderPipeline();
}

// ─── Drag & Drop ──────────────────────────────────────────────────────────────

function onCatalogDrag(e, type) { dragType = type; e.dataTransfer.effectAllowed = 'copy'; }

function onPipelineDrop(e) {
  e.preventDefault();
  if (dragType) { addStep(dragType); dragType = null; }
}

// ─── Render ───────────────────────────────────────────────────────────────────

function renderPipeline() {
  const container = document.getElementById('pipelineSteps');
  const empty = document.getElementById('pipelineEmpty');
  empty.style.display = chain.length ? 'none' : '';
  container.innerHTML = '';
  document.getElementById('chainStatus').textContent = chain.length ? `${chain.length} step${chain.length>1?'s':''}` : '';

  chain.forEach((step, idx) => {
    // Connector from previous step
    if (idx > 0) {
      const conn = document.createElement('div');
      conn.className = 'step-connector';
      const prevStep = chain[idx - 1];
      const binding = Object.values(step.bindings)[0];
      const connLabel = binding ? `${binding.outputName} →` : '';
      conn.innerHTML = connLabel
        ? `<span class="step-connector-label" style="color:var(--blue)">${escHtml(connLabel)}</span>`
        : `<span class="step-connector-label">↓</span>`;
      container.appendChild(conn);
    }

    container.appendChild(renderStepCard(step, idx));
  });

  // Drop zone at bottom
  const drop = document.createElement('div');
  drop.style.cssText = 'border:2px dashed var(--border);border-radius:10px;padding:20px;text-align:center;color:var(--text-muted);font-size:0.8rem;margin-top:8px;cursor:pointer;';
  drop.innerHTML = '<i class="bi bi-plus-circle me-1"></i>Drop a step here or click in the catalog';
  container.appendChild(drop);
}

function renderStepCard(step, idx) {
  const def = STEP_DEFS[step.type];
  if (!def) return document.createElement('div');

  const card = document.createElement('div');
  card.className = `step-card ${step.status}`;
  card.id = `card-${step.id}`;

  const statusBadgeHtml = {
    idle:    '',
    running: '<span class="step-badge" style="background:rgba(88,166,255,0.15);color:var(--blue)"><span class="spinner-border spinner-border-sm me-1"></span>Running</span>',
    success: '<span class="step-badge" style="background:rgba(63,185,80,0.15);color:var(--green)">✓ Success</span>',
    error:   '<span class="step-badge" style="background:rgba(248,81,73,0.12);color:var(--red)">✗ Error</span>',
  }[step.status] || '';

  // Build input binding rows
  const inputRows = (def.inputs || []).map(inp => {
    const options = getAvailableOutputs(step.id, inp.accepts);
    const bound = step.bindings[inp.name];
    const sel = `<select class="binding-select" onchange="setBinding('${step.id}','${inp.name}',this.value)">
      <option value="">— not bound —</option>
      ${options.map(o => `<option value="${o.value}" ${bound && bound.value===o.value?'selected':''}>${escHtml(o.label)}</option>`).join('')}
    </select>`;
    return `<div class="binding-row"><span class="binding-name">${escHtml(inp.name)}</span>${sel}</div>`;
  }).join('');

  // Output chips
  const outputChips = (def.outputs || []).map(out => {
    const val = outputStore[`${step.id}.${out}`];
    const short = val ? (val.length > 30 ? val.slice(0,30)+'…' : val) : '';
    return `<span class="output-chip ${val?'has-value':'no-value'}" style="background:${val?'rgba(88,166,255,0.1)':'var(--surface2)'};color:${val?'var(--blue)':'var(--text-muted)'};border:1px solid ${val?'rgba(88,166,255,0.25)':'var(--border)'}" title="${escHtml(short)}">
      ● ${escHtml(out)}${val ? ` <span style="font-size:0.6rem;opacity:0.7">✓</span>` : ''}
    </span>`;
  }).join('');

  // Config form
  const configRows = (def.configFields || []).map(f => {
    const v = step.config[f.k] || f.def || '';
    let input;
    if (f.type === 'select' && f.options) {
      const opts = f.options.map(o => `<option value="${escHtml(o.value)}" ${v===o.value?'selected':''}>${escHtml(o.label)}</option>`).join('');
      input = `<select class="form-control form-control-sm" onchange="setConfig('${step.id}','${f.k}',this.value)">${opts}</select>`;
    } else if (f.type === 'textarea') {
      input = `<textarea class="form-control form-control-sm" rows="2" placeholder="${escHtml(f.ph||'')}" style="font-family:monospace;font-size:0.72rem;resize:vertical"
        oninput="setConfig('${step.id}','${f.k}',this.value)">${escHtml(v)}</textarea>`;
    } else {
      input = `<input type="${f.type||'text'}" class="form-control form-control-sm" value="${escHtml(v)}" placeholder="${escHtml(f.ph||'')}"
        oninput="setConfig('${step.id}','${f.k}',this.value)">`;
    }
    return `<div class="step-config-row"><div style="flex:1"><div class="form-label">${escHtml(f.label)}</div>${input}</div></div>`;
  }).join('');

  // Result display
  let resultHtml = '';
  if (step.result) {
    if (step.result.error) {
      resultHtml = `<div class="step-result">
        <div style="color:var(--red);font-size:0.78rem;margin-bottom:6px">✗ ${escHtml(step.result.error)}</div>
        <div class="d-flex gap-2">
          <button class="btn btn-sm" style="color:var(--yellow);border:1px solid var(--yellow);background:rgba(210,153,34,0.08);font-size:0.72rem"
            onclick="retryFromStep('${step.id}')">
            <i class="bi bi-arrow-clockwise me-1"></i>Retry from here
          </button>
          <button class="btn btn-sm" style="color:var(--text-muted);border:1px solid var(--border);font-size:0.72rem"
            onclick="skipStepAndContinue('${step.id}')">
            <i class="bi bi-skip-forward me-1"></i>Skip &amp; continue
          </button>
        </div>
      </div>`;
    } else {
      resultHtml = _renderStepResult(step);
    }
  }

  card.innerHTML = `
    <div class="step-header" title="Drag to reorder">
      <span class="step-num">${idx+1}</span>
      <span class="step-icon" style="background:${def.bg};color:${def.color}"><i class="bi ${def.icon}"></i></span>
      <span class="step-title" style="color:${def.color}">${escHtml(def.label)}</span>
      ${statusBadgeHtml}
      <div class="d-flex gap-1 ms-2">
        ${idx > 0 ? `<button class="btn btn-outline-secondary btn-sm" onclick="moveStep('${step.id}',-1)" title="Move up"><i class="bi bi-arrow-up"></i></button>` : ''}
        ${idx < chain.length-1 ? `<button class="btn btn-outline-secondary btn-sm" onclick="moveStep('${step.id}',1)" title="Move down"><i class="bi bi-arrow-down"></i></button>` : ''}
        <button class="btn btn-outline-secondary btn-sm" onclick="removeStep('${step.id}')" title="Remove" style="color:var(--red)"><i class="bi bi-x"></i></button>
      </div>
    </div>
    <div class="step-body">
      ${inputRows ? `<div style="margin-bottom:6px">${inputRows}</div>` : ''}
      ${configRows ? `<div class="step-config"><div style="font-size:0.68rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;">Configuration</div>${configRows}</div>` : ''}
      ${outputChips ? `<div class="output-chips" style="margin-top:8px">${outputChips}</div>` : ''}
      ${resultHtml}
    </div>`;

  return card;
}

function getAvailableOutputs(currentStepId, accepts) {
  const options = [];
  for (const s of chain) {
    if (s.id === currentStepId) break;
    const def = STEP_DEFS[s.type];
    (def?.outputs || []).forEach(out => {
      if (!accepts?.length || accepts.includes(out)) {
        options.push({ value: `${s.id}.${out}`, label: `Step ${chain.indexOf(s)+1}: ${def.label} → ${out}` });
      }
    });
  }
  return options;
}

function setBinding(stepId, inputName, value) {
  const step = chain.find(s => s.id === stepId);
  if (!step) return;
  if (!value) { delete step.bindings[inputName]; }
  else {
    const [sid, out] = value.split('.');
    step.bindings[inputName] = { stepId: sid, outputName: out, value };
  }
  saveChain();
}

function setConfig(stepId, key, value) {
  const step = chain.find(s => s.id === stepId);
  if (step) { step.config[key] = value; saveChain(); }
}

// ─── Execution ────────────────────────────────────────────────────────────────

let _chainRunning  = false;
let _chainAborted  = false;
let _chainStartIdx = 0; // index to resume/retry from

async function runChain(fromIdx = 0) {
  if (_chainRunning) { toast('Chain is already running', 'warning'); return; }
  if (!chain.length) { toast('Add some steps first', 'warning'); return; }

  _chainRunning = true;
  _chainAborted = false;
  _chainStartIdx = fromIdx;

  const runBtn  = document.getElementById('runBtn');
  const stopBtn = document.getElementById('stopBtn');
  setLoading(runBtn, true, '<i class="bi bi-play-fill me-1"></i>Running…');
  if (stopBtn) stopBtn.style.display = '';

  document.getElementById('runLog').style.display = '';
  if (fromIdx === 0) {
    document.getElementById('runLogEntries').innerHTML = '';
    outputStore = {};
    chain.forEach(s => { s.status = 'idle'; s.result = null; });
  } else {
    // Partial restart: reset from fromIdx onward, keep earlier outputs
    chain.slice(fromIdx).forEach(s => { s.status = 'idle'; s.result = null; });
  }
  renderPipeline();

  const g = G();
  const domain = g.oktaDomain || '';
  const sid    = g.authServerId || '';

  document.getElementById('chainStatus').textContent = `Running… (${chain.length} step${chain.length>1?'s':''})`;

  for (let i = fromIdx; i < chain.length; i++) {
    if (_chainAborted) {
      chain[i].status = 'idle';
      document.getElementById('chainStatus').textContent = `⏹ Stopped at step ${i+1}`;
      break;
    }

    const step = chain[i];
    step.status = 'running';
    renderPipeline();

    // Resolve inputs from outputStore
    const inputs = {};
    for (const [iname, binding] of Object.entries(step.bindings || {})) {
      const key = `${binding.stepId}.${binding.outputName}`;
      inputs[iname] = outputStore[key];
    }

    const t0 = Date.now();
    let result;
    try {
      result = await executeStep(step, inputs, domain, sid);
    } catch (e) {
      result = { success: false, error: e.message, outputs: {} };
    }

    step.result = result;
    step.status = result.success ? 'success' : 'error';

    if (result.outputs) {
      Object.entries(result.outputs).forEach(([k, v]) => { if (v) outputStore[`${step.id}.${k}`] = v; });
    }

    addLog(i+1, STEP_DEFS[step.type]?.label || step.type, result.success, Date.now()-t0, result.error);
    renderPipeline();
    await new Promise(r => setTimeout(r, 50));

    if (!result.success && !_chainAborted) {
      // Chain paused on failure — show recovery options
      const label = STEP_DEFS[step.type]?.label || step.type;
      document.getElementById('chainStatus').textContent = `⚠️ Paused at step ${i+1} (${label})`;
      toast(`Chain paused — step ${i+1} failed. Fix the config then retry.`, 'error');
      break;
    }
  }

  const allDone = chain.every(s => s.status === 'success');
  if (allDone) document.getElementById('chainStatus').textContent = `✅ All ${chain.length} steps completed`;

  _chainRunning = false;
  setLoading(runBtn, false, '<i class="bi bi-play-fill me-1"></i>Run Chain');
  if (stopBtn) stopBtn.style.display = 'none';
}

function stopChain() {
  _chainAborted = true;
  toast('Chain aborted', 'info');
}

function restartChain() {
  if (_chainRunning) { toast('Stop the chain first', 'warning'); return; }
  outputStore = {};
  chain.forEach(s => { s.status = 'idle'; s.result = null; });
  renderPipeline();
  document.getElementById('runLogEntries').innerHTML = '';
  document.getElementById('chainStatus').textContent = '';
  toast('Chain reset — ready to run', 'info');
}

function retryFromStep(stepId) {
  if (_chainRunning) { toast('Stop the chain first', 'warning'); return; }
  const idx = chain.findIndex(s => s.id === stepId);
  if (idx < 0) return;
  // Clear results from this step onward
  chain.slice(idx).forEach(s => { s.status = 'idle'; s.result = null; });
  chain.slice(idx).forEach(s => {
    const def = STEP_DEFS[s.type];
    (def?.outputs || []).forEach(out => delete outputStore[`${s.id}.${out}`]);
  });
  renderPipeline();
  toast(`Retrying from step ${idx+1}…`, 'info');
  runChain(idx);
}

function skipStepAndContinue(stepId) {
  if (_chainRunning) { toast('Stop the chain first', 'warning'); return; }
  const idx = chain.findIndex(s => s.id === stepId);
  if (idx < 0) return;
  chain[idx].status = 'idle';
  chain[idx].result = null;
  renderPipeline();
  toast(`Skipping step ${idx+1}, continuing from step ${idx+2}…`, 'warning');
  runChain(idx + 1);
}

function renderStepCard_update(step) { renderPipeline(); }

// ─── Result display helpers ───────────────────────────────────────────────────

function _tokenSummary(token) {
  if (!token) return null;
  const d = decodeJwt(token);
  if (!d) return null;
  const p = d.payload;
  const exp = p.exp ? new Date(p.exp * 1000) : null;
  return {
    _type: p.uid ? 'User Token' : 'Machine (M2M)',
    _dpop: !!p.cnf?.jkt,
    sub:   p.sub,
    cid:   p.cid,
    acr:   p.acr ? p.acr.replace('urn:okta:loa:','') : undefined,
    amr:   Array.isArray(p.amr) ? p.amr.join(', ') : p.amr,
    scp:   Array.isArray(p.scp) ? p.scp.join(' ') : p.scp,
    exp:   exp ? exp.toLocaleString() : undefined,
    _expired: !!(exp && exp < new Date()),
  };
}

function _renderStepResult(step) {
  const r = step.result;
  if (!r) return '';
  const _btn = `<div style="margin-top:5px"><button class="btn btn-outline-secondary btn-sm" style="font-size:0.68rem" onclick="showStepResult('${step.id}')"><i class="bi bi-eye me-1"></i>View full result</button></div>`;

  // Timing badge (shown for all steps that have it)
  const timing = r.durationMs != null
    ? `<span style="background:rgba(45,217,198,0.1);color:#2dd9c6;border:1px solid rgba(45,217,198,0.25);border-radius:10px;padding:1px 7px;font-size:0.68rem;font-weight:700;font-family:monospace;display:inline-block;margin-bottom:5px">⏱ ${r.durationMs}ms</span> `
    : '';

  // ── token-inspect: show decoded claims ─────────────────────────────────────
  if (step.type === 'token-inspect' && r.decoded) {
    const p = r.decoded.payload;
    /* compact preview below; full RFC table is in the modal */
    const exp  = p.exp ? new Date(p.exp * 1000) : null;
    const ok   = exp && exp > new Date();
    const keys = ['sub','cid','uid','acr','amr','scp'];
    const rows = keys.filter(k => p[k] !== undefined).map(k => {
      const v = Array.isArray(p[k]) ? p[k].join(', ') : String(p[k]);
      return `<div class="result-output-row">
        <span class="result-key" style="color:#e3b341">${k}</span>
        <span class="result-val">${escHtml(v.length>80 ? v.slice(0,80)+'…' : v)}</span>
      </div>`;
    }).join('');
    const expRow = exp ? `<div class="result-output-row">
      <span class="result-key" style="color:#e3b341">exp</span>
      <span class="result-val" style="color:${ok?'var(--green)':'var(--red)'}">${ok?'✓ Valid':'⚠ Expired'} · ${exp.toLocaleString()}</span>
    </div>` : '';
    const dpop = p.cnf?.jkt ? `<span style="color:#2dd9c6;font-size:0.68rem"> · DPoP-bound</span>` : '';
    const typeLabel = p.uid ? 'User Token' : 'Machine Token (M2M)';
    return `<div class="step-result">
      ${timing}<span style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted)">${typeLabel}${dpop}</span>
      ${rows}${expRow}
    </div>${_btn}`;
  }

  // ── token-revoke: show revocation verdict ──────────────────────────────────
  if (step.type === 'token-revoke') {
    const icon = r.revoked ? '✓' : '⚠';
    const color = r.revoked ? 'var(--green)' : 'var(--yellow)';
    const msg   = r.revoked ? 'Revoked — active: false (confirmed)' : 'Revoke sent (introspect still pending)';
    return `<div class="step-result">${timing}<span style="color:${color};font-size:0.78rem">${icon} ${msg}</span></div>${_btn}`;
  }

  // ── mfa-list-factors: factor list ─────────────────────────────────────────
  if (step.type === 'mfa-list-factors' && (r.factorCount != null || r.summary)) {
    return `<div class="step-result">${timing}
      <div style="font-size:0.78rem;color:var(--green)">✓ ${r.factorCount ?? '?'} factor${r.factorCount!==1?'s':''} found</div>
      ${r.summary ? `<div style="font-size:0.72rem;color:var(--text-muted);margin-top:2px">${escHtml(r.summary)}</div>` : ''}
    </div>${_btn}`;
  }

  // ── token summary for all token-producing steps ────────────────────────────
  if (r.summary && typeof r.summary === 'object') {
    const s = r.summary;
    const typeLine = s._type ? `<div style="font-size:0.68rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:3px">${s._type}${s._dpop?' · DPoP':''}</div>` : '';
    const rows = [
      s.sub && ['sub', s.sub],
      s.cid && ['cid', s.cid],
      s.acr && ['acr', s.acr],
      s.amr && ['amr', s.amr],
      s.scp && ['scope', s.scp],
      s.exp && ['exp', (s._expired ? '⚠ Expired · ' : '✓ Valid · ') + s.exp],
    ].filter(Boolean).map(([k,v]) => `<div class="result-output-row">
      <span class="result-key">${k}</span>
      <span class="result-val" style="${k==='exp'&&s._expired?'color:var(--red)':k==='exp'?'color:var(--green)':''}">${escHtml(v.slice(0,80)+(v.length>80?'…':''))}</span>
    </div>`).join('');
    return `<div class="step-result">${timing}${typeLine}${rows}</div>${_btn}`;
  }

  // ── Named outputs (fallback) ───────────────────────────────────────────────
  if (r.outputs && Object.keys(r.outputs).filter(k => r.outputs[k]).length) {
    const rows = Object.entries(r.outputs).filter(([,v]) => v).map(([k,v]) =>
      `<div class="result-output-row">
        <span class="result-key">${escHtml(k)}</span>
        <span class="result-val" onclick="showTokenPopup('${escHtml(String(v))}')">${escHtml(String(v).slice(0,60)+(String(v).length>60?'…':''))}</span>
        <button class="btn btn-outline-secondary btn-sm" onclick="copyRaw('${escHtml(String(v))}')" title="Copy"><i class="bi bi-clipboard"></i></button>
      </div>`).join('');
    return `<div class="step-result">${timing}${rows}</div>${_btn}`;
  }

  // ── Bare success ───────────────────────────────────────────────────────────
  return `<div class="step-result">${timing}<span style="color:var(--green);font-size:0.78rem">✓ Completed</span></div>${_btn}`;
}

// Appends the "View full result" button to any successful step card result area
function _viewBtn(stepId) {
  return `<div style="margin-top:6px">
    <button class="btn btn-outline-secondary btn-sm" style="font-size:0.7rem" onclick="showStepResult('${stepId}')">
      <i class="bi bi-eye me-1"></i>View full result
    </button>
  </div>`;
}

// ─── Step Result Modal ────────────────────────────────────────────────────────
// Shows IDENTICAL content to the standalone test page inside a modal overlay.

let _stepModalKeyHandler = null;

function showStepResult(stepId) {
  const step = chain.find(s => s.id === stepId);
  if (!step?.result) return;
  const def = STEP_DEFS[step.type];
  const r   = step.result;
  const idx = chain.indexOf(step);

  // Title
  document.getElementById('stepResultTitle').innerHTML =
    `<span style="width:22px;height:22px;border-radius:5px;background:${def.bg};color:${def.color};display:inline-flex;align-items:center;justify-content:center;font-size:0.78rem;margin-right:8px;flex-shrink:0"><i class="bi ${def.icon}"></i></span>
     Step ${idx+1} — ${escHtml(def.label)}
     ${r.durationMs!=null?`<span style="background:rgba(45,217,198,0.1);color:#2dd9c6;border:1px solid rgba(45,217,198,0.25);border-radius:10px;padding:1px 8px;font-size:0.68rem;font-weight:700;font-family:monospace;margin-left:8px">⏱ ${r.durationMs}ms</span>`:''}`;

  let html = '';

  // ── token-inspect: exact same RFC table as the standalone page ──────────────
  if (step.type === 'token-inspect' && r.decoded) {
    html = renderTokenBadges(r.decoded) + renderClaimsTable(r.decoded.payload);
  }

  // ── token-revoke: show the two-step timeline ────────────────────────────────
  else if (step.type === 'token-revoke') {
    const verdict = r.revoked
      ? `<div style="color:var(--green);font-size:0.85rem;font-weight:600;margin-bottom:12px">✓ Token successfully revoked — active: false confirmed via introspect</div>`
      : `<div style="color:var(--yellow);font-size:0.85rem;font-weight:600;margin-bottom:12px">⚠ Revoke sent — introspect verification pending</div>`;
    html = verdict + (r.steps||[]).map((s,i) => {
      const ok = s.success !== false;
      return `<details${i===((r.steps||[]).length-1)?' open':''} style="margin-bottom:6px">
        <summary style="cursor:pointer;padding:7px 10px;background:var(--surface2);border-radius:7px;font-size:0.8rem;list-style:none;display:flex;align-items:center;gap:8px">
          <span style="width:8px;height:8px;border-radius:50%;background:${ok?'var(--green)':'var(--red)'};flex-shrink:0"></span>
          <span style="font-weight:600">${escHtml(s.label)}</span>
          ${s.statusCode?`<span style="color:var(--text-muted);font-size:0.72rem;margin-left:auto">HTTP ${s.statusCode} · ${s.durationMs}ms</span>`:''}
          ${s.note?`<span style="font-size:0.7rem;color:var(--text-muted)">— ${escHtml(s.note)}</span>`:''}
        </summary>
        <div class="code-block json" style="margin:4px 0 0;max-height:200px">${escHtml(JSON.stringify(s.response||s.body||s.error||{},null,2))}</div>
      </details>`;
    }).join('');
  }

  // ── all token-producing steps: full JWT decode (same as standalone pages) ───
  else {
    const tokens = [
      r.outputs?.access_token  && ['access_token',  r.outputs.access_token],
      r.outputs?.id_token       && ['id_token',       r.outputs.id_token],
      r.outputs?.refresh_token  && ['refresh_token',  r.outputs.refresh_token],
    ].filter(Boolean);

    if (tokens.length) {
      // Tab strip when multiple tokens
      const tabId = 'rt_' + stepId;
      if (tokens.length > 1) {
        const tabs = tokens.map(([name],i) =>
          `<button class="tab-btn${i===0?' active':''}" onclick="document.querySelectorAll('.${tabId}').forEach((el,j)=>{el.style.display=j===${i}?'':'none';el.previousElementSibling?.classList.toggle('active',j===${i})});this.closest('.tabs-nav').querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));this.classList.add('active')">${escHtml(name)}</button>`
        ).join('');
        const panels = tokens.map(([name, token],i) =>
          `<button style="display:none"></button><div class="${tabId}" style="${i!==0?'display:none':''}">${renderJwtDecoded(token, name)}</div>`
        ).join('');
        html = `<div class="tabs-nav">${tabs}</div>${panels}`;
        // Fix: first tab panel always visible
        html = `<div class="tabs-nav">${tabs}</div>` + tokens.map(([name,token],i) =>
          `<div class="${tabId}" style="${i!==0?'display:none':''}">${renderJwtDecoded(token,name)}</div>`
        ).join('');
      } else {
        html = renderJwtDecoded(tokens[0][1], tokens[0][0]);
      }
    } else {
      html = `<div style="color:var(--text-muted);font-size:0.82rem">No token data available</div>`;
    }
  }

  // Error details
  if (r.error) {
    html += `<div class="code-block" style="color:var(--red);margin-top:12px">${escHtml(r.error)}</div>`;
  }

  document.getElementById('stepResultContent').innerHTML = html;

  // Wire up tab buttons if any
  const firstTab = document.querySelector(`#stepResultContent .tabs-nav .tab-btn`);
  if (firstTab) firstTab.click();

  document.getElementById('stepResultModal').style.display = 'flex';

  _stepModalKeyHandler = (e) => { if (e.key === 'Escape') closeStepModal(); };
  document.addEventListener('keydown', _stepModalKeyHandler);
}

function closeStepModal() {
  document.getElementById('stepResultModal').style.display = 'none';
  if (_stepModalKeyHandler) { document.removeEventListener('keydown', _stepModalKeyHandler); _stepModalKeyHandler = null; }
}

async function executeStep(step, inputs, domain, sid) {
  const c = step.config;
  const stepDomain = domain;
  const stepSid = sid;

  switch (step.type) {
    case 'auth-code':
      return await execAuthCode(step, stepDomain, stepSid);

    case 'client-creds': {
      const r = await fetch('/api/oauth/client-creds', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret, scope:(c.scope||'openid').split(/\s+/) })
      }).then(r=>r.json());
      const at = r.response?.access_token;
      return { success:r.success, outputs:{ access_token:at },
        durationMs:r.durationMs, summary:_tokenSummary(at),
        error:!r.success?(r.response?.error_description||`HTTP ${r.statusCode}`):null };
    }

    case 'token-exchange': {
      const r = await fetch('/api/token-exchange/exchange', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret,
          subjectToken:inputs.subject_token, subjectTokenType:'urn:ietf:params:oauth:token-type:access_token', scope:(c.scope||'openid').split(/\s+/) })
      }).then(r=>r.json());
      const at = r.response?.access_token;
      return { success:r.success, outputs:{ access_token:at, id_token:r.response?.id_token, refresh_token:r.response?.refresh_token },
        durationMs:r.durationMs, summary:_tokenSummary(at),
        error:!r.success?(r.response?.error_description||r.response?.error||`HTTP ${r.statusCode}`):null };
    }

    case 'token-inspect': {
      const token = inputs.token;
      if (!token) return { success:false, error:'No token provided — bind this step\'s input to a previous step\'s output' };
      const decoded = decodeJwt(token);
      if (!decoded) return { success:false, error:'Could not decode — not a valid JWT' };
      return { success:true, outputs:{}, decoded };
    }

    case 'token-revoke': {
      const token = inputs.token;
      if (!token) return { success:false, error:'No token provided' };
      const cid = c.clientId || G().clientId;
      const csec = c.clientSecret || G().clientSecret;
      const r = await fetch('/api/token/revoke-and-verify', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:cid, clientSecret:csec, token, tokenTypeHint:'access_token' })
      }).then(r=>r.json());
      return { success:r.revoked, outputs:{}, revoked:r.revoked,
        durationMs: r.steps?.reduce((t,s) => t+(s.durationMs||0), 0),
        error:!r.revoked?'Revoke sent but token may still be active (propagation)':null };
    }

    case 'pkjwt-token': {
      // Generate assertion from the stored private JWK, or use configAssertion
      let body = { oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, scope:(c.scope||'openid').split(/\s+/), grantType:'client_credentials' };
      if (c.privateJwk) {
        try {
          const kp = await fetch('/api/pkjwt/generate-assertion', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ privateJwk:JSON.parse(c.privateJwk), clientId:c.clientId,
              audience: (c.authServerId||stepSid) ? `https://${stepDomain}/oauth2/${c.authServerId||stepSid}/v1/token` : `https://${stepDomain}/oauth2/v1/token`,
              validitySeconds:300 })
          }).then(r=>r.json());
          body.clientAssertion = kp.assertion;
        } catch {}
      }
      const r = await fetch('/api/pkjwt/exchange-token', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) }).then(r=>r.json());
      const at = r.response?.access_token;
      return { success:r.success, outputs:{ access_token:at, refresh_token:r.response?.refresh_token },
        durationMs:r.durationMs, summary:_tokenSummary(at),
        error:!r.success?(r.response?.error_description||`HTTP ${r.statusCode}`):null };
    }

    case 'dpop-token': {
      const alg       = c.dpopAlg || 'ES256';
      const grantType = c.grantType || 'client_credentials';
      const kp = await fetch('/api/dpop/generate-keypair', {
        method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({alg})
      }).then(r=>r.json());
      const r = await fetch('/api/dpop/exchange-token', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          oktaDomain:stepDomain, authServerId:stepSid,
          clientId:c.clientId, clientSecret:c.clientSecret,
          scope:(c.scope||'openid').split(/\s+/),
          grantType,
          refreshToken: grantType === 'refresh_token' ? c.refreshToken : undefined,
          privateJwk:kp.privateJwk, publicJwk:kp.publicJwk
        })
      }).then(r=>r.json());
      const at = r.response?.access_token;
      const ms = r.steps?.filter(s=>s.type==='request').reduce((t,s)=>t+(s.durationMs||0),0);
      return { success:r.success,
        outputs:{ access_token:at, refresh_token:r.response?.refresh_token },
        durationMs:ms, summary:_tokenSummary(at),
        error:!r.success?(r.response?.error||`HTTP ${r.statusCode}`):null };
    }

    case 'ropc': {
      const r = await fetch('/api/oauth/ropc', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid,
          clientId:c.clientId, clientSecret:c.clientSecret,
          username:c.username, password:c.password,
          scope:(c.scope||'openid').split(/\s+/) })
      }).then(r=>r.json());
      const at = r.response?.access_token;
      return { success:r.success,
        outputs:{ access_token:at, id_token:r.response?.id_token, refresh_token:r.response?.refresh_token },
        durationMs:r.durationMs, summary:_tokenSummary(at),
        error:!r.success?(r.response?.error_description||r.response?.error||`HTTP ${r.statusCode}`):null };
    }

    case 'mfa-list-factors': {
      const adminToken = c.adminToken || G().adminApiToken || '';
      const login = inputs.user_id || c.userLogin;
      if (!login) return { success:false, error:'user_id input or userLogin config required', outputs:{} };
      const uRes = await fetch('/api/admin/find-user', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, adminApiToken:adminToken, login })
      }).then(r=>r.json());
      if (!uRes.success) return { success:false, error:`User not found: HTTP ${uRes.statusCode}`, outputs:{} };
      const userId = uRes.response.id;
      const fRes = await fetch('/api/admin/list-factors', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, adminApiToken:adminToken, userId })
      }).then(r=>r.json());
      const factors = fRes.response || [];
      const active  = factors.filter(f => f.status === 'ACTIVE');
      const summary = active.map(f => (f.factorType.split(':').pop() + '/' + f.status)).join(', ') || 'none enrolled';
      return { success:fRes.success, outputs:{ user_id:userId },
        factorCount:factors.length, summary:`${active.length} active: ${summary}`,
        error:!fRes.success?`HTTP ${fRes.statusCode}`:null };
    }

    case 'mfa-challenge': {
      const adminToken = c.adminToken || G().adminApiToken || '';
      const userId = inputs.user_id || c.userId;
      if (!userId) {
        // Try to find user by login if no user_id input
        if (!c.userLogin) return { success:false, error:'Bind user_id from a previous step or set userLogin in config', outputs:{} };
        const uRes = await fetch('/api/admin/find-user', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ oktaDomain:stepDomain, adminApiToken:adminToken, login:c.userLogin })
        }).then(r=>r.json());
        if (!uRes.success) return { success:false, error:`User not found`, outputs:{} };
        // Recurse with resolved userId — put it in inputs
        return await executeStep({ ...step, type:'mfa-challenge' }, { ...inputs, user_id: uRes.response.id }, stepDomain, sid);
      }
      // Get factors list to find one to challenge
      const fRes = await fetch('/api/admin/list-factors', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, adminApiToken:adminToken, userId })
      }).then(r=>r.json());
      const factors = (fRes.response || []).filter(f => f.status === 'ACTIVE');
      const SUPPORTED = ['push','email','token:software:sms','token:software:totp','token:hardware'];
      const target = c.factorType
        ? factors.find(f => f.factorType.includes(c.factorType))
        : factors.find(f => SUPPORTED.includes(f.factorType));
      if (!target) return { success:false, error:'No challengeable active factor found', outputs:{} };

      // Trigger challenge (push factors require polling)
      const cRes = await fetch('/api/admin/factor-challenge', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, adminApiToken:adminToken, userId, factorId:target.id })
      }).then(r=>r.json());

      if (target.factorType === 'push' && cRes.pollHref) {
        // Poll up to 60s
        for (let i=0; i<20; i++) {
          await new Promise(r=>setTimeout(r,3000));
          const p = await fetch('/api/admin/factor-poll', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ oktaDomain:stepDomain, adminApiToken:adminToken, pollHref:cRes.pollHref })
          }).then(r=>r.json());
          if (p.factorResult==='SUCCESS')  return { success:true, outputs:{ challenge_result:'approved' } };
          if (p.factorResult==='REJECTED') return { success:false, error:'Push rejected by user', outputs:{ challenge_result:'rejected' } };
          if (p.factorResult==='TIMEOUT')  return { success:false, error:'Push timed out', outputs:{ challenge_result:'timeout' } };
        }
        return { success:false, error:'Challenge timed out after 60s', outputs:{ challenge_result:'timeout' } };
      }
      return { success: cRes.success||false, outputs:{ challenge_result: cRes.factorResult||'unknown' }, error:!cRes.success?(cRes.error||`HTTP ${cRes.statusCode}`):null };
    }

    case 'step-up-auth':
      return await execAuthCode({ ...step, config: { ...c, acrValues: c.acrValues } }, stepDomain, sid);

    case 'ciba': {
      const authRes = await fetch('/api/ciba/backchannel-authorize', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret,
          loginHint:c.loginHint, bindingMessage:c.bindingMessage, scope:(c.scope||'openid').split(/\s+/) })
      }).then(r=>r.json());
      if (!authRes.success) return { success:false, error:authRes.response?.error_description||'CIBA authorize failed', outputs:{} };

      // Poll for result (up to 60s)
      const authReqId = authRes.response.auth_req_id;
      const interval  = (authRes.response.interval || 5) * 1000;
      const t0ciba = Date.now();
      for (let i=0; i < 12; i++) {
        await new Promise(r => setTimeout(r, interval));
        const poll = await fetch('/api/ciba/poll', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret, authReqId, scope:(c.scope||'openid').split(/\s+/) })
        }).then(r=>r.json());
        if (poll.success) {
          const at = poll.response?.access_token;
          return { success:true, outputs:{ access_token:at, id_token:poll.response?.id_token },
            durationMs: Date.now()-t0ciba, summary:_tokenSummary(at) };
        }
        if (poll.denied || poll.expired) return { success:false, error:poll.denied?'User denied':'Request expired', outputs:{} };
      }
      return { success:false, error:'CIBA timeout (60s)', outputs:{} };
    }

    default:
      return { success:false, error:`Unknown step type: ${step.type}` };
  }
}

async function execAuthCode(step, domain, sid) {
  const c = step.config;
  const redirectUri = c.redirectUri || 'http://localhost:3000/oauth/callback';

  const authMethod = c.clientAuthMethod || 'none';
  let privateJwk;
  if (authMethod === 'pkjwt' && c.privateJwk) {
    try { privateJwk = JSON.parse(c.privateJwk); } catch { /* ignore — will fail at backend */ }
  }

  const startRes = await fetch('/api/oauth/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      oktaDomain:domain, authServerId:sid, clientId:c.clientId,
      redirectUri, scope:(c.scope||'openid profile email').split(/\s+/),
      clientAuthMethod: authMethod,
      clientSecret: authMethod === 'basic' ? (c.clientSecret || '') : undefined,
      privateJwk:   authMethod === 'pkjwt' ? privateJwk : undefined,
      ...(c.acrValues ? { acrValues: c.acrValues } : {}),
    })
  }).then(r=>r.json());

  const { flowId, authUrl } = startRes;

  // Show a blocking modal inside the step card while waiting
  updateStepLog(step.id, 'Login popup open — please log in…');

  return new Promise((resolve) => {
    const popup = window.open(authUrl, 'okta-auth', 'width=600,height=700,left=200,top=100');

    let done = false;
    const finish = (tokens, error, durationMs) => {
      if (done) return; done = true;
      clearInterval(pollTimer);
      window.removeEventListener('message', msgHandler);
      if (tokens) resolve({ success:true,
        outputs:{ access_token:tokens.access_token, id_token:tokens.id_token, refresh_token:tokens.refresh_token },
        durationMs,
        summary: _tokenSummary(tokens.access_token) });
      else resolve({ success:false, error: error || 'Auth failed', outputs:{} });
    };

    const msgHandler = (e) => { if (e.data?.type==='oauth-callback') finish(e.data.tokens, e.data.error, e.data.durationMs); };
    window.addEventListener('message', msgHandler);

    const pollTimer = setInterval(async () => {
      const s = await fetch(`/api/oauth/status/${flowId}`).then(r=>r.json()).catch(()=>null);
      if (!s) return;
      if (s.status === 'success') finish(s.tokens, null, s.durationMs);
      if (s.status === 'error')   finish(null, s.error);
    }, 1500);

    // 3-minute timeout
    setTimeout(() => finish(null, 'Timeout waiting for user authentication (3 min)'), 180000);
  });
}

function updateStepLog(stepId, msg) {
  const card = document.getElementById(`card-${stepId}`);
  if (card) {
    let logEl = card.querySelector('.step-run-log');
    if (!logEl) { logEl = document.createElement('div'); logEl.className = 'step-run-log'; logEl.style.cssText='font-size:0.72rem;color:var(--text-muted);padding:4px 14px 8px'; card.appendChild(logEl); }
    logEl.textContent = msg;
  }
}

function addLog(num, label, ok, ms, error) {
  const el = document.getElementById('runLogEntries');
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `<span class="log-time">${new Date().toLocaleTimeString()}</span>
    <span class="log-step">Step ${num} (${escHtml(label)})</span>
    <span class="${ok?'log-ok':'log-err'}">${ok?`✓ ${ms}ms`:`✗ ${escHtml(error||'failed')} (${ms}ms)`}</span>`;
  el.appendChild(entry);
  el.scrollTop = el.scrollHeight;
}

// ─── Token popup ──────────────────────────────────────────────────────────────

function showTokenPopup(token) {
  const decoded = decodeJwt(token);
  if (!decoded) { copyRaw(token); toast('Not a JWT — copied raw value', 'info'); return; }

  let modal = document.getElementById('tokenModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'tokenModal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px';
    modal.onclick = (e) => { if (e.target===modal) modal.remove(); };
    document.body.appendChild(modal);
  }
  modal.innerHTML = `<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;max-width:600px;width:100%;max-height:80vh;overflow-y:auto">
    <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <span style="font-weight:600">Decoded JWT</span>
      <button class="btn btn-outline-secondary btn-sm" onclick="document.getElementById('tokenModal').remove()">✕</button>
    </div>
    <div style="padding:16px">${renderJwtDecoded(token)}</div>
  </div>`;
}
