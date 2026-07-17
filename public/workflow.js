'use strict';

// ─── Step Schema ──────────────────────────────────────────────────────────────

const STEP_DEFS = {
  'auth-code': {
    label:'Auth Code + PKCE', icon:'bi-person-badge', color:'var(--blue)',
    bg:'rgba(88,166,255,0.12)',
    inputs:[], outputs:['access_token','id_token','refresh_token'],
    configFields:[
      {k:'clientId',  label:'Client ID',     type:'text', ph:'0oa...'},
      {k:'scope',     label:'Scope',         type:'text', ph:'openid profile email'},
      {k:'redirectUri',label:'Redirect URI', type:'text', def:'http://localhost:3000/oauth/callback'},
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
    inputs:[], outputs:['access_token'],
    configFields:[
      {k:'clientId',    label:'Client ID',     type:'text'},
      {k:'clientSecret',label:'Client Secret', type:'password'},
      {k:'scope',       label:'Scope',         type:'text', ph:'openid'},
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

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initNavAuth();
  loadChain();

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
    const v = step.config[f.k] || '';
    return `<div class="step-config-row"><div style="flex:1">
      <div class="form-label">${escHtml(f.label)}</div>
      <input type="${f.type||'text'}" class="form-control form-control-sm" value="${escHtml(v)}" placeholder="${escHtml(f.ph||'')}"
        oninput="setConfig('${step.id}','${f.k}',this.value)">
    </div></div>`;
  }).join('');

  // Result display
  let resultHtml = '';
  if (step.result) {
    if (step.result.error) {
      resultHtml = `<div class="step-result" style="color:var(--red);font-size:0.78rem">✗ ${escHtml(step.result.error)}</div>`;
    } else if (step.result.outputs && Object.keys(step.result.outputs).length) {
      const rows = Object.entries(step.result.outputs)
        .filter(([,v]) => v)
        .map(([k,v]) => `<div class="result-output-row">
          <span class="result-key">${escHtml(k)}</span>
          <span class="result-val" title="${escHtml(v)}" onclick="showTokenPopup('${escHtml(v)}')">${escHtml(typeof v==='string'?v.slice(0,60)+(v.length>60?'…':''):String(v))}</span>
          <button class="btn btn-outline-secondary btn-sm" onclick="copyRaw('${escHtml(v)}')" title="Copy"><i class="bi bi-clipboard"></i></button>
        </div>`).join('');
      resultHtml = `<div class="step-result">${rows}</div>`;
    } else if (step.status === 'success') {
      resultHtml = `<div class="step-result" style="color:var(--green);font-size:0.78rem">✓ Completed</div>`;
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

async function runChain() {
  if (!chain.length) { toast('Add some steps first', 'warning'); return; }
  const btn = document.getElementById('runBtn');
  setLoading(btn, true, '<i class="bi bi-play-fill me-1"></i>Running…');
  outputStore = {};

  document.getElementById('runLog').style.display = '';
  document.getElementById('runLogEntries').innerHTML = '';

  // Reset all statuses
  chain.forEach(s => { s.status = 'idle'; s.result = null; });
  renderPipeline();

  const g = G();
  const domain = g.oktaDomain || '';
  const sid = g.authServerId || '';

  for (const step of chain) {
    step.status = 'running';
    renderStepCard_update(step);

    // Resolve inputs
    const inputs = {};
    for (const [iname, binding] of Object.entries(step.bindings || {})) {
      const key = `${binding.stepId}.${binding.outputName}`;
      inputs[iname] = outputStore[key];
    }

    const t0 = Date.now();
    try {
      const result = await executeStep(step, inputs, domain, sid);
      step.result = result;
      step.status = result.success ? 'success' : 'error';

      if (result.outputs) {
        Object.entries(result.outputs).forEach(([k, v]) => { if (v) outputStore[`${step.id}.${k}`] = v; });
      }

      addLog(chain.indexOf(step)+1, STEP_DEFS[step.type]?.label || step.type, result.success, Date.now()-t0, result.error);
    } catch (e) {
      step.result = { success: false, error: e.message, outputs: {} };
      step.status = 'error';
      addLog(chain.indexOf(step)+1, STEP_DEFS[step.type]?.label || step.type, false, Date.now()-t0, e.message);
      break; // stop chain on error
    }

    renderPipeline();
    await new Promise(r => setTimeout(r, 50)); // small UI refresh pause
  }

  setLoading(btn, false, '<i class="bi bi-play-fill me-1"></i>Run Chain');
}

function renderStepCard_update(step) {
  // Just re-render the full pipeline for simplicity
  renderPipeline();
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
      return { success:r.success, outputs:{ access_token:r.response?.access_token }, error:!r.success?(r.response?.error_description||`HTTP ${r.statusCode}`):null, raw:r };
    }

    case 'token-exchange': {
      const r = await fetch('/api/token-exchange/exchange', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret,
          subjectToken:inputs.subject_token, subjectTokenType:'urn:ietf:params:oauth:token-type:access_token', scope:(c.scope||'openid').split(/\s+/) })
      }).then(r=>r.json());
      return { success:r.success, outputs:{ access_token:r.response?.access_token, id_token:r.response?.id_token, refresh_token:r.response?.refresh_token }, error:!r.success?(r.response?.error_description||r.response?.error||`HTTP ${r.statusCode}`):null };
    }

    case 'token-inspect': {
      const token = inputs.token;
      if (!token) return { success:false, error:'No token provided — bind this step\'s input to a previous step\'s output' };
      const decoded = decodeJwt(token);
      return { success:!!decoded, outputs:{}, decoded, error:decoded?null:'Could not decode token' };
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
      return { success:r.revoked, outputs:{}, error:!r.revoked?'Token not revoked':null };
    }

    case 'pkjwt-token': {
      const r = await fetch('/api/pkjwt/exchange-token', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientAssertion:c.clientAssertion, scope:(c.scope||'openid').split(/\s+/), grantType:'client_credentials' })
      }).then(r=>r.json());
      return { success:r.success, outputs:{ access_token:r.response?.access_token }, error:!r.success?(r.response?.error_description||`HTTP ${r.statusCode}`):null };
    }

    case 'dpop-token': {
      const kp = await fetch('/api/dpop/generate-keypair',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alg:'ES256'})}).then(r=>r.json());
      const r = await fetch('/api/dpop/exchange-token', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret,
          scope:(c.scope||'openid').split(/\s+/), grantType:'client_credentials', privateJwk:kp.privateJwk, publicJwk:kp.publicJwk })
      }).then(r=>r.json());
      return { success:r.success, outputs:{ access_token:r.response?.access_token }, error:!r.success?(r.response?.error||`HTTP ${r.statusCode}`):null };
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
      const summary = factors.map(f => `${f.factorType}/${f.status}`).join(', ') || 'none';
      return { success:fRes.success, outputs:{ user_id:userId }, factorCount:factors.length, summary, error:!fRes.success?`HTTP ${fRes.statusCode}`:null };
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
      for (let i=0; i < 12; i++) {
        await new Promise(r => setTimeout(r, interval));
        const poll = await fetch('/api/ciba/poll', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ oktaDomain:stepDomain, authServerId:stepSid, clientId:c.clientId, clientSecret:c.clientSecret, authReqId, scope:(c.scope||'openid').split(/\s+/) })
        }).then(r=>r.json());
        if (poll.success) return { success:true, outputs:{ access_token:poll.response?.access_token, id_token:poll.response?.id_token }, raw:poll };
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

  const startRes = await fetch('/api/oauth/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ oktaDomain:domain, authServerId:sid, clientId:c.clientId,
      redirectUri, scope:(c.scope||'openid profile email').split(/\s+/) })
  }).then(r=>r.json());

  const { flowId, authUrl } = startRes;

  // Show a blocking modal inside the step card while waiting
  updateStepLog(step.id, 'Login popup open — please log in…');

  return new Promise((resolve) => {
    const popup = window.open(authUrl, 'okta-auth', 'width=600,height=700,left=200,top=100');

    let done = false;
    const finish = (tokens, error) => {
      if (done) return; done = true;
      clearInterval(pollTimer);
      window.removeEventListener('message', msgHandler);
      if (tokens) resolve({ success:true, outputs:{ access_token:tokens.access_token, id_token:tokens.id_token, refresh_token:tokens.refresh_token } });
      else resolve({ success:false, error: error || 'Auth failed', outputs:{} });
    };

    const msgHandler = (e) => { if (e.data?.type==='oauth-callback') finish(e.data.tokens, e.data.error); };
    window.addEventListener('message', msgHandler);

    const pollTimer = setInterval(async () => {
      const s = await fetch(`/api/oauth/status/${flowId}`).then(r=>r.json()).catch(()=>null);
      if (!s) return;
      if (s.status === 'success') finish(s.tokens, null);
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
