'use strict';
/**
 * Universal navbar for all Okta OAuth Super Tester pages.
 * Loaded after common.js on every page. Auto-detects the current page,
 * replaces the existing <nav> with a consistent categorised dropdown navbar,
 * and wires the Save button to window._pageSave().
 *
 * Each page JS should set:
 *   window._pageSave  = () => savePageConfig(prefix, CONFIG_FIELDS)
 *   window._pageTitle = 'Page Name'   (optional — shown in mobile breadcrumb)
 */
(function () {

  const PAGES = {
    'auth-code':      { href:'/authcode.html',       cat:'grant', label:'Auth Code + PKCE',   desc:'Human login via popup' },
    'client-creds':   { href:'/client-creds.html',   cat:'grant', label:'Client Credentials', desc:'M2M service token' },
    'saml':           { href:'/',                    cat:'grant', label:'SAML 2.0 Bearer',    desc:'Exchange SAML assertion' },
    'dpop':           { href:'/dpop.html',           cat:'grant', label:'DPoP',               desc:'Sender-constrained tokens (RFC 9449)' },
    'pkjwt':          { href:'/pkjwt.html',          cat:'grant', label:'Private Key JWT',    desc:'Client auth — no secret needed' },
    'ciba':           { href:'/ciba.html',           cat:'grant', label:'CIBA',              desc:'Push to user device' },
    'token-exchange': { href:'/token-exchange.html', cat:'grant', label:'Token Exchange',    desc:'RFC 8693 cross-app delegation' },
    'ropc':           { href:'/ropc.html',           cat:'grant', label:'ROPC',              desc:'Resource Owner Password (legacy)' },
    'token-inspector':{ href:'/token-inspector.html',cat:'tools', label:'Token Inspector',   desc:'RFC-annotated claims + revoke' },
    'step-up':        { href:'/step-up.html',        cat:'tools', label:'Step-Up Auth',      desc:'acr_values MFA escalation' },
    'mfa':            { href:'/mfa.html',            cat:'admin', label:'MFA Manager',       desc:'List, challenge & reset factors' },
    'admin':          { href:'/admin.html',          cat:'admin', label:'Admin API',         desc:'Apps, audit, MFA, Terraform' },
    'workflow':       { href:'/workflow.html',       cat:'chain', label:'Test Chain',        desc:'Chain multiple tests' },
    'settings':       { href:'/settings.html',       cat:'other', label:'Settings',          desc:'Global config, auth & keys' },
    'home':           { href:'/home.html',           cat:'other', label:'Home',              desc:'All tools overview' },
  };

  function _esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  function currentPage() {
    const p = window.location.pathname;
    for (const [id, pg] of Object.entries(PAGES)) {
      if (p === pg.href || (pg.href === '/' && (p === '/' || p === '/index.html'))) return id;
    }
    return '';
  }

  function ddItem(id) {
    const pg = PAGES[id]; if (!pg) return '';
    const active = id === currentPage();
    return `<a href="${_esc(pg.href)}" class="nav-dd-item${active?' active':''}">
      <span class="nav-dd-name">${_esc(pg.label)}</span>
      <span class="nav-dd-desc">${_esc(pg.desc)}</span>
    </a>`;
  }

  function dropdown(key, icon, label, ids) {
    const hasActive = ids.includes(currentPage());
    return `<div class="nav-dd" id="ndd-${key}">
      <button class="nav-dd-btn${hasActive?' act':''}" onclick="_navDd('${key}')">
        ${icon} ${_esc(label)}<i class="bi bi-chevron-down nav-dd-chev"></i>
      </button>
      <div class="nav-dd-menu">${ids.map(ddItem).join('')}</div>
    </div>`;
  }

  function navHtml() {
    const cur = currentPage();
    return `
    <div class="nav-inner">
      <a href="/home.html" class="nav-brand">
        <i class="bi bi-lightning-charge-fill" style="color:var(--blue,#58a6ff)"></i>
        <span>Okta OAuth Super Tester</span>
      </a>
      <span class="nav-sep"></span>
      ${dropdown('grant','🔑','Grant Flows',['auth-code','client-creds','saml','dpop','pkjwt','ciba','token-exchange','ropc'])}
      ${dropdown('tools','🔍','Token Tools',['token-inspector','step-up'])}
      ${dropdown('admin','🛡️','MFA &amp; Admin',['mfa','admin'])}
      <a href="/workflow.html" class="nav-pill${cur==='workflow'?' act':''}">
        <i class="bi bi-diagram-3"></i> Test Chain
      </a>
      <div class="nav-right">
        <button class="nav-save" onclick="_navSave()" title="Save current page settings (Ctrl+S)">
          <i class="bi bi-floppy me-1"></i>Save
        </button>
        <a href="/settings.html" class="nav-pill nav-gear${cur==='settings'?' act':''}" title="Settings">
          <i class="bi bi-gear-fill"></i>
        </a>
        <div id="navAuthArea" style="display:flex;align-items:center"></div>
      </div>
    </div>`;
  }

  // ─── Global handlers ────────────────────────────────────────────────────────

  window._navDd = function(key) {
    const dd   = document.getElementById('ndd-' + key);
    const menu = dd?.querySelector('.nav-dd-menu');
    const btn  = dd?.querySelector('.nav-dd-btn');
    if (!menu) return;
    const open = menu.classList.contains('open');
    _closeAllDd();
    if (!open) { menu.classList.add('open'); btn?.classList.add('open'); }
  };

  function _closeAllDd() {
    document.querySelectorAll('.nav-dd-menu.open').forEach(m => m.classList.remove('open'));
    document.querySelectorAll('.nav-dd-btn.open').forEach(b => b.classList.remove('open'));
  }

  window._navSave = function() {
    if (typeof window._pageSave === 'function') {
      window._pageSave();
    } else if (typeof toast === 'function') {
      toast('Nothing to save on this page', 'info');
    }
  };

  // Ctrl+S shortcut
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); window._navSave(); }
  });

  // Close dropdowns on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.nav-dd')) _closeAllDd();
  });

  // ─── CSS ────────────────────────────────────────────────────────────────────

  const CSS = `
  .app-nav{background:var(--surface,#161b22);border-bottom:1px solid var(--border,#30363d);position:sticky;top:0;z-index:1000}
  .nav-inner{display:flex;align-items:center;gap:4px;padding:7px 14px;flex-wrap:nowrap;overflow-x:auto}
  .nav-inner::-webkit-scrollbar{height:0}
  .nav-brand{font-weight:700;font-size:0.95rem;color:var(--text,#c9d1d9);text-decoration:none;display:flex;align-items:center;gap:6px;white-space:nowrap;flex-shrink:0;margin-right:2px}
  .nav-brand:hover{color:var(--text,#c9d1d9)}
  .nav-sep{width:1px;height:18px;background:var(--border,#30363d);flex-shrink:0;margin:0 4px}

  /* Dropdown */
  .nav-dd{position:relative;flex-shrink:0}
  .nav-dd-btn{background:transparent;border:1px solid transparent;color:var(--text-muted,#8b949e);border-radius:6px;padding:4px 9px;font-size:0.775rem;cursor:pointer;display:flex;align-items:center;gap:4px;transition:all 0.12s;white-space:nowrap;font-family:inherit}
  .nav-dd-btn:hover,.nav-dd-btn.open{background:var(--surface2,#21262d);color:var(--text,#c9d1d9);border-color:var(--border,#30363d)}
  .nav-dd-btn.act{color:var(--blue,#58a6ff);background:rgba(88,166,255,0.08);border-color:rgba(88,166,255,0.25)}
  .nav-dd-chev{font-size:0.55rem;margin-left:2px;transition:transform 0.15s}
  .nav-dd-btn.open .nav-dd-chev{transform:rotate(180deg)}
  .nav-dd-menu{position:absolute;top:calc(100% + 5px);left:0;min-width:230px;background:var(--surface,#161b22);border:1px solid var(--border,#30363d);border-radius:9px;padding:5px;display:none;z-index:9999;box-shadow:0 10px 28px rgba(0,0,0,0.5)}
  .nav-dd-menu.open{display:block}
  .nav-dd-item{display:block;padding:6px 10px;border-radius:6px;text-decoration:none;color:var(--text,#c9d1d9);transition:background 0.1s}
  .nav-dd-item:hover{background:var(--surface2,#21262d)}
  .nav-dd-item.active{background:rgba(88,166,255,0.1);color:var(--blue,#58a6ff)}
  .nav-dd-name{display:block;font-size:0.78rem;font-weight:600;line-height:1.3}
  .nav-dd-desc{display:block;font-size:0.68rem;color:var(--text-muted,#8b949e);margin-top:1px}
  .nav-dd-item.active .nav-dd-desc{color:rgba(88,166,255,0.65)}

  /* Pills (direct links) */
  .nav-pill{background:transparent;border:1px solid transparent;color:var(--text-muted,#8b949e);border-radius:6px;padding:4px 9px;font-size:0.775rem;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:4px;transition:all 0.12s;white-space:nowrap;flex-shrink:0}
  .nav-pill:hover{background:var(--surface2,#21262d);color:var(--text,#c9d1d9);border-color:var(--border,#30363d)}
  .nav-pill.act{background:rgba(88,166,255,0.1);color:var(--blue,#58a6ff);border-color:rgba(88,166,255,0.25)}
  .nav-gear{padding:4px 8px}

  /* Right section */
  .nav-right{margin-left:auto;display:flex;align-items:center;gap:6px;flex-shrink:0;padding-left:8px}

  /* Save button */
  .nav-save{background:var(--blue,#58a6ff);border:none;color:#0d1117;font-weight:600;border-radius:6px;padding:4px 12px;font-size:0.775rem;cursor:pointer;white-space:nowrap;font-family:inherit;transition:background 0.12s}
  .nav-save:hover{background:#79b8ff}
  .nav-save:active{transform:scale(0.97)}
  `;

  // ─── Init ────────────────────────────────────────────────────────────────────

  // Inject styles immediately (before DOM ready)
  const s = document.createElement('style');
  s.textContent = CSS;
  (document.head || document.documentElement).appendChild(s);

  // Replace navbar on DOM ready
  function injectNav() {
    let nav = document.querySelector('nav.navbar, nav.app-nav, nav');
    if (!nav) {
      nav = document.createElement('nav');
      document.body.insertBefore(nav, document.body.firstChild);
    }
    nav.className = 'app-nav';
    nav.innerHTML = navHtml();
    // Trigger initNavAuth if available (populates navAuthArea)
    if (typeof initNavAuth === 'function') initNavAuth();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectNav);
  } else {
    injectNav();
  }

})();
