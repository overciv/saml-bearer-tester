'use strict';
/**
 * Universal navbar — uses Bootstrap 5 dropdowns (already on every page).
 * Auto-detects current page, injects consistent categorised nav.
 * Each page sets: window._pageSave = () => savePageConfig(prefix, fields)
 */
(function () {

  const PAGES = {
    'auth-code':      { href:'/authcode.html',       cat:'grant', label:'Auth Code + PKCE',   desc:'Human login via popup' },
    'client-creds':   { href:'/client-creds.html',   cat:'grant', label:'Client Credentials', desc:'M2M service token' },
    'saml':           { href:'/index.html',          cat:'grant', label:'SAML 2.0 Bearer',    desc:'Exchange SAML assertion' },
    'dpop':           { href:'/dpop.html',           cat:'grant', label:'DPoP',               desc:'Sender-constrained tokens (RFC 9449)' },
    'pkjwt':          { href:'/pkjwt.html',          cat:'grant', label:'Private Key JWT',    desc:'Client auth without secret' },
    'ciba':           { href:'/ciba.html',           cat:'grant', label:'CIBA',              desc:'Push to user device' },
    'token-exchange': { href:'/token-exchange.html', cat:'grant', label:'Token Exchange',    desc:'RFC 8693 cross-app delegation' },
    'ropc':           { href:'/ropc.html',           cat:'grant', label:'ROPC',              desc:'Resource Owner Password (legacy)' },
    'token-inspector':{ href:'/token-inspector.html',cat:'tools', label:'Token Inspector',   desc:'RFC claims + revoke + lifetime' },
    'step-up':        { href:'/step-up.html',        cat:'tools', label:'Step-Up Auth',      desc:'acr_values MFA escalation' },
    'mfa':            { href:'/mfa.html',            cat:'admin', label:'MFA Manager',       desc:'List, challenge & reset factors' },
    'admin':          { href:'/admin.html',          cat:'admin', label:'Admin API',         desc:'Apps, audit, MFA, Terraform' },
    'workflow':       { href:'/workflow.html',       cat:'chain', label:'Test Chain',        desc:'Chain multiple tests' },
    'settings':       { href:'/settings.html',       cat:'other', label:'Settings',          desc:'Global config, auth & keys' },
    'home':           { href:'/home.html',           cat:'other', label:'Home',              desc:'All tools overview' },
  };

  function esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function current() {
    const p = window.location.pathname;
    for (const [id, pg] of Object.entries(PAGES)) {
      if (p === pg.href || (pg.href === '/index.html' && (p === '/' || p === '/index.html'))) return id;
    }
    return '';
  }

  function ddItem(id) {
    const pg = PAGES[id]; if (!pg) return '';
    const active = id === current();
    return `<li><a href="${esc(pg.href)}" class="dropdown-item nav-item${active ? ' active' : ''}">
      <span class="nav-item-name">${esc(pg.label)}</span>
      <span class="nav-item-desc">${esc(pg.desc)}</span>
    </a></li>`;
  }

  function dropdown(key, icon, label, ids) {
    const hasActive = ids.includes(current());
    return `<div class="dropdown">
      <button class="nav-pill${hasActive ? ' act' : ''} dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
        ${icon} ${esc(label)}
      </button>
      <ul class="dropdown-menu nav-dd">
        ${ids.map(ddItem).join('')}
      </ul>
    </div>`;
  }

  function buildNav() {
    const cur = current();
    return `<div class="nav-inner">
      <a href="/home.html" class="nav-brand">
        <i class="bi bi-lightning-charge-fill" style="color:var(--blue,#58a6ff)"></i>
        <span>Okta OAuth Super Tester</span>
      </a>
      <span class="nav-sep"></span>
      ${dropdown('grant', '🔑', 'Grant Flows',  ['auth-code','client-creds','saml','dpop','pkjwt','ciba','token-exchange','ropc'])}
      ${dropdown('tools', '🔍', 'Token Tools',  ['token-inspector','step-up'])}
      ${dropdown('admin', '🛡️', 'MFA & Admin', ['mfa','admin'])}
      <a href="/workflow.html" class="nav-pill${cur === 'workflow' ? ' act' : ''}">
        <i class="bi bi-diagram-3"></i> Test Chain
      </a>
      <div class="nav-right">
        <button class="nav-save" id="navSaveBtn" title="Save current page settings (Ctrl+S)">
          <i class="bi bi-floppy me-1"></i>Save
        </button>
        <a href="/settings.html" class="nav-pill nav-gear${cur === 'settings' ? ' act' : ''}" title="Settings">
          <i class="bi bi-gear-fill"></i>
        </a>
        <div id="navAuthArea" style="display:flex;align-items:center"></div>
      </div>
    </div>`;
  }

  // ─── CSS ──────────────────────────────────────────────────────────────────────

  const CSS = `
.app-nav{background:var(--surface,#161b22);border-bottom:1px solid var(--border,#30363d);position:sticky;top:0;z-index:1020;overflow:visible}
.nav-inner{display:flex;align-items:center;gap:4px;padding:7px 14px;overflow:visible;flex-wrap:wrap}
.nav-brand{font-weight:700;font-size:0.95rem;color:var(--text,#c9d1d9)!important;text-decoration:none;display:flex;align-items:center;gap:6px;white-space:nowrap;flex-shrink:0;margin-right:2px}
.nav-sep{width:1px;height:18px;background:var(--border,#30363d);flex-shrink:0;margin:0 4px}

/* Pills (nav buttons) */
.nav-pill{background:transparent;border:1px solid transparent;color:var(--text-muted,#8b949e);border-radius:6px;padding:4px 9px;font-size:0.775rem;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:4px;white-space:nowrap;flex-shrink:0;font-family:inherit;transition:all 0.12s}
.nav-pill:hover{background:var(--surface2,#21262d);color:var(--text,#c9d1d9)!important;border-color:var(--border,#30363d)}
.nav-pill.act{background:rgba(88,166,255,0.1);color:var(--blue,#58a6ff)!important;border-color:rgba(88,166,255,0.25)}
.nav-pill.dropdown-toggle::after{display:none}
.nav-gear{padding:4px 8px}

/* Dropdown menu */
.nav-dd{background:var(--surface,#161b22)!important;border:1px solid var(--border,#30363d)!important;border-radius:9px!important;padding:5px!important;min-width:230px;box-shadow:0 10px 28px rgba(0,0,0,0.5)!important;margin-top:4px!important}
.nav-item{border-radius:6px!important;padding:6px 10px!important;color:var(--text,#c9d1d9)!important;display:block}
.nav-item:hover{background:var(--surface2,#21262d)!important;color:var(--text,#c9d1d9)!important}
.nav-item.active{background:rgba(88,166,255,0.1)!important;color:var(--blue,#58a6ff)!important}
.nav-item-name{display:block;font-size:0.79rem;font-weight:600;line-height:1.3}
.nav-item-desc{display:block;font-size:0.68rem;color:var(--text-muted,#8b949e);margin-top:1px}
.nav-item.active .nav-item-desc{color:rgba(88,166,255,0.65)}

/* Right section */
.nav-right{margin-left:auto;display:flex;align-items:center;gap:6px;flex-shrink:0;padding-left:8px}
.nav-save{background:var(--blue,#58a6ff);border:none;color:#0d1117;font-weight:600;border-radius:6px;padding:4px 12px;font-size:0.775rem;cursor:pointer;white-space:nowrap;font-family:inherit;transition:background 0.12s}
.nav-save:hover{background:#79b8ff}
.nav-save:active{transform:scale(0.97)}
`;

  // ─── Init ──────────────────────────────────────────────────────────────────────

  // Inject CSS immediately
  const styleEl = document.createElement('style');
  styleEl.textContent = CSS;
  (document.head || document.documentElement).appendChild(styleEl);

  function injectNav() {
    // Find or create the top-level <nav>
    let nav = document.querySelector('nav.navbar, nav.app-nav, nav');
    if (!nav) {
      nav = document.createElement('nav');
      document.body.insertBefore(nav, document.body.firstChild);
    }
    nav.className  = 'app-nav';
    nav.removeAttribute('style'); // strip old inline styles
    nav.innerHTML  = buildNav();

    // Wire Save button (after injection so the element exists)
    const saveBtn = nav.querySelector('#navSaveBtn');
    if (saveBtn) {
      saveBtn.addEventListener('click', () => {
        if (typeof window._pageSave === 'function') window._pageSave();
        else if (typeof toast === 'function') toast('Nothing to save on this page', 'info');
      });
    }

    // Populate auth area
    if (typeof initNavAuth === 'function') initNavAuth();
  }

  // Ctrl/Cmd+S
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      if (typeof window._pageSave === 'function') window._pageSave();
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectNav);
  } else {
    injectNav();
  }

})();
