'use strict';

// ── THEME ────────────────────────────────────────────────────────────────────
let themeWasToggled = false;

function systemTheme() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function setTheme(mode) {
  const next = mode === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;

  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  const target = next === 'dark' ? 'light' : 'dark';
  toggle.setAttribute('aria-label', `Switch to ${target} mode`);
  toggle.title = `Switch to ${target} mode`;
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (!themeWasToggled) setTheme(systemTheme());
});


function b64uDec(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  try { return atob(s); } catch { return null; }
}
function b64uDecJSON(s) {
  const r = b64uDec(s); if (!r) return null;
  try { return JSON.parse(r); } catch { return null; }
}
function b64uEnc(buf) {
  const bytes = new Uint8Array(buf); let b = '';
  for (let i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]);
  return btoa(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function strToB64u(s) {
  return btoa(unescape(encodeURIComponent(s))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escAttr(s) { return esc(s).replace(/"/g,'&quot;'); }

function synHL(json) {
  if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
  return json.replace(/("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, m => {
    if (/^"/.test(m)) {
      if (/:$/.test(m)) return `<span class="jk">${esc(m.slice(0,-1))}</span>:`;
      return `<span class="jv">${esc(m)}</span>`;
    }
    if (/true|false/.test(m)) return `<span class="jb">${m}</span>`;
    if (/null/.test(m)) return `<span class="jz">${m}</span>`;
    return `<span class="jn">${m}</span>`;
  });
}

function colorJWT(token) {
  const p = token.split('.');
  if (p.length < 2) return esc(token);
  let o = `<span class="jh">${esc(p[0])}</span><span class="jd">.</span><span class="jp">${esc(p[1])}</span>`;
  if (p[2] !== undefined) o += `<span class="jd">.</span><span class="js">${esc(p[2])}</span>`;
  return o;
}

function tokenSpan(cls, raw, target, label) {
  const attrs = Object.entries({ target, label })
    .map(([k, v]) => `data-${k}="${escAttr(v)}"`)
    .join(' ');
  return `<span class="token-seg ${cls}" tabindex="0" role="button" title="${escAttr(label)}" ${attrs}>${esc(raw)}</span>`;
}

function colorJWTInspectable(token, targets = {}, prefix = 'JWT') {
  const p = token.split('.');
  if (p.length < 2) return esc(token);
  const target = {
    header: targets.header || 'decode-header-panel',
    payload: targets.payload || 'decode-payload-panel',
    signature: targets.signature || 'decode-signature-panel',
  };
  const sig = p[2] !== undefined ? p[2] : '';
  let out = tokenSpan('jh', p[0], target.header, `${prefix} header`);
  out += '<span class="jd">.</span>';
  out += tokenSpan('jp', p[1], target.payload, `${prefix} payload`);
  if (p[2] !== undefined) {
    out += '<span class="jd">.</span>';
    out += tokenSpan('js', sig, target.signature, `${prefix} signature`);
  }
  return out;
}

function colorSDInspectable(raw) {
  const parts = raw.split('~');
  const issuer = parts[0] || '';
  let out = colorJWTInspectable(issuer, {
    header: 'sd-issuer-panel',
    payload: 'sd-issuer-panel',
    signature: 'sd-issuer-panel',
  }, 'Issuer JWT');
  const tail = parts.slice(1).filter(Boolean);
  const kbJwt = tail.length && looksLikeJwt(tail[tail.length - 1]) ? tail.pop() : '';
  tail.forEach((d, idx) => {
    out += '<span class="jd">~</span>';
    out += tokenSpan('sd-disc-token', d, `sd-disc-item-${idx}`, `Disclosure ${idx + 1}`);
  });
  if (kbJwt) {
    out += '<span class="jd">~</span>';
    out += tokenSpan('sd-kb-token', kbJwt, 'sd-kb-panel', 'Holder Binding JWT');
  }
  if (raw.endsWith('~')) out += '<span class="jd">~</span>';
  return out;
}

function highlightTokenTarget(seg) {
  const target = document.getElementById(seg.dataset.target);
  if (!target) return;
  document.querySelectorAll('.token-seg.active').forEach(s => s.classList.remove('active'));
  seg.classList.add('active');
  target.classList.remove('target-flash');
  const rect = target.getBoundingClientRect();
  const viewportPad = 72;
  if (rect.top < viewportPad || rect.bottom > window.innerHeight) {
    window.scrollTo({
      top: Math.max(0, rect.top + window.scrollY - viewportPad),
      behavior: 'smooth'
    });
  }
  void target.offsetWidth;
  target.classList.add('target-flash');
}

document.addEventListener('click', e => {
  const seg = e.target.closest('.token-seg');
  if (seg) highlightTokenTarget(seg);
});
document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.classList?.contains('token-seg')) {
    e.preventDefault();
    highlightTokenTarget(e.target);
  }
});

function fmtTime(ts) {
  if (!ts || isNaN(ts)) return null;
  return new Date(ts * 1000).toLocaleString();
}

const copyFeedbackTimers = new WeakMap();

function showCopyFeedback(btn, ok) {
  if (!btn) return;
  if (!btn.dataset.defaultLabel) btn.dataset.defaultLabel = btn.textContent.trim() || 'Copy';
  clearTimeout(copyFeedbackTimers.get(btn));
  btn.classList.remove('copied', 'failed');
  btn.classList.add(ok ? 'copied' : 'failed');
  btn.textContent = ok ? '✓ Copied' : 'Copy failed';
  const timer = setTimeout(() => {
    btn.classList.remove('copied', 'failed');
    btn.textContent = btn.dataset.defaultLabel;
  }, 1500);
  copyFeedbackTimers.set(btn, timer);
}

async function clip(text) {
  try {
    await navigator.clipboard.writeText(text || '');
    return true;
  } catch {
    return false;
  }
}
async function copyField(id, btn) {
  const el = document.getElementById(id); if (!el) return;
  const ok = await clip(el._rawText || el.value || el.textContent || el.innerText);
  showCopyFeedback(btn, ok);
}
async function copyMono(id) {
  const el = document.getElementById(id); if (!el) return;
  await clip(el._rawText || el.textContent || el.innerText);
}

function switchSub(group, tab, btn) {
  document.querySelectorAll(`#view-${group} .sub-tab`).forEach(b => b.classList.remove('active'));
  document.querySelectorAll(`#view-${group} .sub-view`).forEach(v => v.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(`${group}-${tab}`).classList.add('active');
}

document.querySelectorAll('.nav-tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.main > .view').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById(`view-${t.dataset.view}`).classList.add('active');
  });
});

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const stampEl = document.getElementById('version-stamp');
  if (stampEl && window.JWT_PAL_VERSION) {
    stampEl.textContent = window.JWT_PAL_VERSION;
  }

  // Theme
  setTheme(systemTheme());
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    themeWasToggled = true;
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  // URL pre-load: ?jwt=<token> or ?token=<token> (legacy compat)
  const _qs = new URLSearchParams(window.location.search);
  const _preload = (_qs.get('jwt') || _qs.get('token') || '').trim();
  if (_preload) {
    if (_preload.includes('~')) {
      // SD-JWT — switch to SD-JWT › Decode tab
      document.querySelectorAll('.nav-tab').forEach(x => x.classList.remove('active'));
      document.querySelectorAll('.main > .view').forEach(x => x.classList.remove('active'));
      document.querySelector('.nav-tab[data-view="sdjwt"]').classList.add('active');
      document.getElementById('view-sdjwt').classList.add('active');
      document.getElementById('sd-input').value = _preload;
      decodeSD(_preload);
    } else {
      // JWT — JWT › Decode tab is already active by default
      document.getElementById('decode-input').value = _preload;
      decodeJWT(_preload);
    }
  }

  runEncode();
  renderSDRows();
  buildSD();
  await genPKCE();
});

Object.assign(window, {
  copyField,
  copyMono,
  switchSub,
});
