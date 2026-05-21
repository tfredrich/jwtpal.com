'use strict';

// ── PKCE ──────────────────────────────────────────────────────────────────────
let _pkce = { v:'', c:'', s:'', n:'' };

async function genPKCE() {
  const v = randB64u(32);
  const c = b64uEnc(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)));
  const s = randB64u(16), n = randB64u(16);
  _pkce = { v, c, s, n };
  const set = (id, val) => { const el = document.getElementById(id); el.textContent = val; el._rawText = val; };
  set('pv', v); set('pc', c); set('pst', s); set('pno', n);
  buildAuthURL(); buildTokenReq();
}

async function genFlowPKCE() { await genPKCE(); }

function buildAuthURL() {
  const ep = document.getElementById('fl-auth-ep').value;
  const cid = document.getElementById('fl-cid').value;
  const redir = document.getElementById('fl-redirect').value;
  const scope = document.getElementById('fl-scope').value;
  const { c, s, n } = _pkce;
  if (!c) { document.getElementById('fl-auth-url').textContent = 'Click "Generate PKCE + Build URL" first.'; return; }
  const params = [['response_type','code'],['client_id',cid],['redirect_uri',redir],['scope',scope],['state',s],['nonce',n],['code_challenge',c],['code_challenge_method','S256']];
  const full = `${ep}?${params.map(([k,v])=>`${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}`;
  const el = document.getElementById('fl-auth-url'); el._rawText = full;
  el.innerHTML = `<span class="ub">${esc(ep)}?</span>` + params.map(([k,v],i)=>`${i>0?'<span class="ub">&amp;</span>':''}<span class="ua">${esc(k)}</span>=<span class="uv">${esc(v)}</span>`).join('');
  buildTokenReq();
}

function buildTokenReq() {
  const ep = document.getElementById('fl-token-ep').value;
  const cid = document.getElementById('fl-cid').value;
  const redir = document.getElementById('fl-redirect').value;
  const code = document.getElementById('fl-code').value || '[authorization_code]';
  const { v } = _pkce;
  if (!v) { document.getElementById('fl-token-req').innerHTML = '<span class="text-muted">Generate PKCE params first.</span>'; return; }
  const bodyStr = Object.entries({ grant_type:'authorization_code', code, redirect_uri:redir, client_id:cid, code_verifier:v }).map(([k,v])=>`${k}=${encodeURIComponent(v)}`).join('&');
  const text = `POST ${ep}\nContent-Type: application/x-www-form-urlencoded\n\n${bodyStr}`;
  const el = document.getElementById('fl-token-req'); el._rawText = text; el.textContent = text;
}

Object.assign(window, {
  buildAuthURL,
  buildTokenReq,
  genFlowPKCE,
  genPKCE,
});
