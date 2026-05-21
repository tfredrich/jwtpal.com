'use strict';

// ── CLAIM COMPLIANCE ──────────────────────────────────────────────────────────
const CLAIM_SPECS = {
  'bearer-jwt': {
    label: 'Bearer JWT',
    spec: 'RFC 7519',
    claims: [
      { claim: 'iss', level: 'optional',     desc: 'Issuer',              ref: 'RFC 7519 §4.1.1' },
      { claim: 'sub', level: 'optional',     desc: 'Subject',             ref: 'RFC 7519 §4.1.2' },
      { claim: 'aud', level: 'optional',     desc: 'Audience',            ref: 'RFC 7519 §4.1.3' },
      { claim: 'exp', level: 'optional',     desc: 'Expiration time',     ref: 'RFC 7519 §4.1.4' },
      { claim: 'nbf', level: 'optional',     desc: 'Not before',          ref: 'RFC 7519 §4.1.5' },
      { claim: 'iat', level: 'optional',     desc: 'Issued at',           ref: 'RFC 7519 §4.1.6' },
      { claim: 'jti', level: 'optional',     desc: 'JWT ID (unique ID)',  ref: 'RFC 7519 §4.1.7' },
    ]
  },
  'access-token': {
    label: 'Access Token',
    spec: 'RFC 9068',
    claims: [
      { claim: 'iss',       level: 'required',     desc: 'Issuer',                      ref: 'RFC 9068 §2.2' },
      { claim: 'exp',       level: 'required',     desc: 'Expiration time',             ref: 'RFC 9068 §2.2' },
      { claim: 'aud',       level: 'required',     desc: 'Audience',                    ref: 'RFC 9068 §2.2' },
      { claim: 'sub',       level: 'required',     desc: 'Subject',                     ref: 'RFC 9068 §2.2' },
      { claim: 'client_id', level: 'required',     desc: 'Client identifier',           ref: 'RFC 9068 §2.2' },
      { claim: 'iat',       level: 'required',     desc: 'Issued at',                   ref: 'RFC 9068 §2.2' },
      { claim: 'jti',       level: 'required',     desc: 'JWT ID (unique per token)',   ref: 'RFC 9068 §2.2' },
      { claim: 'nbf',       level: 'optional',     desc: 'Not before',                  ref: 'RFC 9068 §2.2' },
      { claim: 'scope',     level: 'optional',     desc: 'Scope',                       ref: 'RFC 9068 §2.2' },
      { claim: 'auth_time', level: 'optional',     desc: 'Authentication time',         ref: 'RFC 9068 §2.2' },
      { claim: 'acr',       level: 'optional',     desc: 'Auth context class ref',      ref: 'RFC 9068 §2.2' },
      { claim: 'amr',       level: 'optional',     desc: 'Auth methods references',     ref: 'RFC 9068 §2.2' },
      { claim: 'groups',    level: 'optional',     desc: 'Groups',                      ref: 'RFC 9068 §2.2' },
      { claim: 'roles',     level: 'optional',     desc: 'Roles',                       ref: 'RFC 9068 §2.2' },
    ]
  },
  'id-token': {
    label: 'ID Token',
    spec: 'OIDC Core',
    claims: [
      { claim: 'iss',       level: 'required',     desc: 'Issuer',                            ref: 'OIDC Core §2' },
      { claim: 'sub',       level: 'required',     desc: 'Subject',                           ref: 'OIDC Core §2' },
      { claim: 'aud',       level: 'required',     desc: 'Audience',                          ref: 'OIDC Core §2' },
      { claim: 'exp',       level: 'required',     desc: 'Expiration time',                   ref: 'OIDC Core §2' },
      { claim: 'iat',       level: 'required',     desc: 'Issued at',                         ref: 'OIDC Core §2' },
      { claim: 'nonce',     level: 'conditional',  desc: 'Required if sent in auth request',  ref: 'OIDC Core §2' },
      { claim: 'at_hash',   level: 'conditional',  desc: 'Required when issuing access token',ref: 'OIDC Core §3.1.3.6' },
      { claim: 'c_hash',    level: 'conditional',  desc: 'Required when issuing auth code',   ref: 'OIDC Core §3.3.2.11' },
      { claim: 'auth_time', level: 'recommended',  desc: 'Authentication time',               ref: 'OIDC Core §2' },
      { claim: 'acr',       level: 'recommended',  desc: 'Auth context class reference',      ref: 'OIDC Core §2' },
      { claim: 'amr',       level: 'recommended',  desc: 'Auth methods references',           ref: 'OIDC Core §2' },
      { claim: 'azp',       level: 'optional',     desc: 'Authorized party',                  ref: 'OIDC Core §2' },
    ]
  }
};

const LEVEL_ORDER = ['required', 'conditional', 'recommended', 'optional'];
const LEVEL_LABELS = { required: 'Required', conditional: 'Conditional', recommended: 'Recommended', optional: 'Optional' };

let _complianceType = 'bearer-jwt';
let _complianceManual = false;
let _compliancePay = null;

function detectTokenType(hdr, pay) {
  if (!pay) return 'bearer-jwt';
  const typ = (hdr && hdr.typ || '').toLowerCase();
  if (typ === 'at+jwt' || typ === 'application/at+jwt') return 'access-token';
  if (pay.nonce !== undefined || pay.at_hash !== undefined || pay.c_hash !== undefined) return 'id-token';
  if (pay.client_id !== undefined) return 'access-token';
  return 'bearer-jwt';
}

function setComplianceType(type, manual) {
  _complianceManual = !!manual;
  _complianceType = type;
  document.querySelectorAll('#compliance-type-ctrl .seg-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.type === type);
  });
  renderCompliance(_compliancePay);
}

function renderCompliance(pay) {
  _compliancePay = pay;
  const panel = document.getElementById('decode-compliance-panel');
  const body = document.getElementById('compliance-body');
  if (!pay) { panel.style.display = 'none'; return; }
  panel.style.display = 'block';

  const spec = CLAIM_SPECS[_complianceType];
  const present = new Set(Object.keys(pay));
  const missing = spec.claims.filter(c => !present.has(c.claim));

  if (!missing.length) {
    body.innerHTML = `<p class="comp-empty">✓ All ${spec.spec} registered claims are present.</p>`;
    return;
  }

  const byLevel = {};
  for (const c of missing) {
    (byLevel[c.level] = byLevel[c.level] || []).push(c);
  }

  body.innerHTML = LEVEL_ORDER.filter(l => byLevel[l]).map(level => {
    const rows = byLevel[level].map(c => `
      <div class="comp-row">
        <span class="comp-claim">${esc(c.claim)}</span>
        <span class="comp-desc">${esc(c.desc)}</span>
        <span class="comp-ref">${esc(c.ref)}</span>
        <span class="badge badge-${level}">${LEVEL_LABELS[level]}</span>
      </div>`).join('');
    return `<div class="comp-group"><div class="comp-group-hd">${LEVEL_LABELS[level]}</div>${rows}</div>`;
  }).join('');
}

function weakAlgorithmWarning(alg) {
  if (alg === 'none') {
    return {
      className: 'algo-warn-none',
      text: '⚠ Unsafe — alg: none produces unsigned tokens. Any recipient that accepts this will accept a forged token.'
    };
  }
  if (/^HS\d+$/i.test(alg || '')) {
    return {
      className: 'algo-warn-sym',
      text: '⚠ Symmetric — the same secret is used to sign and verify. Prefer RS256 or ES256 when the verifier and issuer are separate parties.'
    };
  }
  return null;
}

function renderWeakAlgorithmWarning(targetId, alg) {
  const warn = document.getElementById(targetId);
  const warning = weakAlgorithmWarning(alg);
  if (!warning) {
    warn.style.display = 'none';
    warn.className = 'algo-warn-strip';
    warn.textContent = '';
    return;
  }
  warn.className = `algo-warn-strip ${warning.className}`;
  warn.textContent = warning.text;
  warn.style.display = 'block';
}

// ── DECODE ────────────────────────────────────────────────────────────────────
let _dtok = '', _dhdr = null;

function loadDecodeExample() {
  const ex = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqd3RwYWwuY29tIiwiaWF0IjoxNjA0NDQ1NDM1LCJleHAiOjE2MzU5ODE0MzUsImF1ZCI6Ind3dy5uZXZlcmxhbmQub3JnIiwic3ViIjoicHBhbkBuZXZlcmxhbmQub3JnIiwiR2l2ZW5OYW1lIjoiUGV0ZXIiLCJTdXJuYW1lIjoiUGFuIiwiRW1haWwiOiJwcGFuQG5ldmVybGFuZC5vcmcifQ.twV78VhAbatpW5z68Y7jcHHF5QZIP2KHAL88mzZh6uM';
  document.getElementById('decode-input').value = ex;
  decodeJWT(ex);
}

function clearDecode() {
  const input = document.getElementById('decode-input');
  input.value = '';
  document.getElementById('decode-colored').innerHTML = '<span class="text-muted text-sm">Paste a token above.</span>';
  document.getElementById('decode-header').innerHTML = '<span class="text-muted">—</span>';
  document.getElementById('decode-payload').innerHTML = '<span class="text-muted">—</span>';
  document.getElementById('decode-timing').style.display = 'none';
  document.getElementById('hdr-badge').style.display = 'none';
  renderWeakAlgorithmWarning('decode-algo-warn', null);
  document.getElementById('sig-badge').className = 'badge badge-dim';
  document.getElementById('sig-badge').textContent = 'not verified';
  document.getElementById('sig-alg').textContent = '—';
  document.getElementById('verify-result').innerHTML = '';
  document.getElementById('decode-compliance-panel').style.display = 'none';
  _dtok = ''; _dhdr = null; _compliancePay = null; _complianceManual = false;
  input.focus();
}

function decodeJWT(raw) {
  raw = (raw || '').trim(); _dtok = raw;
  if (!raw) { clearDecode(); return; }
  document.getElementById('decode-colored').innerHTML = colorJWTInspectable(raw);
  const parts = raw.split('.');
  if (parts.length < 2) {
    document.getElementById('decode-header').innerHTML = '<span style="color:var(--danger);">Need at least 2 parts (header.payload)</span>';
    renderWeakAlgorithmWarning('decode-algo-warn', null);
    return;
  }
  const hdr = b64uDecJSON(parts[0]); _dhdr = hdr;
  if (hdr) {
    document.getElementById('decode-header').innerHTML = synHL(JSON.stringify(hdr, null, 2));
    document.getElementById('hdr-badge').style.display = 'inline-flex';
    document.getElementById('sig-alg').textContent = hdr.alg || 'none';
    renderWeakAlgorithmWarning('decode-algo-warn', hdr.alg);
  } else {
    document.getElementById('decode-header').innerHTML = '<span style="color:var(--danger);">Could not decode header</span>';
    renderWeakAlgorithmWarning('decode-algo-warn', null);
  }
  const pay = b64uDecJSON(parts[1]);
  if (pay) {
    document.getElementById('decode-payload').innerHTML = synHL(JSON.stringify(pay, null, 2));
    const rows = [];
    if (pay.iat) rows.push(`<span>iat &nbsp;</span>${fmtTime(pay.iat)}`);
    if (pay.exp) {
      const expired = Date.now()/1000 > pay.exp;
      rows.push(`<span>exp &nbsp;</span>${fmtTime(pay.exp)} <span class="badge ${expired?'badge-err':'badge-ok'}" style="margin-left:6px;">${expired?'expired':'valid'}</span>`);
    }
    if (pay.nbf) rows.push(`<span>nbf &nbsp;</span>${fmtTime(pay.nbf)}`);
    const td = document.getElementById('decode-timing');
    if (rows.length) { td.style.display = 'flex'; td.innerHTML = rows.map(r=>`<div>${r}</div>`).join(''); }
    else td.style.display = 'none';
    if (!_complianceManual) {
      const detected = detectTokenType(hdr, pay);
      setComplianceType(detected, false);
    }
    renderCompliance(pay);
  } else {
    document.getElementById('decode-payload').innerHTML = '<span style="color:var(--danger);">Could not decode payload</span>';
    renderCompliance(null);
  }
  if (parts.length < 3 || !parts[2]) {
    document.getElementById('sig-badge').className = 'badge badge-warn';
    document.getElementById('sig-badge').textContent = 'alg: none';
  } else {
    document.getElementById('sig-badge').className = 'badge badge-dim';
    document.getElementById('sig-badge').textContent = 'not verified';
  }
  verifySignature();
}

async function verifySignature() {
  const secret = document.getElementById('verify-secret').value.trim();
  const badge = document.getElementById('sig-badge');
  const result = document.getElementById('verify-result');
  if (!_dtok || !secret) { result.innerHTML = ''; return; }
  const parts = _dtok.split('.');
  if (parts.length !== 3) return;
  const alg = _dhdr && _dhdr.alg;
  if (!alg || alg === 'none') return;
  try {
    const enc = new TextEncoder();
    const msgBuf = enc.encode(`${parts[0]}.${parts[1]}`);
    const sigBuf = Uint8Array.from(atob(parts[2].replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    if (alg.startsWith('HS')) {
      const hashMap = { HS256:'SHA-256', HS384:'SHA-384', HS512:'SHA-512' };
      const hash = hashMap[alg]; if (!hash) return;
      const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name:'HMAC', hash }, false, ['verify']);
      const ok = await crypto.subtle.verify('HMAC', key, sigBuf, msgBuf);
      badge.className = ok ? 'badge badge-ok' : 'badge badge-err';
      badge.textContent = ok ? 'valid ✓' : 'invalid ✗';
      result.innerHTML = ok ? '<span class="badge badge-ok">Signature verified</span>' : '<span class="badge badge-err">Signature mismatch</span>';
    } else if (alg.startsWith('RS') || alg.startsWith('ES')) {
      if (!secret.startsWith('-----BEGIN')) { result.innerHTML = '<span class="text-sm text-muted">Paste a PEM public key for RS*/ES* verification.</span>'; return; }
      const der = Uint8Array.from(atob(secret.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')), c => c.charCodeAt(0));
      const algMap = {
        RS256:{ name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, RS384:{ name:'RSASSA-PKCS1-v1_5', hash:'SHA-384' }, RS512:{ name:'RSASSA-PKCS1-v1_5', hash:'SHA-512' },
        ES256:{ name:'ECDSA', namedCurve:'P-256', hash:'SHA-256' }, ES384:{ name:'ECDSA', namedCurve:'P-384', hash:'SHA-384' },
      };
      const ka = algMap[alg];
      if (!ka) { result.innerHTML = `<span class="text-sm text-muted">${alg} not supported for verify.</span>`; return; }
      const pubKey = await crypto.subtle.importKey('spki', der, ka, false, ['verify']);
      const ok = await crypto.subtle.verify(alg.startsWith('ES') ? { name:'ECDSA', hash:ka.hash } : ka.name, pubKey, sigBuf, msgBuf);
      badge.className = ok ? 'badge badge-ok' : 'badge badge-err';
      badge.textContent = ok ? 'valid ✓' : 'invalid ✗';
      result.innerHTML = ok ? '<span class="badge badge-ok">Signature verified</span>' : '<span class="badge badge-err">Signature mismatch</span>';
    }
  } catch(e) { result.innerHTML = `<span class="text-sm text-muted">Error: ${esc(e.message)}</span>`; }
}

// ── ENCODE ────────────────────────────────────────────────────────────────────
let _encAlg = 'HS256', _encTok = '';

function setAlgo(alg) {
  _encAlg = alg;
  document.querySelectorAll('.algo-pill').forEach(p => p.classList.toggle('active', p.dataset.alg === alg));
  const isHmac = alg.startsWith('HS');
  const isAsym = alg.startsWith('RS') || alg.startsWith('ES');
  document.getElementById('enc-secret-wrap').style.display = isHmac ? 'block' : 'none';
  document.getElementById('enc-pem-wrap').style.display = isAsym ? 'block' : 'none';
  renderWeakAlgorithmWarning('algo-warn', alg);
  try { const h = JSON.parse(document.getElementById('enc-header').value); h.alg = alg; document.getElementById('enc-header').value = JSON.stringify(h, null, 2); } catch {}
  runEncode();
}

async function runEncode() {
  const hRaw = document.getElementById('enc-header').value;
  const pRaw = document.getElementById('enc-payload').value;
  const errEl = document.getElementById('enc-err');
  const outEl = document.getElementById('enc-output');
  errEl.style.display = 'none';
  let hdr, pay;
  try { hdr = JSON.parse(hRaw); } catch(e) { errEl.textContent = 'Header JSON: ' + e.message; errEl.style.display='block'; return; }
  try { pay = JSON.parse(pRaw); } catch(e) { errEl.textContent = 'Payload JSON: ' + e.message; errEl.style.display='block'; return; }
  document.getElementById('enc-prev-hdr').innerHTML = synHL(JSON.stringify(hdr, null, 2));
  document.getElementById('enc-prev-pay').innerHTML = synHL(JSON.stringify(pay, null, 2));
  const alg = hdr.alg || 'none';
  const hB = strToB64u(JSON.stringify(hdr)), pB = strToB64u(JSON.stringify(pay)), si = `${hB}.${pB}`;
  try {
    let sig = '';
    if (alg === 'none') {
      sig = '';
    } else if (alg.startsWith('HS')) {
      const hashMap = { HS256:'SHA-256', HS384:'SHA-384', HS512:'SHA-512' };
      const secret = document.getElementById('enc-secret').value;
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name:'HMAC', hash:hashMap[alg] }, false, ['sign']);
      sig = b64uEnc(await crypto.subtle.sign('HMAC', key, enc.encode(si)));
    } else if (alg.startsWith('RS') || alg.startsWith('ES')) {
      const pem = document.getElementById('enc-privkey').value.trim();
      if (!pem) { outEl.innerHTML = '<span class="text-muted text-sm">Paste a PEM private key (PKCS#8) to sign.</span>'; return; }
      const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')), c => c.charCodeAt(0));
      const algMap = { RS256:{ name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, RS384:{ name:'RSASSA-PKCS1-v1_5', hash:'SHA-384' }, RS512:{ name:'RSASSA-PKCS1-v1_5', hash:'SHA-512' }, ES256:{ name:'ECDSA', namedCurve:'P-256', hash:'SHA-256' } };
      const ka = algMap[alg];
      if (!ka) { errEl.textContent = `${alg} signing not supported.`; errEl.style.display='block'; return; }
      const privKey = await crypto.subtle.importKey('pkcs8', der, ka, false, ['sign']);
      sig = b64uEnc(await crypto.subtle.sign(alg.startsWith('ES') ? { name:'ECDSA', hash:ka.hash } : ka.name, privKey, new TextEncoder().encode(si)));
    }
    _encTok = sig ? `${si}.${sig}` : `${si}.`;
    outEl.innerHTML = colorJWT(_encTok);
  } catch(e) { errEl.textContent = 'Signing error: ' + e.message; errEl.style.display='block'; }
}

async function copyEncode(btn) {
  const ok = await clip(_encTok);
  showCopyFeedback(btn, ok);
}

Object.assign(window, {
  copyEncode,
  clearDecode,
  decodeJWT,
  loadDecodeExample,
  renderCompliance,
  runEncode,
  setAlgo,
  setComplianceType,
  verifySignature,
});
