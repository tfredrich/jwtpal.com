'use strict';

// ── SD-JWT DECODE ─────────────────────────────────────────────────────────────
function loadSDExample() {
  const sdjwt = 'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJWHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0YlJTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bhaLhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJd~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MTAwNjk3MjIsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsIm5vbmNlIjoiazh2ZGYwbmQ2Iiwic2RfaGFzaCI6Il8tTmJWSzNmczl3VzNHaDNOUktSNEt1NmZDMUwzN0R2MFFfalBXd0ppRkUifQ.pqw2OB5IA5ya9Mxf60hE3nr2gsJEIoIlnuCa4qIisijHbwg3WzTDFmW2SuNvK_ORN0WU6RoGbJx5uYZh8k4EbA';
  document.getElementById('sd-input').value = sdjwt;
  decodeSD(sdjwt);
}

function clearSD() {
  const input = document.getElementById('sd-input');
  input.value = '';
  document.getElementById('sd-colored').innerHTML = '<span class="text-muted text-sm">Paste an SD-JWT above.</span>';
  document.getElementById('sd-issuer-json').innerHTML = '<span class="text-muted">—</span>';
  document.getElementById('sd-disc-count').textContent = '0';
  document.getElementById('sd-disc-list').innerHTML = '<span class="text-muted text-sm">—</span>';
  document.getElementById('sd-kb-alg').textContent = '—';
  document.getElementById('sd-kb-header').innerHTML = '<span class="text-muted">—</span>';
  document.getElementById('sd-kb-payload').innerHTML = '<span class="text-muted">—</span>';
  document.getElementById('sd-kb-panel').style.display = 'none';
  document.getElementById('sd-claims-bd').innerHTML = '<span class="text-muted text-sm">—</span>';
  input.focus();
}

function looksLikeJwt(segment) {
  return typeof segment === 'string' && segment.split('.').length === 3;
}

function decodeSDHolderBinding(segment) {
  const kbPanel = document.getElementById('sd-kb-panel');
  const kbAlg = document.getElementById('sd-kb-alg');
  const kbHeader = document.getElementById('sd-kb-header');
  const kbPayload = document.getElementById('sd-kb-payload');
  if (!segment) {
    kbPanel.style.display = 'none';
    return;
  }
  kbPanel.style.display = '';

  const parts = segment.split('.');
  const hdr = b64uDecJSON(parts[0]);
  const pay = b64uDecJSON(parts[1]);
  kbAlg.textContent = hdr?.alg || '—';
  kbHeader.innerHTML = hdr ? synHL(JSON.stringify(hdr, null, 2)) : '<span style="color:var(--danger);">Could not decode holder-binding header</span>';
  kbPayload.innerHTML = pay ? synHL(JSON.stringify(pay, null, 2)) : '<span style="color:var(--danger);">Could not decode holder-binding payload</span>';
}

function decodeSD(raw) {
  raw = (raw || '').trim(); if (!raw) return;
  document.getElementById('sd-colored').innerHTML = colorSDInspectable(raw);
  const parts = raw.split('~');
  const jparts = parts[0].split('.');
  const pay = jparts.length >= 2 ? b64uDecJSON(jparts[1]) : null;
  document.getElementById('sd-issuer-json').innerHTML = pay ? synHL(JSON.stringify(pay, null, 2)) : '<span style="color:var(--danger);">Could not decode issuer JWT</span>';
  const tail = parts.slice(1).filter(d => d.length > 0);
  const kbJwt = tail.length && looksLikeJwt(tail[tail.length - 1]) ? tail.pop() : '';
  decodeSDHolderBinding(kbJwt);
  const discs = tail;
  document.getElementById('sd-disc-count').textContent = discs.length;
  const discList = document.getElementById('sd-disc-list'); discList.innerHTML = '';
  const discClaims = [];
  for (const [idx, d] of discs.entries()) {
    const dec = b64uDecJSON(d);
    const item = document.createElement('div'); item.className = 'disc-item';
    item.id = `sd-disc-item-${idx}`;
    if (Array.isArray(dec) && dec.length >= 3) {
      const [salt, name, val] = dec; discClaims.push({ key: name, val });
      item.innerHTML = `<div><div class="disc-key">${esc(String(name))}</div><div class="disc-val">${esc(JSON.stringify(val))}</div><div style="font-size:10px;color:var(--muted);margin-top:2px;">salt: ${esc(String(salt))}</div></div><div class="disc-raw">${esc(d.length>48?d.slice(0,48)+'…':d)}</div>`;
    } else { item.innerHTML = `<span class="text-muted text-sm">Unreadable: ${esc(d.slice(0,40))}…</span>`; }
    discList.appendChild(item);
  }
  if (!discs.length) discList.innerHTML = '<span class="text-muted text-sm">—</span>';
  const claimsBd = document.getElementById('sd-claims-bd');
  const issuerClaims = pay ? Object.entries(pay).filter(([k]) => !['_sd','_sd_alg','iss','sub','iat','exp','nbf'].includes(k)) : [];
  const allClaims = [
    ...issuerClaims.map(([k, v]) => ({ key: k, val: v, source: 'jwt' })),
    ...discClaims.map(({ key, val }) => ({ key, val, source: 'disclosed' })),
  ];
  if (!allClaims.length) {
    claimsBd.innerHTML = '<span class="text-muted text-sm">—</span>';
  } else {
    const rows = allClaims.map(({ key, val, source }) =>
      `<tr><td class="ck">${esc(key)}</td><td class="cv">${esc(JSON.stringify(val))}</td><td><span class="badge ${source === 'jwt' ? 'badge-dim' : 'badge-ok'}">${source === 'jwt' ? 'JWT' : 'disclosed'}</span></td></tr>`
    ).join('');
    claimsBd.innerHTML = `<table class="ct"><thead><tr><th>Claim</th><th>Value</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
}

// ── SD-JWT ENCODE ─────────────────────────────────────────────────────────────
let _sdRows = [
  { key:'given_name', val:'Jane', sd:true },
  { key:'family_name', val:'Doe', sd:true },
  { key:'birthdate', val:'1990-01-15', sd:true },
  { key:'email', val:'jane@example.com', sd:false },
];

function renderSDRows() {
  const c = document.getElementById('sd-rows'); c.innerHTML = '';
  _sdRows.forEach((r, i) => {
    const d = document.createElement('div'); d.className = 'claim-row';
    d.innerHTML = `
      <input type="checkbox" ${r.sd?'checked':''} onchange="_sdRows[${i}].sd=this.checked;buildSD()" title="Selectively disclosed"/>
      <input type="text" value="${esc(r.key)}" placeholder="name" oninput="_sdRows[${i}].key=this.value;buildSD()" style="font-family:var(--font-mono);font-size:12px;"/>
      <input type="text" value="${esc(r.val)}" placeholder="value" oninput="_sdRows[${i}].val=this.value;buildSD()" style="font-family:var(--font-mono);font-size:12px;"/>
      <button class="btn btn-ghost" onclick="_sdRows.splice(${i},1);renderSDRows();buildSD();" style="color:var(--danger);padding:3px 5px;font-size:13px;">✕</button>`;
    c.appendChild(d);
  });
}

function addSDRow() { _sdRows.push({ key:'', val:'', sd:true }); renderSDRows(); }

function randB64u(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return b64uEnc(a); }

async function buildSD() {
  const iss = document.getElementById('sd-iss').value;
  const sub = document.getElementById('sd-sub').value;
  const secret = document.getElementById('sd-secret').value;
  const discs = [], direct = {};
  for (const r of _sdRows) {
    if (!r.key) continue;
    let v = r.val; try { v = JSON.parse(r.val); } catch {}
    if (r.sd) { const salt = randB64u(12); discs.push({ b64: strToB64u(JSON.stringify([salt, r.key, v])), key: r.key, val: v, salt }); }
    else direct[r.key] = v;
  }
  const payload = { iss, sub, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 3600, ...direct, ...(discs.length ? { _sd: discs.map(d=>`<sha256_of_${d.key}_disclosure>`), _sd_alg:'sha-256' } : {}) };
  const si = `${strToB64u(JSON.stringify({ alg:'HS256', typ:'sd+jwt' }))}.${strToB64u(JSON.stringify(payload))}`;
  let sigB = 'unsigned';
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
    sigB = b64uEnc(await crypto.subtle.sign('HMAC', key, enc.encode(si)));
  } catch {}
  const sdjwt = `${si}.${sigB}~${discs.map(d=>d.b64).join('~')}~`;
  const ta = document.getElementById('sd-out'); ta.value = sdjwt; ta._rawText = sdjwt;
  const bd = document.getElementById('sd-build-discs');
  if (discs.length) {
    bd.innerHTML = `<div class="panel"><div class="panel-hd"><span class="panel-title">Disclosures (${discs.length})</span></div><div class="panel-bd">${discs.map(d=>`<div class="disc-item"><div><div class="disc-key">${esc(d.key)}</div><div class="disc-val">${esc(JSON.stringify(d.val))}</div><div style="font-size:10px;color:var(--muted);margin-top:2px;">salt: ${esc(d.salt)}</div></div><div class="disc-raw">${esc(d.b64.length>48?d.b64.slice(0,48)+'…':d.b64)}</div></div>`).join('')}</div></div>`;
  } else { bd.innerHTML = ''; }
}

Object.assign(window, {
  addSDRow,
  buildSD,
  clearSD,
  decodeSD,
  loadSDExample,
  renderSDRows,
  _sdRows,
});
