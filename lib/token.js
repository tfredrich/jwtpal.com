async function process(jwt) {
  if (jwt === "") {
    resetJwt();
    return;
  }
  const rawJwt = jwt;
  const sdJwtParts = splitSdJwt(rawJwt);
  const jwtToDecode = sdJwtParts ? sdJwtParts.baseJwt : rawJwt;
  let decoded = decode(jwtToDecode);
  if (decoded.error)
  {
    $("#error").show();
    $("#link").hide();
    decoded.summary = summarize(decoded, rawJwt);
  }
  else {
    $("#error").hide();
    $("#share").attr("href", "https://jwtpal.com?jwt=" + rawJwt);
    $("#link").show();
    decoded.summary = summarize(decoded, rawJwt);
  }
  await updateDecoded(decoded, rawJwt);
  if (window.Prism && Prism.highlightAll) {
    Prism.highlightAll(false, null);
  }
}
function decode (jwt) {
  let parts = jwt.split(".");
  let header, payload, signature;
  let headerError = false;
  let payloadError = false;
  let signatureError = false;
  if (parts.length >= 1)
  {
    let decodedHeader;
    try {
      decodedHeader = decodeBase64Url(parts[0]);
    }
    catch (err) {
      header = "Token header is not properly Base64 encoded";
      headerError = true;
    }
    try {
      if (!headerError) header = JSON.parse(decodedHeader);
    }
    catch (err) {
      header = "Token header is not valid JSON";
      headerError = true;
    }
  }
  else {
    header = "No header included in token";
  }
  if (parts.length >= 2) {
    let decodedPayload;
    try {
      decodedPayload = decodeBase64Url(parts[1]);
    }
    catch (err) {
      payload = "Token payload is not properly Base64 encoded";
      payloadError = true;
    }
    try {
      if (!payloadError) payload = JSON.parse(decodedPayload);
    }
    catch (err) {
      payload = "Token payload is not valid JSON";
      payloadError = true;
    }
  }
  else {
    payload = "No payload included in token";
  }
  if (parts.length === 3) {
    signature = parts[2];
  }
  else {
    if (header && typeof header === "object" && header.alg && header.alg !== "none") {
      signature = "Expected signature for alg:" + header.alg + " but none found";
      signatureError = true;
    }
    else {
      signature = "(no signature)";
    }
  }
  return {
    header: header,
    payload: payload,
    signature: signature,
    error: headerError || payloadError || signatureError
  };
}
function decodeBase64Url(encoded) {
  const cleaned = encoded.replace(/\s/g, "")
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const padding = cleaned.length % 4;
  const padded = padding ? cleaned + "=".repeat(4 - padding) : cleaned;
  return atob(padded);
}
function summarize(decoded, encoded) {
  const summary = {};
  summary.signature = {
    "value": decoded.signature,
    "status": "NOT_VALIDATED"
  };
  summary.expiration = expiration(decoded.payload);
  summary.missing_claims = {
    "jwt": {
      "recommended": requiredClaims(decoded.payload),
      "additional": optionalClaims(decoded.payload)
    },
    "id_token": {
      "required": requiredIdTokenClaims(decoded.payload),
      "optional": optionalIdTokenClaims(decoded.payload)
    }
  };
  summary._links = {
    "self": {"href": "https://jwtpal.com?jwt=" + encoded, "title": "A reference back to this JWT Pal page with the current token"},
    "jwt.claims": {"href": "https://tools.ietf.org/html/rfc7519#section-4", "title": "JSON Web Token Claims"},
    "jwt.validation": {"href": "https://tools.ietf.org/html/rfc7519#section-7.2", "title": "How to Validate a JSON Web Token (JWT)"},
    "oauth.access_token": {"href": "https://www.oauth.com/oauth2-servers/access-tokens/", "title": "About OAuth 2.0 Access Tokens"},
    "oidc.id_token": {"href": "https://openid.net/specs/openid-connect-core-1_0.html#IDToken", "title": "About OpenID Connect ID Tokens"},
    "oidc.id_token_validation": {"href": "https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation", "title": "How to Validate an OpenID Connect ID Token"},
    "oidc.standard_claims": {"href": "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims", "title": "OpenID Connect Standard Claims"}
  }
  return summary;
}
function expiration(payload) {
  if (payload.exp == null || payload.iat == null) return {};
  const s = payload.exp - payload.iat;
  const m = s / 60;
  const h = m / 60;
  const d = h / 24;
  const now = Math.round(Date.now() / 1000);
  return {
    "expired": now > payload.exp,
    "at": new Date(payload.exp * 1000).toISOString(),
    "lifetime": {
      "seconds": s,
      "minutes": m,
      "hours": h,
      "days": d
    }
  };
}
function requiredClaims(payload) {
  const claims = ["iss", "sub", "aud", "exp", "iat"];
  return checkClaims(payload, claims);
}
function optionalClaims(payload) {
  const claims = ["acr", "amr", "azp", "auth_time", "jti", "nbf"];
  return checkClaims(payload, claims);
}
function requiredIdTokenClaims(payload) {
  const claims = ["iss", "sub", "aud", "exp", "iat", "at_hash", "c_hash", "nonce"];
  return checkClaims(payload, claims);
}
function optionalIdTokenClaims(payload) {
  const claims = ["acr", "amr", "azp", "auth_time", "name", "given_name",
    "family_name", "middle_name", "nickname", "preferred_username", "profile",
    "picture", "website", "email", "email_verified", "gender", "birthdate",
    "zoneinfo", "locale", "phone_number", "phone_number_verified", "address",
    "updated_at"];
  return checkClaims(payload, claims);
}
function checkClaims(payload, claims) {
  if (!payload || typeof payload !== "object") return claims.slice();
  let missingClaims = [];
  for (const claim of claims) {
    if (!(claim in payload)) missingClaims.push(claim);
  }
  return missingClaims;
}
function updateDecoded(decoded, rawJwt) {
  update("#header", decoded.header);
  update("#payload", decoded.payload);
  update("#summary", decoded.summary);
  return updateSdJwt(decoded, rawJwt);
}
function update(id, obj) {
  if (typeof obj === "string") {
    $(id).html(obj);
  }
  else {
    $(id).html(JSON.stringify(obj, null, "\t"));
  }
}
function setCodeText(id, text) {
  const el = document.querySelector(id);
  if (!el) return;
  el.textContent = text;
}
function isSdJwtHeader(header) {
  return header && typeof header === "object" &&
    header.typ && String(header.typ).toLowerCase() === "sd+jwt";
}
function splitSdJwt(rawJwt) {
  if (rawJwt.indexOf("~") === -1) return null;
  const parts = rawJwt.split("~");
  const baseJwt = parts[0];
  let disclosures = parts.slice(1).filter(function(part) {
    return part !== "";
  });
  let kbJwt = null;
  if (disclosures.length && disclosures[disclosures.length - 1].split(".").length === 3) {
    kbJwt = disclosures.pop();
  }
  return {
    baseJwt: baseJwt,
    disclosures: disclosures,
    kbJwt: kbJwt
  };
}
function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
function normalizeSdAlg(alg) {
  if (!alg) return null;
  const normalized = String(alg).toLowerCase();
  if (normalized === "sha-256" || normalized === "sha256") return "SHA-256";
  return null;
}
async function hashDisclosure(encoded, alg) {
  if (!window.crypto || !crypto.subtle || !window.TextEncoder) return null;
  const normalizedAlg = normalizeSdAlg(alg);
  if (!normalizedAlg) return null;
  const data = new TextEncoder().encode(encoded);
  const digest = await crypto.subtle.digest(normalizedAlg, data);
  return base64UrlEncode(new Uint8Array(digest));
}
function parseDisclosure(encoded) {
  let parsed;
  try {
    parsed = JSON.parse(decodeBase64Url(encoded));
  }
  catch (err) {
    return { error: "Invalid disclosure encoding" };
  }
  if (!Array.isArray(parsed) || parsed.length < 2) {
    return { error: "Disclosure format is invalid" };
  }
  if (parsed.length >= 3) {
    return { salt: parsed[0], name: parsed[1], value: parsed[2] };
  }
  return { salt: parsed[0], name: null, value: parsed[1] };
}
function collectSdDigests(payload) {
  const entries = [];
  function visit(node, path) {
    if (Array.isArray(node)) {
      node.forEach(function(item, index) {
        visit(item, path.concat(index));
      });
      return;
    }
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node._sd)) {
      node._sd.forEach(function(digest) {
        entries.push({ digest: digest, path: path.slice() });
      });
    }
    Object.keys(node).forEach(function(key) {
      if (key === "_sd" || key === "_sd_alg") return;
      visit(node[key], path.concat(key));
    });
  }
  visit(payload, []);
  return entries;
}
function getByPath(root, path) {
  let current = root;
  for (const segment of path) {
    if (current == null) return null;
    current = current[segment];
  }
  return current;
}
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}
function buildDisclosuresPayload(payload, state) {
  const clone = deepClone(payload);
  const errors = [];
  state.disclosures.forEach(function(disclosure) {
    if (!disclosure.selected || !disclosure.digest || !state.digestMap.has(disclosure.digest)) {
      return;
    }
    const entry = state.digestMap.get(disclosure.digest);
    const parent = getByPath(clone, entry.path);
    if (!parent) return;
    if (disclosure.name != null) {
      parent[disclosure.name] = disclosure.value;
    }
    else if (Array.isArray(parent)) {
      parent.push(disclosure.value);
    }
    else {
      errors.push("Unsupported array disclosure in object payload.");
    }
    if (Array.isArray(parent._sd)) {
      parent._sd = parent._sd.filter(function(digest) {
        return digest !== disclosure.digest;
      });
      if (parent._sd.length === 0) delete parent._sd;
    }
  });
  return { payload: clone, errors: errors };
}
function resetSdJwtUI() {
  const section = document.getElementById("sdjwtSection");
  if (section) section.style.display = "none";
  const errorEl = document.getElementById("sdjwtErrors");
  if (errorEl) {
    errorEl.style.display = "none";
    errorEl.textContent = "";
  }
  setCodeText("#disclosures", "");
  setCodeText("#kbheader", "");
  setCodeText("#kbpayload", "");
  const kbSection = document.getElementById("sdjwtKeyBinding");
  if (kbSection) kbSection.style.display = "none";
}
function setPayloadMode(mode) {
  const payloadPre = document.getElementById("payload-div");
  const sdSection = document.getElementById("sdjwtSection");
  const jwtInput = document.getElementById("toggle-jwt");
  const sdInput = document.getElementById("toggle-sdjwt");
  const jwtLabel = document.getElementById("toggle-jwt-label");
  const sdLabel = document.getElementById("toggle-sdjwt-label");
  if (payloadPre) payloadPre.style.display = mode === "sd-jwt" ? "none" : "";
  if (sdSection) sdSection.style.display = mode === "sd-jwt" ? "" : "none";
  if (jwtInput) jwtInput.checked = mode !== "sd-jwt";
  if (sdInput) sdInput.checked = mode === "sd-jwt";
  if (jwtLabel) jwtLabel.classList.toggle("active", mode !== "sd-jwt");
  if (sdLabel) sdLabel.classList.toggle("active", mode === "sd-jwt");
  const toggle = document.getElementById("payloadToggle");
  if (toggle) toggle.dataset.mode = mode;
}
function showSdJwtErrors(messages) {
  const errorEl = document.getElementById("sdjwtErrors");
  if (!errorEl) return;
  if (!messages.length) {
    errorEl.textContent = "";
    errorEl.style.display = "none";
    return;
  }
  errorEl.textContent = messages.join(" ");
  errorEl.style.display = "";
}
function renderDisclosures(state) {
  const disclosures = buildDisclosuresPayload(state.payload, state);
  update("#disclosures", disclosures.payload);
  const allErrors = state.errors.concat(disclosures.errors);
  showSdJwtErrors(allErrors);
}
async function buildSdJwtState(payload, parsed) {
  const state = {
    payload: payload,
    sdAlg: payload && typeof payload === "object" ? (payload._sd_alg || "sha-256") : "sha-256",
    disclosures: [],
    digestEntries: [],
    digestMap: new Map(),
    missingDigests: [],
    errors: []
  };
  if (!payload || typeof payload !== "object") {
    state.errors.push("Payload is not a JSON object.");
    return state;
  }
  const digestEntries = collectSdDigests(payload);
  state.digestEntries = digestEntries;
  const digestMap = new Map();
  digestEntries.forEach(function(entry) {
    if (!digestMap.has(entry.digest)) digestMap.set(entry.digest, entry);
  });
  state.digestMap = digestMap;
  const normalizedAlg = normalizeSdAlg(state.sdAlg);
  if (!normalizedAlg) {
    state.errors.push("Unsupported _sd_alg: " + state.sdAlg + ".");
  }
  if (!window.crypto || !crypto.subtle || !window.TextEncoder) {
    state.errors.push("Web Crypto not available for disclosure hashing.");
  }
  const matchedDigests = new Set();
  let hasDisclosureErrors = false;
  for (const encoded of parsed.disclosures) {
    const disclosure = parseDisclosure(encoded);
    if (disclosure.error) {
      hasDisclosureErrors = true;
      state.disclosures.push({
        encoded: encoded,
        name: null,
        value: null,
        digest: null,
        isMatch: false,
        selected: false,
        error: disclosure.error
      });
      continue;
    }
    let digest = null;
    if (normalizedAlg && window.crypto && crypto.subtle && window.TextEncoder) {
      digest = await hashDisclosure(encoded, state.sdAlg);
    }
    const isMatch = digest && digestMap.has(digest);
    if (isMatch) matchedDigests.add(digest);
    state.disclosures.push({
      encoded: encoded,
      name: disclosure.name,
      value: disclosure.value,
      digest: digest,
      isMatch: isMatch,
      selected: isMatch,
      error: null
    });
  }
  digestMap.forEach(function(entry, digest) {
    if (!matchedDigests.has(digest)) state.missingDigests.push(digest);
  });
  if (hasDisclosureErrors) {
    state.errors.push("One or more disclosures could not be decoded.");
  }
  return state;
}
function updateSdJwt(decoded, rawJwt) {
  const section = document.getElementById("sdjwtSection");
  if (!section) return Promise.resolve();
  if (!isSdJwtHeader(decoded.header)) {
    resetSdJwtUI();
    const toggle = document.getElementById("payloadToggle");
    if (toggle) toggle.style.display = "none";
    setPayloadMode("jwt");
    return Promise.resolve();
  }
  resetSdJwtUI();
  const toggle = document.getElementById("payloadToggle");
  if (toggle) toggle.style.display = "";
  setPayloadMode("sd-jwt");
  section.style.display = "";
  const parsed = splitSdJwt(rawJwt);
  if (!parsed) {
    showSdJwtErrors(["SD-JWT typ detected, but token does not include disclosures."]);
    return Promise.resolve();
  }
  if (parsed.kbJwt) {
    const kbDecoded = decode(parsed.kbJwt);
    update("#kbheader", kbDecoded.header);
    update("#kbpayload", kbDecoded.payload);
    const kbSection = document.getElementById("sdjwtKeyBinding");
    if (kbSection) kbSection.style.display = "";
  }
  return buildSdJwtState(decoded.payload, parsed).then(function(state) {
    showSdJwtErrors(state.errors);
    renderDisclosures(state);
  });
}
function sampleJwt() {
  const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqd3RwYWwuY29tIiwiaWF0IjoxNjA0NDQ1NDM1LCJleHAiOjE2MzU5ODE0MzUsImF1ZCI6Ind3dy5uZXZlcmxhbmQub3JnIiwic3ViIjoicHBhbkBuZXZlcmxhbmQub3JnIiwiR2l2ZW5OYW1lIjoiUGV0ZXIiLCJTdXJuYW1lIjoiUGFuIiwiRW1haWwiOiJwcGFuQG5ldmVybGFuZC5vcmcifQ.twV78VhAbatpW5z68Y7jcHHF5QZIP2KHAL88mzZh6uM";
  resetFields();
  focusOnJwt(jwt);
}
function sampleSdJwt() {
  const sdJwt = "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJWHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0YlJTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bhaLhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJd~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MTAwNjk3MjIsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsIm5vbmNlIjoiazh2ZGYwbmQ2Iiwic2RfaGFzaCI6Il8tTmJWSzNmczl3VzNHaDNOUktSNEt1NmZDMUwzN0R2MFFfalBXd0ppRkUifQ.pqw2OB5IA5ya9Mxf60hE3nr2gsJEIoIlnuCa4qIisijHbwg3WzTDFmW2SuNvK_ORN0WU6RoGbJx5uYZh8k4EbA";
  resetFields();
  focusOnJwt(sdJwt);
}
function resetJwt() {
  resetFields();
  focusOnJwt(null);
}
function resetFields() {
  $("#error").hide();
  $("#link").hide();
  $("#encodedJwt").val("");
  $("#header").html("");
  $("#payload").html("");
  $("#summary").html("");
  const toggle = document.getElementById("payloadToggle");
  if (toggle) toggle.style.display = "none";
  setPayloadMode("jwt");
  resetSdJwtUI();
}
function focusOnJwt(jwt) {
  let ta = document.getElementById("encodedJwt");
  if (jwt !== null) {
    ta.value = jwt;
    process(jwt);
  }
  ta.focus();
};
window.onload = function() {
  let params = new URLSearchParams(location.search);
  let jwt = params.get("jwt");
  if (jwt === null) {
    jwt = params.get("token");
  }
  focusOnJwt(jwt);
  const jwtToggle = document.getElementById("toggle-jwt");
  const sdToggle = document.getElementById("toggle-sdjwt");
  const jwtLabel = document.getElementById("toggle-jwt-label");
  const sdLabel = document.getElementById("toggle-sdjwt-label");
  if (jwtToggle) {
    jwtToggle.addEventListener("change", function() {
      if (jwtToggle.checked) setPayloadMode("jwt");
    });
  }
  if (sdToggle) {
    sdToggle.addEventListener("change", function() {
      if (sdToggle.checked) setPayloadMode("sd-jwt");
    });
  }
  if (jwtLabel) {
    jwtLabel.addEventListener("click", function() {
      setPayloadMode("jwt");
    });
  }
  if (sdLabel) {
    sdLabel.addEventListener("click", function() {
      setPayloadMode("sd-jwt");
    });
  }
  const stampEl = document.getElementById("version-stamp");
  if (stampEl && window.JWT_PAL_VERSION) {
    stampEl.textContent = window.JWT_PAL_VERSION;
  }
  if (window.jQuery && $.fn && $.fn.tooltip) {
    $("[data-toggle='tooltip']").tooltip();
  }
}
document.getElementById('encodedJwt').addEventListener('input', function() {
  process(this.value);
});
const sampleJwtButton = document.querySelector('#btn-sample-jwt');
const sampleSdJwtButton = document.querySelector('#btn-sample-sdjwt');
if (sampleJwtButton) {
  sampleJwtButton.addEventListener('click', sampleJwt);
  sampleJwtButton.addEventListener('touchend', sampleJwt);
}
if (sampleSdJwtButton) {
  sampleSdJwtButton.addEventListener('click', sampleSdJwt);
  sampleSdJwtButton.addEventListener('touchend', sampleSdJwt);
}
document.querySelector('#btn-clear').addEventListener('click', resetJwt);
document.querySelector('#btn-clear').addEventListener('touchend', resetJwt);
