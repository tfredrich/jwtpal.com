function process(jwt) {
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
  updateDecoded(decoded, rawJwt);
  Prism.highlightAll(false, null);
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
  updateSdJwt(decoded, rawJwt);
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
function removeSdFields(node) {
  if (Array.isArray(node)) {
    node.forEach(removeSdFields);
    return;
  }
  if (!node || typeof node !== "object") return;
  delete node._sd;
  delete node._sd_alg;
  Object.keys(node).forEach(function(key) {
    removeSdFields(node[key]);
  });
}
function buildRedactedPayload(payload, showUndisclosed) {
  const clone = deepClone(payload);
  if (!showUndisclosed) removeSdFields(clone);
  return clone;
}
function buildReconstructedPayload(payload, state, showUndisclosed) {
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
  if (!showUndisclosed) removeSdFields(clone);
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
  const disclosureRows = document.getElementById("disclosureRows");
  if (disclosureRows) disclosureRows.innerHTML = "";
  const disclosureSummary = document.getElementById("disclosureSummary");
  if (disclosureSummary) disclosureSummary.textContent = "";
  setCodeText("#reconstructed", "");
  setCodeText("#kbheader", "");
  setCodeText("#kbpayload", "");
  const kbSection = document.getElementById("sdjwtKeyBinding");
  if (kbSection) kbSection.style.display = "none";
  ["badge-sd", "badge-sd-alg", "badge-cnf", "badge-kb-jwt"].forEach(function(id) {
    const badge = document.getElementById(id);
    if (badge) badge.classList.add("d-none");
  });
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
function updateBadges(payload, parsed) {
  const badges = [
    { id: "badge-sd", show: payload && typeof payload === "object" && Array.isArray(payload._sd) },
    { id: "badge-sd-alg", show: payload && typeof payload === "object" && !!payload._sd_alg },
    { id: "badge-cnf", show: payload && typeof payload === "object" && !!payload.cnf },
    { id: "badge-kb-jwt", show: parsed && !!parsed.kbJwt }
  ];
  badges.forEach(function(badge) {
    const el = document.getElementById(badge.id);
    if (!el) return;
    if (badge.show) el.classList.remove("d-none");
    else el.classList.add("d-none");
  });
}
function statusClass(status) {
  if (status === "valid") return "sdjwt-status-valid";
  if (status === "unused") return "sdjwt-status-unused";
  if (status === "missing") return "sdjwt-status-missing";
  return "sdjwt-status-invalid";
}
function renderDisclosures(state) {
  const disclosureRows = document.getElementById("disclosureRows");
  if (!disclosureRows) return;
  disclosureRows.innerHTML = "";
  let validCount = 0;
  let unusedCount = 0;
  let invalidCount = 0;
  state.disclosures.forEach(function(disclosure, index) {
    const row = document.createElement("tr");
    const revealCell = document.createElement("td");
    const claimCell = document.createElement("td");
    const statusCell = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = !!disclosure.selected;
    checkbox.disabled = !disclosure.isMatch;
    checkbox.addEventListener("change", function() {
      disclosure.selected = checkbox.checked;
      renderReconstructed(state);
      renderDisclosures(state);
    });
    revealCell.appendChild(checkbox);
    const claimName = disclosure.error ? "Invalid disclosure" :
      (disclosure.name == null ? "(array element)" : String(disclosure.name));
    claimCell.textContent = claimName;
    let status = "invalid hash";
    if (disclosure.isMatch) {
      status = disclosure.selected ? "valid" : "unused";
    }
    if (status === "valid") validCount += 1;
    else if (status === "unused") unusedCount += 1;
    else invalidCount += 1;
    statusCell.textContent = status;
    statusCell.classList.add(statusClass(status));
    row.appendChild(revealCell);
    row.appendChild(claimCell);
    row.appendChild(statusCell);
    disclosureRows.appendChild(row);
  });
  state.missingDigests.forEach(function() {
    const row = document.createElement("tr");
    const revealCell = document.createElement("td");
    const claimCell = document.createElement("td");
    const statusCell = document.createElement("td");
    revealCell.textContent = "-";
    claimCell.textContent = "(undisclosed)";
    statusCell.textContent = "missing";
    statusCell.classList.add(statusClass("missing"));
    row.appendChild(revealCell);
    row.appendChild(claimCell);
    row.appendChild(statusCell);
    disclosureRows.appendChild(row);
  });
  const disclosureSummary = document.getElementById("disclosureSummary");
  if (disclosureSummary) {
    const missingCount = state.missingDigests.length;
    disclosureSummary.textContent = "Valid: " + validCount +
      ", Unused: " + unusedCount +
      ", Invalid: " + invalidCount +
      ", Missing: " + missingCount;
  }
}
function renderReconstructed(state) {
  const toggle = document.getElementById("toggle-undisclosed");
  const showUndisclosed = toggle ? toggle.checked : true;
  const reconstructed = buildReconstructedPayload(state.payload, state, showUndisclosed);
  update("#reconstructed", reconstructed.payload);
  const allErrors = state.errors.concat(reconstructed.errors);
  showSdJwtErrors(allErrors);
}
function wireCopyButtons(state) {
  const reconstructedButton = document.getElementById("copy-reconstructed");
  const redactedButton = document.getElementById("copy-redacted");
  if (reconstructedButton) {
    reconstructedButton.onclick = function() {
      if (!navigator.clipboard) return;
      const toggle = document.getElementById("toggle-undisclosed");
      const showUndisclosed = toggle ? toggle.checked : true;
      const reconstructed = buildReconstructedPayload(state.payload, state, showUndisclosed);
      navigator.clipboard.writeText(JSON.stringify(reconstructed.payload, null, 2));
    };
  }
  if (redactedButton) {
    redactedButton.onclick = function() {
      if (!navigator.clipboard) return;
      const toggle = document.getElementById("toggle-undisclosed");
      const showUndisclosed = toggle ? toggle.checked : true;
      const redacted = buildRedactedPayload(state.payload, showUndisclosed);
      navigator.clipboard.writeText(JSON.stringify(redacted, null, 2));
    };
  }
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
  if (!section) return;
  if (!isSdJwtHeader(decoded.header)) {
    resetSdJwtUI();
    const toggle = document.getElementById("payloadToggle");
    if (toggle) toggle.style.display = "none";
    setPayloadMode("jwt");
    return;
  }
  resetSdJwtUI();
  const toggle = document.getElementById("payloadToggle");
  if (toggle) toggle.style.display = "";
  setPayloadMode("sd-jwt");
  section.style.display = "";
  const parsed = splitSdJwt(rawJwt);
  updateBadges(decoded.payload, parsed);
  if (!parsed) {
    showSdJwtErrors(["SD-JWT typ detected, but token does not include disclosures."]);
    return;
  }
  if (parsed.kbJwt) {
    const kbDecoded = decode(parsed.kbJwt);
    update("#kbheader", kbDecoded.header);
    update("#kbpayload", kbDecoded.payload);
    const kbSection = document.getElementById("sdjwtKeyBinding");
    if (kbSection) kbSection.style.display = "";
  }
  buildSdJwtState(decoded.payload, parsed).then(function(state) {
    showSdJwtErrors(state.errors);
    renderDisclosures(state);
    renderReconstructed(state);
    wireCopyButtons(state);
    const toggle = document.getElementById("toggle-undisclosed");
    if (toggle) {
      toggle.onchange = function() {
        renderReconstructed(state);
      };
    }
  });
}
function sampleJwt() {
  const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqd3RwYWwuY29tIiwiaWF0IjoxNjA0NDQ1NDM1LCJleHAiOjE2MzU5ODE0MzUsImF1ZCI6Ind3dy5uZXZlcmxhbmQub3JnIiwic3ViIjoicHBhbkBuZXZlcmxhbmQub3JnIiwiR2l2ZW5OYW1lIjoiUGV0ZXIiLCJTdXJuYW1lIjoiUGFuIiwiRW1haWwiOiJwcGFuQG5ldmVybGFuZC5vcmcifQ.twV78VhAbatpW5z68Y7jcHHF5QZIP2KHAL88mzZh6uM";
  resetFields();
  focusOnJwt(jwt);
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
document.querySelector('#btn-sample').addEventListener('click', sampleJwt);
document.querySelector('#btn-sample').addEventListener('touchend', sampleJwt);
document.querySelector('#btn-clear').addEventListener('click', resetJwt);
document.querySelector('#btn-clear').addEventListener('touchend', resetJwt);
