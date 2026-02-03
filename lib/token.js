// ============================================================================
// Theme Management
// ============================================================================
function initTheme() {
  const savedTheme = localStorage.getItem("jwtpal-theme");
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const theme = savedTheme || (prefersDark ? "dark" : "light");
  setTheme(theme);
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("jwtpal-theme", theme);
  updateThemeIcon(theme);
}

function updateThemeIcon(theme) {
  const iconEl = document.querySelector(".theme-icon");
  if (iconEl) {
    iconEl.innerHTML = theme === "dark" ? "&#9788;" : "&#9790;";
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  setTheme(newTheme);
}

// ============================================================================
// Clipboard Functionality
// ============================================================================
function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  // Fallback for older browsers
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand("copy");
  } catch (err) {
    console.error("Copy failed:", err);
  }
  document.body.removeChild(textarea);
  return Promise.resolve();
}

function handleCopyClick(event) {
  const btn = event.target;
  const targetId = btn.getAttribute("data-target");
  const targetEl = document.getElementById(targetId);
  if (!targetEl) return;

  const text = targetEl.textContent;
  copyToClipboard(text).then(function() {
    const originalText = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(function() {
      btn.textContent = originalText;
      btn.classList.remove("copied");
    }, 1500);
  });
}

// ============================================================================
// Token Size Display
// ============================================================================
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  return (bytes / 1024).toFixed(1) + " KB";
}

function updateTokenSize(jwt) {
  const sizeEl = document.getElementById("tokenSize");
  if (!sizeEl) return;

  if (!jwt || jwt.trim() === "") {
    sizeEl.textContent = "";
    return;
  }

  const total = new Blob([jwt]).size;
  const parts = jwt.split("~")[0].split(".");
  const headerSize = parts[0] ? new Blob([parts[0]]).size : 0;
  const payloadSize = parts[1] ? new Blob([parts[1]]).size : 0;
  const signatureSize = parts[2] ? new Blob([parts[2]]).size : 0;

  sizeEl.innerHTML =
    "<span>Total: " + formatBytes(total) + "</span>" +
    "<span>Header: " + formatBytes(headerSize) + "</span>" +
    "<span>Payload: " + formatBytes(payloadSize) + "</span>" +
    "<span>Signature: " + formatBytes(signatureSize) + "</span>";
}

// ============================================================================
// Session History
// ============================================================================
var HISTORY_KEY = "jwtpal-history";
var MAX_HISTORY = 10;

function getHistory() {
  try {
    var history = sessionStorage.getItem(HISTORY_KEY);
    return history ? JSON.parse(history) : [];
  } catch (e) {
    return [];
  }
}

function saveHistory(history) {
  try {
    sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch (e) {
    // Ignore storage errors
  }
}

function addToHistory(jwt) {
  if (!jwt || jwt.trim() === "") return;

  var history = getHistory();
  // Don't add duplicates
  var existingIndex = history.findIndex(function(item) {
    return item.token === jwt;
  });
  if (existingIndex !== -1) {
    // Move to front
    history.splice(existingIndex, 1);
  }

  var decoded = decode(jwt.split("~")[0]);
  var preview = "";
  if (decoded.payload && typeof decoded.payload === "object") {
    preview = decoded.payload.sub || decoded.payload.iss || decoded.payload.aud || "Token";
  } else {
    preview = "Token";
  }

  history.unshift({
    token: jwt,
    preview: preview,
    timestamp: Date.now()
  });

  // Limit history size
  if (history.length > MAX_HISTORY) {
    history = history.slice(0, MAX_HISTORY);
  }

  saveHistory(history);
  renderHistory();
}

function clearHistory() {
  sessionStorage.removeItem(HISTORY_KEY);
  renderHistory();
}

function renderHistory() {
  var menu = document.getElementById("historyMenu");
  if (!menu) return;

  var history = getHistory();

  if (history.length === 0) {
    menu.innerHTML = '<span class="dropdown-item text-muted">No history yet</span>';
    return;
  }

  var html = "";
  history.forEach(function(item, index) {
    var time = new Date(item.timestamp);
    var timeStr = time.toLocaleTimeString();
    html += '<a class="dropdown-item" href="#" data-history-index="' + index + '">' +
      '<div class="history-preview">' + escapeHtml(item.preview) + '</div>' +
      '<div class="history-time">' + timeStr + '</div>' +
      '</a>';
  });
  html += '<div class="dropdown-divider"></div>';
  html += '<a class="dropdown-item btn-clear-history" href="#">Clear History</a>';

  menu.innerHTML = html;
}

function escapeHtml(str) {
  var div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function handleHistoryClick(event) {
  event.preventDefault();
  var target = event.target.closest("[data-history-index]");
  if (target) {
    var index = parseInt(target.getAttribute("data-history-index"), 10);
    var history = getHistory();
    if (history[index]) {
      focusOnJwt(history[index].token);
    }
    return;
  }
  if (event.target.classList.contains("btn-clear-history")) {
    clearHistory();
  }
}

// ============================================================================
// Timestamp Formatting
// ============================================================================
function formatTimestamp(ts) {
  if (typeof ts !== "number") return null;
  var date = new Date(ts * 1000);
  var iso = date.toISOString();
  var relative = getRelativeTime(ts);
  return iso + " (" + relative + ")";
}

function getRelativeTime(ts) {
  var now = Math.floor(Date.now() / 1000);
  var diff = ts - now;
  var absDiff = Math.abs(diff);

  var units = [
    { name: "d", seconds: 86400 },
    { name: "h", seconds: 3600 },
    { name: "m", seconds: 60 }
  ];

  for (var i = 0; i < units.length; i++) {
    var unit = units[i];
    if (absDiff >= unit.seconds) {
      var value = Math.floor(absDiff / unit.seconds);
      if (diff < 0) {
        return value + unit.name + " ago";
      } else {
        return "in " + value + unit.name;
      }
    }
  }

  if (diff < 0) {
    return absDiff + "s ago";
  }
  return "in " + absDiff + "s";
}

function annotateTimestamps(obj) {
  if (!obj || typeof obj !== "object") return obj;

  var timestampClaims = ["exp", "iat", "nbf", "auth_time"];
  var annotated = {};

  for (var key in obj) {
    if (obj.hasOwnProperty(key)) {
      var value = obj[key];
      if (timestampClaims.indexOf(key) !== -1 && typeof value === "number") {
        annotated[key + " /* " + formatTimestamp(value) + " */"] = value;
      } else if (typeof value === "object" && value !== null) {
        annotated[key] = annotateTimestamps(value);
      } else {
        annotated[key] = value;
      }
    }
  }

  return annotated;
}

// ============================================================================
// Token Builder
// ============================================================================
function generateUUID() {
  if (window.crypto && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0;
    var v = c === "x" ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function base64UrlEncodeString(str) {
  var base64 = btoa(unescape(encodeURIComponent(str)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function buildUnsignedToken() {
  var header = { typ: "JWT", alg: "none" };
  var payload = {};

  var iss = document.getElementById("builderIss").value.trim();
  var sub = document.getElementById("builderSub").value.trim();
  var aud = document.getElementById("builderAud").value.trim();
  var jti = document.getElementById("builderJti").value.trim();
  var iat = document.getElementById("builderIat").value.trim();
  var exp = document.getElementById("builderExp").value.trim();
  var nbf = document.getElementById("builderNbf").value.trim();

  if (iss) payload.iss = iss;
  if (sub) payload.sub = sub;
  if (aud) payload.aud = aud;
  if (jti) payload.jti = jti;
  if (iat) payload.iat = parseInt(iat, 10);
  if (exp) payload.exp = parseInt(exp, 10);
  if (nbf) payload.nbf = parseInt(nbf, 10);

  // Add custom claims
  var customClaims = document.querySelectorAll(".custom-claim-row");
  customClaims.forEach(function(row) {
    var keyInput = row.querySelector(".claim-key");
    var valueInput = row.querySelector(".claim-value");
    if (keyInput && valueInput) {
      var key = keyInput.value.trim();
      var value = valueInput.value.trim();
      if (key) {
        // Try to parse as JSON, otherwise use as string
        try {
          payload[key] = JSON.parse(value);
        } catch (e) {
          payload[key] = value;
        }
      }
    }
  });

  var encodedHeader = base64UrlEncodeString(JSON.stringify(header));
  var encodedPayload = base64UrlEncodeString(JSON.stringify(payload));

  return encodedHeader + "." + encodedPayload + ".";
}

function addCustomClaimRow() {
  var list = document.getElementById("customClaimsList");
  if (!list) return;

  var row = document.createElement("div");
  row.className = "custom-claim-row";
  row.innerHTML =
    '<input type="text" class="form-control form-control-sm claim-key" placeholder="Claim name">' +
    '<input type="text" class="form-control form-control-sm claim-value" placeholder="Value (JSON or string)">' +
    '<button type="button" class="btn btn-outline-danger btn-sm btn-remove" title="Remove">×</button>';

  row.querySelector(".btn-remove").addEventListener("click", function() {
    row.remove();
  });

  list.appendChild(row);
}

function populateBuilderFromPayload() {
  // Get the current payload from the decoded section
  var payloadEl = document.getElementById("payload");
  if (!payloadEl || !payloadEl.textContent.trim()) return;

  var payload;
  try {
    // Parse the payload, removing timestamp annotations
    var text = payloadEl.textContent;
    // Remove the timestamp annotations like: "exp /* 2024-01-01T00:00:00.000Z (in 5d) */"
    text = text.replace(/"([^"]+)\s*\/\*[^*]*\*\/"/g, '"$1"');
    payload = JSON.parse(text);
  } catch (e) {
    return; // Can't parse, skip population
  }

  var standardClaims = ["iss", "sub", "aud", "jti", "iat", "exp", "nbf"];

  // Populate standard fields
  if (payload.iss !== undefined) {
    document.getElementById("builderIss").value = payload.iss;
  }
  if (payload.sub !== undefined) {
    document.getElementById("builderSub").value = payload.sub;
  }
  if (payload.aud !== undefined) {
    document.getElementById("builderAud").value = Array.isArray(payload.aud) ? payload.aud.join(", ") : payload.aud;
  }
  if (payload.jti !== undefined) {
    document.getElementById("builderJti").value = payload.jti;
  }
  if (payload.iat !== undefined) {
    document.getElementById("builderIat").value = payload.iat;
  }
  if (payload.exp !== undefined) {
    document.getElementById("builderExp").value = payload.exp;
  }
  if (payload.nbf !== undefined) {
    document.getElementById("builderNbf").value = payload.nbf;
  }

  // Clear existing custom claims
  var customClaimsList = document.getElementById("customClaimsList");
  if (customClaimsList) {
    customClaimsList.innerHTML = "";
  }

  // Add custom claims (non-standard claims)
  for (var key in payload) {
    if (payload.hasOwnProperty(key) && standardClaims.indexOf(key) === -1) {
      addCustomClaimRow();
      var rows = customClaimsList.querySelectorAll(".custom-claim-row");
      var lastRow = rows[rows.length - 1];
      if (lastRow) {
        lastRow.querySelector(".claim-key").value = key;
        var value = payload[key];
        lastRow.querySelector(".claim-value").value = typeof value === "object" ? JSON.stringify(value) : value;
      }
    }
  }
}

function clearBuilderForm() {
  document.getElementById("builderIss").value = "";
  document.getElementById("builderSub").value = "";
  document.getElementById("builderAud").value = "";
  document.getElementById("builderJti").value = "";
  document.getElementById("builderIat").value = "";
  document.getElementById("builderExp").value = "";
  document.getElementById("builderNbf").value = "";

  var customClaimsList = document.getElementById("customClaimsList");
  if (customClaimsList) {
    customClaimsList.innerHTML = "";
  }
}

function initTokenBuilder() {
  var genJtiBtn = document.getElementById("genJtiBtn");
  var nowIatBtn = document.getElementById("nowIatBtn");
  var nowNbfBtn = document.getElementById("nowNbfBtn");
  var exp1hBtn = document.getElementById("exp1hBtn");
  var exp24hBtn = document.getElementById("exp24hBtn");
  var addClaimBtn = document.getElementById("addClaimBtn");
  var buildTokenBtn = document.getElementById("buildTokenBtn");
  var clearBuilderBtn = document.getElementById("clearBuilderBtn");

  if (genJtiBtn) {
    genJtiBtn.addEventListener("click", function() {
      document.getElementById("builderJti").value = generateUUID();
    });
  }

  if (nowIatBtn) {
    nowIatBtn.addEventListener("click", function() {
      document.getElementById("builderIat").value = Math.floor(Date.now() / 1000);
    });
  }

  if (nowNbfBtn) {
    nowNbfBtn.addEventListener("click", function() {
      document.getElementById("builderNbf").value = Math.floor(Date.now() / 1000);
    });
  }

  if (exp1hBtn) {
    exp1hBtn.addEventListener("click", function() {
      var iat = document.getElementById("builderIat").value;
      var base = iat ? parseInt(iat, 10) : Math.floor(Date.now() / 1000);
      document.getElementById("builderExp").value = base + 3600;
    });
  }

  if (exp24hBtn) {
    exp24hBtn.addEventListener("click", function() {
      var iat = document.getElementById("builderIat").value;
      var base = iat ? parseInt(iat, 10) : Math.floor(Date.now() / 1000);
      document.getElementById("builderExp").value = base + 86400;
    });
  }

  if (addClaimBtn) {
    addClaimBtn.addEventListener("click", addCustomClaimRow);
  }

  if (buildTokenBtn) {
    buildTokenBtn.addEventListener("click", function() {
      var token = buildUnsignedToken();
      focusOnJwt(token);
    });
  }

  if (clearBuilderBtn) {
    clearBuilderBtn.addEventListener("click", clearBuilderForm);
  }
}

// ============================================================================
// Signature Verification
// ============================================================================
var SUPPORTED_ALGS = {
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
  RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
  PS256: { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 },
  PS384: { name: "RSA-PSS", hash: "SHA-384", saltLength: 48 },
  PS512: { name: "RSA-PSS", hash: "SHA-512", saltLength: 64 },
  ES256: { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
  ES384: { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" },
  ES512: { name: "ECDSA", namedCurve: "P-521", hash: "SHA-512" }
};

function showVerifyResult(message, type) {
  var resultEl = document.getElementById("verifyResult");
  if (!resultEl) return;
  resultEl.className = "verify-result " + type;
  resultEl.textContent = message;
  resultEl.style.display = "block";
}

function pemToArrayBuffer(pem) {
  var base64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");
  var binary = atob(base64);
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64UrlToArrayBuffer(base64url) {
  var base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  var padding = base64.length % 4;
  if (padding) {
    base64 += "=".repeat(4 - padding);
  }
  var binary = atob(base64);
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function importPublicKey(keyData, algorithm, format) {
  var keyUsages = ["verify"];

  if (format === "jwk") {
    var jwk = typeof keyData === "string" ? JSON.parse(keyData) : keyData;
    return crypto.subtle.importKey("jwk", jwk, algorithm, false, keyUsages);
  }

  // PEM format
  var keyBuffer = pemToArrayBuffer(keyData);
  return crypto.subtle.importKey("spki", keyBuffer, algorithm, false, keyUsages);
}

function convertEcdsaSignature(signature, curveSize) {
  // ECDSA signatures from JWT are in R || S format
  // Web Crypto expects DER format for some browsers, but actually accepts raw for ECDSA
  // Most browsers accept the raw format directly
  return signature;
}

async function verifySignature() {
  var jwt = document.getElementById("encodedJwt").value.trim();
  if (!jwt) {
    showVerifyResult("No token to verify. Please paste a JWT first.", "error");
    return;
  }

  var parts = jwt.split("~")[0].split(".");
  if (parts.length !== 3) {
    showVerifyResult("Invalid JWT format. Expected 3 parts.", "error");
    return;
  }

  var decoded = decode(jwt.split("~")[0]);
  if (decoded.error) {
    showVerifyResult("Cannot verify: JWT has decoding errors.", "error");
    return;
  }

  var alg = decoded.header.alg;

  // Reject HMAC algorithms
  if (alg && alg.startsWith("HS")) {
    showVerifyResult("HMAC algorithms (HS256, HS384, HS512) use shared secrets and cannot be safely verified in a browser. Use asymmetric algorithms (RS*, ES*, PS*) instead.", "error");
    return;
  }

  if (alg === "none") {
    showVerifyResult("Token has 'alg: none' - no signature to verify.", "error");
    return;
  }

  if (!SUPPORTED_ALGS[alg]) {
    showVerifyResult("Unsupported algorithm: " + alg + ". Supported: " + Object.keys(SUPPORTED_ALGS).join(", "), "error");
    return;
  }

  var format = document.getElementById("verifyKeyFormat").value;
  var keyInput = document.getElementById("verifyKeyInput").value.trim();

  if (!keyInput) {
    showVerifyResult("Please provide a public key.", "error");
    return;
  }

  try {
    var algConfig = SUPPORTED_ALGS[alg];
    var importAlg = { name: algConfig.name };

    if (algConfig.hash) {
      importAlg.hash = algConfig.hash;
    }
    if (algConfig.namedCurve) {
      importAlg.namedCurve = algConfig.namedCurve;
    }

    var key = await importPublicKey(keyInput, importAlg, format);

    var signedData = new TextEncoder().encode(parts[0] + "." + parts[1]);
    var signature = base64UrlToArrayBuffer(parts[2]);

    var verifyAlg = { name: algConfig.name };
    if (algConfig.hash && algConfig.name === "ECDSA") {
      verifyAlg.hash = algConfig.hash;
    }
    if (algConfig.saltLength) {
      verifyAlg.saltLength = algConfig.saltLength;
    }

    var isValid = await crypto.subtle.verify(verifyAlg, key, signature, signedData);

    if (isValid) {
      showVerifyResult("Signature is valid.", "valid");
    } else {
      showVerifyResult("Signature is invalid.", "invalid");
    }
  } catch (err) {
    showVerifyResult("Verification error: " + err.message, "error");
  }
}

async function fetchJwks() {
  var url = document.getElementById("verifyJwksUrl").value.trim();
  if (!url) {
    showVerifyResult("Please enter a JWKS URL.", "error");
    return;
  }

  try {
    var response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    var jwks = await response.json();

    // Get the kid from current token
    var jwt = document.getElementById("encodedJwt").value.trim();
    var decoded = decode(jwt.split("~")[0]);
    var kid = decoded.header && decoded.header.kid;

    var selectedKey = null;
    if (kid && jwks.keys) {
      selectedKey = jwks.keys.find(function(k) {
        return k.kid === kid;
      });
    }

    if (selectedKey) {
      document.getElementById("verifyKeyInput").value = JSON.stringify(selectedKey, null, 2);
      document.getElementById("verifyKeyFormat").value = "jwk";
      toggleKeyInputVisibility();
      showVerifyResult("Found key with kid: " + kid, "valid");
    } else if (jwks.keys && jwks.keys.length > 0) {
      document.getElementById("verifyKeyInput").value = JSON.stringify(jwks.keys[0], null, 2);
      document.getElementById("verifyKeyFormat").value = "jwk";
      toggleKeyInputVisibility();
      showVerifyResult("Using first key from JWKS (no matching kid found).", "error");
    } else {
      showVerifyResult("No keys found in JWKS.", "error");
    }
  } catch (err) {
    showVerifyResult("Failed to fetch JWKS: " + err.message, "error");
  }
}

function toggleKeyInputVisibility() {
  var format = document.getElementById("verifyKeyFormat").value;
  var keyGroup = document.getElementById("verifyKeyInputGroup");
  var jwksGroup = document.getElementById("verifyJwksGroup");

  if (format === "jwks") {
    if (keyGroup) keyGroup.style.display = "none";
    if (jwksGroup) jwksGroup.style.display = "block";
  } else {
    if (keyGroup) keyGroup.style.display = "block";
    if (jwksGroup) jwksGroup.style.display = "none";
  }
}

function initSignatureVerification() {
  var verifyBtn = document.getElementById("verifyBtn");
  var fetchJwksBtn = document.getElementById("fetchJwksBtn");
  var keyFormatSelect = document.getElementById("verifyKeyFormat");

  if (verifyBtn) {
    verifyBtn.addEventListener("click", verifySignature);
  }

  if (fetchJwksBtn) {
    fetchJwksBtn.addEventListener("click", fetchJwks);
  }

  if (keyFormatSelect) {
    keyFormatSelect.addEventListener("change", toggleKeyInputVisibility);
  }
}

// ============================================================================
// Collapsible Sections
// ============================================================================
function initCollapsibleSections() {
  var headers = document.querySelectorAll(".collapsible-header");
  headers.forEach(function(header) {
    header.addEventListener("click", function() {
      var body = header.nextElementSibling;
      var isExpanded = header.getAttribute("aria-expanded") === "true";

      header.setAttribute("aria-expanded", !isExpanded);
      body.classList.toggle("show", !isExpanded);

      // Populate Token Builder when it's expanded
      if (!isExpanded && body.id === "builderBody") {
        populateBuilderFromPayload();
      }
    });

    header.addEventListener("keydown", function(e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        header.click();
      }
    });
  });
}

// ============================================================================
// Main Process Function
// ============================================================================
async function process(jwt) {
  if (jwt === "") {
    resetJwt();
    updateTokenSize("");
  }
  else {
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
      addToHistory(rawJwt);
    }
    await updateDecoded(decoded, rawJwt);
    updateTokenSize(rawJwt);
  }
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
    // Annotate timestamps for payload section
    var displayObj = obj;
    if (id === "#payload" && obj && typeof obj === "object") {
      displayObj = annotateTimestamps(obj);
    }
    $(id).html(JSON.stringify(displayObj, null, "\t"));
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
function setPayloadTabAvailability(canUseSdJwt) {
  const jwtTab = document.getElementById("payload-tab-jwt");
  const sdTab = document.getElementById("payload-tab-sdjwt");
  if (jwtTab) {
    jwtTab.classList.remove("disabled");
    jwtTab.setAttribute("aria-disabled", "false");
    jwtTab.tabIndex = 0;
  }
  if (sdTab) {
    sdTab.classList.toggle("disabled", !canUseSdJwt);
    sdTab.setAttribute("aria-disabled", canUseSdJwt ? "false" : "true");
    sdTab.disabled = !canUseSdJwt;
    sdTab.tabIndex = canUseSdJwt ? 0 : -1;
  }
}
function setPayloadMode(mode) {
  const payloadPane = document.getElementById("payloadPaneJwt");
  const sdSection = document.getElementById("sdjwtSection");
  const jwtTab = document.getElementById("payload-tab-jwt");
  const sdTab = document.getElementById("payload-tab-sdjwt");
  const targetTab = mode === "sd-jwt" ? sdTab : jwtTab;
  if (targetTab && window.jQuery && $.fn && $.fn.tab) {
    if (!targetTab.classList.contains("disabled") && !targetTab.disabled) {
      $(targetTab).tab("show");
    }
    return;
  }
  if (payloadPane) {
    payloadPane.classList.toggle("active", mode !== "sd-jwt");
    payloadPane.classList.toggle("show", mode !== "sd-jwt");
  }
  if (sdSection) {
    sdSection.classList.toggle("active", mode === "sd-jwt");
    sdSection.classList.toggle("show", mode === "sd-jwt");
  }
  if (jwtTab) {
    jwtTab.classList.toggle("active", mode !== "sd-jwt");
    jwtTab.setAttribute("aria-selected", mode !== "sd-jwt" ? "true" : "false");
  }
  if (sdTab) {
    sdTab.classList.toggle("active", mode === "sd-jwt");
    sdTab.setAttribute("aria-selected", mode === "sd-jwt" ? "true" : "false");
  }
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
    setPayloadTabAvailability(false);
    setPayloadMode("jwt");
    return Promise.resolve();
  }
  resetSdJwtUI();
  setPayloadTabAvailability(true);
  setPayloadMode("sd-jwt");
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
  setPayloadTabAvailability(false);
  setPayloadMode("jwt");
  resetSdJwtUI();
  updateTokenSize("");
}
function focusOnJwt(jwt) {
  let ta = document.getElementById("encodedJwt");
  if (jwt !== null) {
    ta.value = jwt;
    process(jwt);
  }
  ta.focus();
};
window.onload = async function() {
  let params = new URLSearchParams(location.search);
  let jwt = params.get("jwt");
  if (jwt === null) {
    jwt = params.get("token");
  }
  const hasJwtParam = jwt !== null;
  setPayloadTabAvailability(false);
  setPayloadMode("jwt");
  let ta = document.getElementById("encodedJwt");
  const initialJwt = jwt === null ? "" : jwt;
  ta.value = initialJwt;
  await process(initialJwt);
  ta.focus();
  if (!(window.jQuery && $.fn && $.fn.tab)) {
    const jwtTab = document.getElementById("payload-tab-jwt");
    const sdTab = document.getElementById("payload-tab-sdjwt");
    if (jwtTab) {
      jwtTab.addEventListener("click", function() {
        setPayloadMode("jwt");
      });
    }
    if (sdTab) {
      sdTab.addEventListener("click", function() {
        if (sdTab.classList.contains("disabled")) return;
        setPayloadMode("sd-jwt");
      });
    }
  }
  const stampEl = document.getElementById("version-stamp");
  if (stampEl && window.JWT_PAL_VERSION) {
    stampEl.textContent = window.JWT_PAL_VERSION;
  }
  if (window.jQuery && $.fn && $.fn.tooltip) {
    $("[data-toggle='tooltip']").tooltip();
  }
  if (!hasJwtParam) {
    setPayloadTabAvailability(false);
    setPayloadMode("jwt");
  }

  // Render history on load (history data may have been populated)
  renderHistory();
}
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js");
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

// Theme toggle - attach immediately since script is at bottom of body
var themeToggleBtn = document.getElementById("themeToggle");
if (themeToggleBtn) {
  themeToggleBtn.addEventListener("click", toggleTheme);
}

// Update theme icon on load (theme already set by inline script in head)
var currentTheme = document.documentElement.getAttribute("data-theme") || "light";
updateThemeIcon(currentTheme);

// Initialize collapsible sections, token builder, and signature verification immediately
initCollapsibleSections();
initTokenBuilder();
initSignatureVerification();

// Copy buttons
document.querySelectorAll(".copy-btn").forEach(function(btn) {
  btn.addEventListener("click", handleCopyClick);
});

// History menu clicks
var historyMenuEl = document.getElementById("historyMenu");
if (historyMenuEl) {
  historyMenuEl.addEventListener("click", handleHistoryClick);
}
