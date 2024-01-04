function process(jwt) {
  if (jwt === "") {
    resetJwt();
    return;
  }
  let decoded = decode(jwt);
  if (decoded.error)
  {
    $("#error").show();
    $("#link").hide();
  }
  else {
    $("#error").hide();
    $("#share").attr("href", "https://jwtpal.com?jwt=" + jwt);
    $("#link").show();
    decoded.summary = summarize(decoded, jwt);
  }
  updateDecoded(decoded);
  Prism.highlightAll(false, null);
}
function decode (jwt) {
  let parts = jwt.split(".");
  let header, payload, signature;
  let error = false;
  if (parts.length >= 1)
  {
    let decodedHeader;
    try {
      decodedHeader = atob(parts[0]);
    }
    catch (err) {
      header = "Token header is not properly Base64 encoded";
      error = true;
    }
    try {
      if (!error) header = JSON.parse(decodedHeader);
    }
    catch (err) {
      header = "Token header is not valid JSON";
      error = true;
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
      console.log(err);
      payload = "Token payload is not properly Base64 encoded";
      error = true;
    }
    try {
      if (!error) payload = JSON.parse(decodedPayload);
    }
    catch (err) {
      payload = "Token payload is not valid JSON";
      error = true;
    }
  }
  else {
    payload = "No payload included in token";
  }
  if (parts.length === 3) {
    signature = parts[2];
  }
  else {
    error = true;
  }
  return {
    header: header,
    payload: payload,
    signature: signature,
    error: error
  };
}
function decodeBase64Url(encoded) {
  return atob(encoded.replace(/\s/g, "")
    .replace(/-/g, '+')
    .replace(/_/g, '/'));
}
function summarize(decoded, encoded) {
  const summary = {};
  summary.signature = "NOT_VALIDATED";
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
    "self": {"href": "https://jwtpal.com?jwt=" + encoded},
    "jwt.claims": {"href": "https://tools.ietf.org/html/rfc7519#section-4"},
    "jwt.validation": {"href": "https://tools.ietf.org/html/rfc7519#section-7.2"},
    "oauth.access_token": {"href": "https://www.oauth.com/oauth2-servers/access-tokens/"},
    "oidc.id_token": {"href": "https://openid.net/specs/openid-connect-core-1_0.html#IDToken"},
    "oidc.id_token_validation": {"href": "https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"},
    "oidc.standard_claims": {"href": "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims"}
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
  let missingClaims = [];
  for (const claim of claims) {
    if (payload[claim] === null) missingClaims.push(claim);
  }
  return missingClaims;
}
function updateDecoded(decoded) {
  update("#header", decoded.header);
  update("#payload", decoded.payload);
  update("#summary", decoded.summary);
}
function update(id, obj) {
  if (typeof obj === "string") {
    $(id).html(obj);
  }
  else {
    $(id).html(JSON.stringify(obj, null, "\t"));
  }
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
}
window.onload = function() {
  let params = new URLSearchParams(location.search);
  let jwt = params.get("jwt");
  if (jwt === null) {
    jwt = params.get("token");
  }
  focusOnJwt(jwt);
}
function focusOnJwt(jwt) {
  let ta = document.getElementById("encodedJwt");
  if (jwt !== null) {
    ta.value = jwt;
    process(jwt);
  }
  ta.focus();
};
