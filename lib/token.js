function process(jwt) {
  if (jwt === "") {
    resetErrors();
    return;
  }
  var decoded = decode(jwt);
  if (decoded.error)
  {
    $("#error").show();
  }
  else {
    $("#error").hide();
  }
  updateDecoded(decoded);
}
function decode (jwt) {
  var parts = jwt.split(".");
  var header, payload, signature;
  var error = false;
  if (parts.length >= 1)
  {
    var decodedHeader;
    try {
      decodedHeader = atob(parts[0]);
    }
    catch (err) {
      header = "Cannot base64 decode token header";
      error = true;
    }
    try {
      header = JSON.parse(decodedHeader);
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
    var decodedPayload;
    try {
      decodedPayload = atob(parts[1]);
    }
    catch (err) {
      payload = "Cannot base64 decode token payload";
      error = true;
    }
    try {
      payload = JSON.parse(decodedPayload);
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
function updateDecoded(decoded) {
  update("#header", decoded.header);
  update("#payload", decoded.payload);
}
function update(id, obj) {
  if (typeof obj === "string") {
    $(id).html(obj);
  }
  else {
    $(id).html(JSON.stringify(obj, null, 4));
  }
}
function resetErrors() {
  $("#error").hide();
  $("#header").html("");
  $("#payload").html("");
  $("#signature").html("");
  $("#verificationError").hide();
  $("#verificationSuccess").hide();
}
window.onload = function() {
  document.getElementById("encodedJwt").focus();
};
