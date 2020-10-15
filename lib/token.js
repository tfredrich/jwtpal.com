function process(jwt) {
  if (jwt === "") {
    resetFields();
    return;
  }
  var decoded = decode(jwt);
  if (decoded.error)
  {
    $("#error").show();
    $("#link").hide();
  }
  else {
    $("#error").hide();
    $("#share").attr("href", "https://jwtpal.com?jwt=" + jwt);
    $("#link").show();
  }
  updateDecoded(decoded);
  Prism.highlightAll(false, null);
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
    var decodedPayload;
    try {
      decodedPayload = atob(parts[1]);
    }
    catch (err) {
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
function updateDecoded(decoded) {
  update("#header", decoded.header);
  update("#payload", decoded.payload);
}
function update(id, obj) {
  if (typeof obj === "string") {
    $(id).html(obj);
  }
  else {
    $(id).html(JSON.stringify(obj, null, "\t"));
  }
}
function resetFields() {
  $("#error").hide();
  $("#link").hide();
  $("#header").html("");
  $("#payload").html("");
  $("#signature").html("");
}
window.onload = function() {
  var params = new URLSearchParams(location.search);
  var jwt = params.get("jwt");
  if (jwt === null) jwt = params.get("token");
  var ta = document.getElementById("encodedJwt");
  if (jwt !== null) {
    ta.value = jwt;
    process(jwt);
  }
  ta.focus();
};
