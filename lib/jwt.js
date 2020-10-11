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
// function verifySignature(jwt) {
//   var parts = jwt.split(".");
//   if (parts.length !== 3) return false;
//   var header = JSON.parse(atob(parts[0]));
//   var payload = JSON.parse(atob(parts[1]));
//   var configUrl = payload.iss + "/.well-known/openid-configuration";
//   $.getJSON (configUrl, function(json) {
//     $.getJSON (json.jwks_uri, function(json) {
//       $.each(json.keys, function(i) {
//         alert ("Found key: " + header.kid + " | " + json.keys[i].kid);
//         if (header.kid === json.keys[i].kid) {
//           var stuff = parts[0] + "." + parts[1];
//           return true;
//         }
//         else return false;
//       });
//     });
//   });
//   return false;
// }
