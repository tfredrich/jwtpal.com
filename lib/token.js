function decode(myToken) {
  var token = myToken.split(".");
  if (token.length != 3) {
    clearDecoded();
    if (myToken !== "") {
      $("#error").show();
      $("#verificationError").show();
      $("#verificationSuccess").hide();
    }
    else {
      $("#error").hide();
      $("#verificationError").hide();
      $("#verificationSuccess").hide();
    }
    return;
  }
  if (updateDecoded(token)) {
    $("#error").hide();
  }
  else {
    $("#error").show();
  }
  if (verifySignature(token)) {
    $("#verificationError").hide();
    $("#verificationSuccess").show();
  }
  else {
    $("#verificationError").show();
    $("#verificationSuccess").hide();
  }
}
function updateDecoded(token) {
  var success = true;
  success &= update("#header", token[0]);
  success &= update("#payload", token[1]);
  return success;
}
function update(id, value) {
  try {
    var obj = JSON.parse(atob(value));
    $(id).html(JSON.stringify(obj, null, 4));
    return true;
  }
  catch (err) {
    $(id).html("Cannot parse value from token");
    return false;
  }
}
function verifySignature(token) {
  // var payload = JSON.parse(atob(token[1]));
  // var configUrl = payload.iss + "/.well-known/openid-configuration";
  // alert("calling: " + configUrl);
  return false;
}
function clearDecoded() {
  $("#header").html("");
  $("#payload").html("");
}
window.onload = function() {
  document.getElementById("encodedJwt").focus();
};
