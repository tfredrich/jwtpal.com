const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const { URLSearchParams } = require("url");

function createClassList() {
  return {
    add: function() {},
    remove: function() {},
    toggle: function() {},
    contains: function() { return false; }
  };
}

function createElement(id) {
  return {
    id: id || null,
    value: "",
    textContent: "",
    innerHTML: "",
    style: {},
    disabled: false,
    tabIndex: 0,
    classList: createClassList(),
    attributes: {},
    nextElementSibling: { classList: createClassList(), id: "" },
    setAttribute: function(name, value) {
      this.attributes[name] = value;
    },
    getAttribute: function(name) {
      return this.attributes[name] || "false";
    },
    addEventListener: function() {},
    removeEventListener: function() {},
    querySelector: function() {
      return createElement();
    },
    querySelectorAll: function() {
      return [];
    },
    appendChild: function() {},
    removeChild: function() {},
    remove: function() {},
    focus: function() {},
    select: function() {}
  };
}

function loadDecoder() {
  const elements = new Map();

  function getElement(id) {
    if (!elements.has(id)) {
      elements.set(id, createElement(id));
    }
    return elements.get(id);
  }

  function jquery(selector) {
    const id = typeof selector === "string" && selector.charAt(0) === "#"
      ? selector.slice(1)
      : null;
    const element = id ? getElement(id) : createElement();

    return {
      html: function(value) {
        if (arguments.length === 0) return element.innerHTML;
        element.innerHTML = value;
        element.textContent = value;
        return this;
      },
      val: function(value) {
        if (arguments.length === 0) return element.value;
        element.value = value;
        return this;
      },
      attr: function(name, value) {
        if (arguments.length === 1) return element.attributes[name];
        element.attributes[name] = value;
        return this;
      },
      show: function() {
        element.style.display = "";
        return this;
      },
      hide: function() {
        element.style.display = "none";
        return this;
      },
      tooltip: function() { return this; },
      tab: function() { return this; }
    };
  }

  jquery.fn = { tooltip: function() {}, tab: function() {} };

  const context = {
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    TextEncoder: TextEncoder,
    URLSearchParams: URLSearchParams,
    Blob: Blob,
    atob: function(input) {
      return Buffer.from(input, "base64").toString("binary");
    },
    btoa: function(input) {
      return Buffer.from(input, "binary").toString("base64");
    },
    localStorage: {
      getItem: function() { return null; },
      setItem: function() {}
    },
    sessionStorage: {
      getItem: function() { return null; },
      setItem: function() {},
      removeItem: function() {}
    },
    navigator: {
      clipboard: { writeText: function() { return Promise.resolve(); } },
      serviceWorker: { register: function() { return Promise.resolve(); } }
    },
    location: { search: "" },
    crypto: crypto.webcrypto,
    Prism: null,
    document: {
      getElementById: function(id) {
        return getElement(id);
      },
      querySelector: function(selector) {
        if (selector && selector.charAt(0) === "#") {
          return getElement(selector.slice(1));
        }
        return createElement();
      },
      querySelectorAll: function() {
        return [];
      },
      createElement: function() {
        return createElement();
      },
      body: {
        appendChild: function() {},
        removeChild: function() {}
      },
      documentElement: {
        setAttribute: function() {},
        getAttribute: function() { return "light"; }
      }
    },
    $: jquery,
    jQuery: jquery
  };

  context.window = context;
  context.window.matchMedia = function() {
    return { matches: false };
  };
  context.window.crypto = crypto.webcrypto;

  vm.createContext(context);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, "..", "lib", "token.js"), "utf8"),
    context,
    { filename: "lib/token.js" }
  );

  return {
    context: context,
    elements: elements
  };
}

function main() {
  const token = fs.readFileSync(
    path.join(__dirname, "fixtures", "oauth-authz-req.jwt"),
    "utf8"
  ).trim();
  const runtime = loadDecoder();
  const decoded = runtime.context.decode(token);

  assert.strictEqual(decoded.error, false, "fixture token should decode cleanly");
  assert.strictEqual(
    decoded.header.typ,
    "oauth-authz-req+jwt",
    "fixture token header typ changed"
  );
  assert.strictEqual(
    runtime.context.isSdJwtHeader(decoded.header),
    false,
    "oauth authz request JWT must not be classified as SD-JWT"
  );
  assert.strictEqual(
    runtime.context.splitSdJwt(token),
    null,
    "fixture token unexpectedly parsed as SD-JWT"
  );

  assert.ok(Array.isArray(decoded.payload.dcql_query.credentials), "credentials must stay an array");
  assert.ok(
    Array.isArray(decoded.payload.dcql_query.credentials[0].claims),
    "claims must stay an array"
  );
  assert.ok(
    Array.isArray(decoded.payload.client_metadata.encrypted_response_enc_values_supported),
    "encrypted response enc values must stay an array"
  );

  runtime.context.update("#payload", decoded.payload);
  const rendered = runtime.elements.get("payload").innerHTML;
  const renderedPayload = JSON.parse(rendered);

  assert.ok(Array.isArray(renderedPayload.dcql_query.credentials), "rendered credentials must stay an array");
  assert.ok(
    Array.isArray(renderedPayload.dcql_query.credentials[0].claims),
    "rendered claims must stay an array"
  );
  assert.ok(
    Array.isArray(renderedPayload.client_metadata.encrypted_response_enc_values_supported),
    "rendered encrypted response enc values must stay an array"
  );

  console.log("oauth-authz-req regression passed");
}

main();
