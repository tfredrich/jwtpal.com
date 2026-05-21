# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JwtPal.com is a client-side JWT and SD-JWT decoder/debugger for OAuth2 and OpenID Connect flows. It's a pure static website with zero backend—tokens never leave the browser.

## Technology Stack

- Vanilla HTML/CSS/JavaScript (ES5+)
- No build tools or bundlers required
- External CSS for the GitHub fork ribbon; application behavior is implemented with local browser scripts.

## Development Commands

```bash
# Start local server
python3 -m http.server 8080

# Open in browser
open http://localhost:8080/index.html

# Format code (optional)
prettier --write lib/*.js lib/*.css
```

## Architecture

**Page Flow:**
```
User Input → feature script decode/build helper → shared rendering/copy helpers → DOM update
```

**Key Files:**
- `index.html` - Single-page JWT, SD-JWT, and OAuth2 PKCE playground markup.
- `lib/playground.js` - Shared UI wiring, theme handling, copy helpers, URL preload logic, and version display.
- `lib/playground-jwt.js` - JWT decoding, encoding, signature verification, and claim compliance behavior.
- `lib/playground-sdjwt.js` - SD-JWT decoding, disclosure display, and SD-JWT example building.
- `lib/playground-oauth.js` - OAuth2 PKCE parameter generation and authorization/token request helpers.
- `lib/playground-style.css` - Styling, theme variables, layout, and responsive rules.

**Main Functions:**
- `decodeJWT(raw)` - Parse JWT header/payload/signature and render decode panels.
- `runEncode()` - Build and optionally sign a JWT from editable JSON inputs.
- `decodeSD(raw)` - Split and render SD-JWT issuer JWT, disclosures, and holder-binding JWT.
- `buildSD()` - Build a local SD-JWT example from editable claims.
- `genPKCE()` - Generate OAuth2 PKCE verifier/challenge/state/nonce values.

## Testing

Manual testing only. Key scenarios:
- Valid JWT with all standard claims
- Expired token detection
- Malformed tokens (invalid Base64, missing segments)
- SD-JWT with multiple disclosures
- Query-string loading (`?jwt=` or `?token=` parameters)
- Tab switching between JWT, SD-JWT, and OAuth2 PKCE views

Use `blob.jwt` for large token regression testing.

## Coding Conventions

- ES5+ JavaScript, no transpilation
- camelCase for variables/functions
- 2-space indentation
- Keep feature-specific behavior in the matching `lib/playground-*.js` file.
- Export functions used by inline HTML handlers through `window`.
- Base64URL decoding must normalize padding for cross-browser support

## Commit Style

Concise, imperative messages (e.g., "Add disclosure validation", "Fix Base64 padding")
