# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JwtPal.com is a client-side JWT and SD-JWT decoder/debugger for OAuth2 and OpenID Connect flows. It's a pure static website with zero backend—tokens never leave the browser.

## Technology Stack

- Vanilla HTML/CSS/JavaScript (ES5+)
- No build tools or bundlers required
- External libraries via CDN with SRI integrity: Bootstrap 4.5.2, jQuery 3.5.1 slim, Popper.js, Prism.js

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

**Token Processing Flow:**
```
User Input → process() → splitSdJwt() → decode() → summarize() → updateDecoded() → Prism.highlightAll()
```

**Key Files:**
- `lib/token.js` - All JWT/SD-JWT decoding, validation, and UI logic (581 lines)
- `index.html` - Single-page application with tabbed UI for JWT vs SD-JWT views
- `lib/style.css` - Styling with color-coded sections (header=pink #fb015b, payload=purple #d63aff, summary=black)

**Main Functions in token.js:**
- `decode(jwt)` - Parse JWT into header/payload/signature
- `process(jwt)` - Main orchestrator handling SD-JWT detection and routing
- `summarize(decoded, encoded)` - Generate claim analysis with RFC compliance checks
- `splitSdJwt(rawJwt)` - Split SD-JWT using `~` delimiters
- `buildSdJwtState(payload, parsed)` - Construct disclosure validation state

## Testing

Manual testing only. Key scenarios:
- Valid JWT with all standard claims
- Expired token detection
- Malformed tokens (invalid Base64, missing segments)
- SD-JWT with multiple disclosures
- Query-string loading (`?jwt=` or `?token=` parameters)
- Tab switching between JWT/SD-JWT views

Use `blob.jwt` for large token regression testing.

## Coding Conventions

- ES5+ JavaScript, no transpilation
- camelCase for variables/functions
- 2-space indentation
- Always call `Prism.highlightAll()` after DOM updates
- Maintain Bootstrap tab functionality with jQuery dependency
- Base64URL decoding must normalize padding for cross-browser support

## Commit Style

Concise, imperative messages (e.g., "Add disclosure validation", "Fix Base64 padding")
