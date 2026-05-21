# Repository Guidelines

## Project Structure & Module Organization
- `index.html` contains the single-page JWT, SD-JWT, and OAuth2 PKCE playground markup plus static asset references.
- `lib/playground.js` hosts shared DOM wiring, theme handling, copy helpers, URL preload logic, and version display.
- `lib/playground-jwt.js` hosts JWT decoding, encoding, signature verification, and claim compliance behavior.
- `lib/playground-sdjwt.js` hosts SD-JWT decoding, disclosure display, and SD-JWT example building.
- `lib/playground-oauth.js` hosts OAuth2 PKCE parameter generation and authorization/token request helpers.
- `lib/playground-style.css` defines theming and layout; keep shared variables and breakpoint rules near the top for quick tuning.
- `img/` holds logos and icons referenced by `index.html`; favicon variations live at the repo root for host compatibility.
- `blob.jwt` is a ready-made [large] token payload; use it for regression checks before shipping changes.

## Build, Test, and Development Commands
- `python3 -m http.server 8080` (from repo root) serves the static site locally so callbacks and query-string parsing work reliably.
- `open http://localhost:8080/index.html` (macOS) or `xdg-open ...` opens the preview in your default browser.
- `npm install --global prettier` followed by `prettier --write lib/*.js lib/*.css` formats assets consistently when touching larger sections.

## Coding Style & Naming Conventions
- JavaScript is ES5+/DOM-centric with `const`/`let`, camelCase functions (e.g., `decodeJWT`), and early returns for validation.
- Favor two-space indentation in JS and CSS to match the current files; keep long object literals vertically aligned for readability.
- Avoid introducing bundlers or frameworks—keep dependencies lightweight and rely on CDN imports already in `index.html`.
- Reference elements via IDs (`#decode-input`, `#sd-input`, `#version-stamp`) to stay consistent with existing selectors and event bindings.

## Testing Guidelines
- No automated test harness exists; run manual scenarios that cover valid/invalid Base64, missing claims, and sample token shortcuts.
- Verify query-string support (`?jwt=` and `?token=`) with pasted URLs while serving locally.
- Test JWT decode/encode, SD-JWT decode/build, OAuth2 PKCE generation, `atob`, and clipboard behavior across at least Chrome and Firefox.

## Commit & Pull Request Guidelines
- Follow the established concise, imperative commit style (`Added logo in header`, `Introduced smaller version of logo`); keep titles under ~60 chars.
- Reference linked issues in the PR description, summarize UI or decoding changes, and attach screenshots/gifs when altering layout.
- Ensure PRs mention manual test steps executed (e.g., “decoded malformed payload shows error banner”) so reviewers can reproduce quickly.

## Security & Configuration Tips
- Never log or persist submitted JWTs; keep debug statements out of playground scripts.
- Validate any third-party library upgrades against CDN integrity attributes before pushing to production.
