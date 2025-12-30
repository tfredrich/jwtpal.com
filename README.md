# JwtPal.com - Java Web Token (JWT) Decoder
[JwtPal.com](https://jwtpal.com) is a lightweight JSON Web Token (JWT) decoder/debugger for OAuth2, OpenID Connect (OIDC), and custom authorization flows. This repository hosts the static site that powers the tool.

## Quick Usage
1. Paste a JWT into the **Encoded** text area. JwtPal immediately decodes the header, payload, and signature and surfaces validation errors inline.
2. Toggle between valid, malformed, and sample tokens with the **Sample** and **Clear** buttons to understand how different inputs affect claims.
3. Share a token by appending it to the URL: `https://jwtpal.com?jwt=a.b.c`. The alternate `?token=` parameter is also supported for compatibility with legacy tooling.
4. Use the automatically generated “Share” link to re-open the same token view without re-entering data. No tokens are persisted on the server.

## Understanding JWTs in OAuth2 & Authorization
- **Access tokens** prove authorization to APIs. Ensure `aud` matches the resource server and expiration (`exp`) is short-lived; JwtPal highlights missing recommended claims so you can verify issuer policies.
- **ID tokens** (OIDC) assert user identity to a relying party. Look for `nonce`, `at_hash`, and profile claims (`email`, `name`, etc.) to confirm that the identity provider followed the spec.
- **Client credentials vs. authorization code**: tokens minted via client credentials often omit user-centric claims; JwtPal’s “Missing Claims” summary calls this out so you can determine if impersonation is happening.
- Always validate signatures and issuer metadata in your application. JwtPal intentionally does not verify cryptographic signatures; treat it as an inspection aid, not a trust boundary.

## Troubleshooting & Best Practices
- **Expired tokens**: The summary panel displays `expired: true/false` plus ISO timestamps, making clock-skew debugging easier.
- **Base64 parsing errors**: If you see “Token header/payload is not properly Base64 encoded,” confirm padding (`=`) and URL-safe characters (`-`, `_`) are used correctly.
- **Missing custom claims**: Organization-specific claims can be added manually after decoding; JwtPal will show them immediately, letting you confirm case sensitivity and nesting.
- **Security reminder**: Avoid pasting production tokens that carry sensitive scopes unless you’re comfortable sharing them with your current browser context. JwtPal never uploads data, but your local clipboard and history might.

## Local Development
```bash
python3 -m http.server 8080
open http://localhost:8080/index.html   # macOS; use xdg-open on Linux
```
The site is pure HTML/CSS/JS located under `index.html` and `lib/`. Update `lib/token.js` for decoder logic and `lib/style.css` for layout adjustments. Pull requests should describe manual test steps (valid token, malformed token, query-string load) and link any relevant OAuth2/OIDC specs influencing the change.

## Contributing
See `AGENTS.md` for full contributor expectations, including repo structure details, coding style, and pull request checklists. Review it before opening issues or submitting patches.
