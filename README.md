# JwtPal.com - Java Web Token (JWT) Decoder
[JwtPal.com](https://jwtpal.com) is a lightweight JSON Web Token (JWT) decoder/debugger for OAuth2, OpenID Connect (OIDC), and custom authorization flows. This repository hosts the static site that powers the tool.

## Quick Usage
1. Paste a JWT into the **Encoded** text area. JwtPal immediately decodes the header, payload, and signature and surfaces validation errors inline.
2. Load ready-made examples with the **Samples** buttons: **JWT** inserts a classic signed JWT, while **SD-JWT** inserts a selective disclosure token (with disclosures and optional key-binding).
3. Use the **Clear** button to reset the encoded input and switch the payload view back to the JWT tab.
4. Use the payload tabs to switch views: **JWT** shows the decoded payload, and **SD-JWT** shows disclosure details plus any key-binding JWT. The SD-JWT tab stays disabled until a token with an SD-JWT `typ` header is detected (e.g. `"typ": "sd+jwt"`).
5. Share a token by appending it to the URL: `https://jwtpal.com?jwt=a.b.c`. The alternate `?token=` parameter is also supported for compatibility with legacy tooling.
6. Use the automatically generated “Share” link to re-open the same token view without re-entering data. No tokens are persisted on the server.

## Understanding JWTs in OAuth2 & Authorization
- **Access tokens** prove authorization to APIs. Ensure `aud` matches the resource server and expiration (`exp`) is short-lived; JwtPal highlights missing recommended claims so you can verify issuer policies.
- **ID tokens** (OIDC) assert user identity to a relying party. Look for `nonce`, `at_hash`, and profile claims (`email`, `name`, etc.) to confirm that the identity provider followed the spec.
- **Client credentials vs. authorization code**: tokens minted via client credentials often omit user-centric claims; JwtPal’s “Missing Claims” summary calls this out so you can determine if impersonation is happening.
- Always validate signatures and issuer metadata in your application. JwtPal intentionally does not verify cryptographic signatures; treat it as an inspection aid, not a trust boundary.

## Troubleshooting & Best Practices
- **Expired tokens**: The summary panel displays `expired: true/false` plus ISO timestamps, making clock-skew debugging easier.
- **Base64 parsing errors**: If you see “Token header/payload is not properly Base64 encoded,” confirm padding (`=`) and URL-safe characters (`-`, `_`) are used correctly.
- **SD-JWT disclosures**: If the SD-JWT tab shows warnings, confirm the token includes disclosures after the main JWT and that the `_sd` digests match. Missing or malformed disclosures show warning banners in the SD-JWT pane.
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
