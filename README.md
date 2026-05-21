# JwtPal.com - JSON Web Token (JWT) Playground
[JwtPal.com](https://jwtpal.com) is a lightweight JSON Web Token (JWT) decoder/debugger for OAuth2, OpenID Connect (OIDC), and custom authorization flows. This repository hosts the static site that powers the tool.

## Quick Usage
1. Paste a JWT into the **JWT > Decode** input. JwtPal decodes the header, payload, signature metadata, and claim compliance details in the browser.
2. Use **JWT > Encode** to build unsigned, HMAC, RSA, or ECDSA test tokens from editable JSON.
3. Use **SD-JWT > Decode** to inspect issuer JWTs, disclosures, holder-binding JWTs, and disclosed claims.
4. Use **SD-JWT > Encode** to build local SD-JWT examples with selectively disclosed claims.
5. Use **OAuth2 PKCE** to generate verifier/challenge/state/nonce values and assemble authorization and token request details.
6. Share a token by appending it to the URL: `https://jwtpal.com?jwt=a.b.c`. The alternate `?token=` parameter is also supported for compatibility with legacy tooling.

## Understanding JWTs in OAuth2 & Authorization
- **Access tokens** prove authorization to APIs. Ensure `aud` matches the resource server and expiration (`exp`) is short-lived; JwtPal highlights missing recommended claims so you can verify issuer policies.
- **ID tokens** (OIDC) assert user identity to a relying party. Look for `nonce`, `at_hash`, and profile claims (`email`, `name`, etc.) to confirm that the identity provider followed the spec.
- **Client credentials vs. authorization code**: tokens minted via client credentials often omit user-centric claims; JwtPal’s “Missing Claims” summary calls this out so you can determine if impersonation is happening.
- Always validate signatures and issuer metadata in your application. JwtPal can perform local signature checks for supported algorithms, but it remains an inspection aid, not a trust boundary.

## Troubleshooting & Best Practices
- **Expired tokens**: The decode view displays `iat` and `exp` timestamps with status badges to make clock-skew debugging easier.
- **Base64 parsing errors**: If a header or payload cannot be decoded, confirm padding (`=`) and URL-safe characters (`-`, `_`) are used correctly.
- **SD-JWT disclosures**: Confirm the token includes disclosures after the issuer JWT and that the final segment is only a holder-binding JWT when intended.
- **Missing claims**: Claim compliance can be viewed as bearer JWT, access token, or ID token guidance.
- **Security reminder**: Avoid pasting production tokens that carry sensitive scopes unless you’re comfortable sharing them with your current browser context. JwtPal never uploads data, but your local clipboard and history might.

## Local Development
```bash
python3 -m http.server 8080
open http://localhost:8080/index.html   # macOS; use xdg-open on Linux
```
The site is pure HTML/CSS/JS located under `index.html` and `lib/`. Update `lib/playground-jwt.js` for JWT behavior, `lib/playground-sdjwt.js` for SD-JWT behavior, `lib/playground-oauth.js` for PKCE/OAuth helpers, `lib/playground.js` for shared UI wiring, and `lib/playground-style.css` for layout and theming. Pull requests should describe manual test steps such as valid token decode, malformed token handling, query-string load, SD-JWT examples, and PKCE generation.

## Contributing
See `AGENTS.md` for full contributor expectations, including repo structure details, coding style, and pull request checklists. Review it before opening issues or submitting patches.
