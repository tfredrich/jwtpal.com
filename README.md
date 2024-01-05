# jwtpal.com
Source code for the [JwtPal.com](https://jwtpal.com) JSON Web Token (JWT) decoder/debugger site.

Usage:

1. Paste a JSON Web Token into the 'Encoded' text area. The 'Decoded' section will be populated with the token data, if successful. Otherwise, an error will be shown.
1. Use the query-string parameter to link to [JwtPal.com?jwt=a.b.c](https://JwtPal.com?jwt=a.b.c) (where a.b.c is the JWT token) to automatically parse the token in the query-string.
    1. The query-string paramer 'token' works as well as 'jwt' to maintain compatibility with *some other* JWT tools (e.g. [JwtPal.com?token=a.b.c](https://JwtPal.com?token=a.b.c)).