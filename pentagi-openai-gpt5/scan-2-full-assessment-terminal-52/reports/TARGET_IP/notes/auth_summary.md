Authentication Surface Assessment Summary (UTC)

Timestamp (UTC): 2026-02-14T10:22:56Z

Scope Host: <TARGET_IP>

1) Discovered authentication endpoints on port 80
- /rest/user/login: HTTP method HEAD -> 405 Method Not Allowed (as observed)
- /rest/user/whoami: HTTP method GET -> 401 Unauthorized (as observed)

2) Baseline cookies from GET / on port 80
- Observed a token cookie present.
- Security flags: Secure = absent, HttpOnly = absent, SameSite = absent.
- Note: Lack of these flags increases risk of token exposure via mixed content, client-side scripts, and CSRF.

3) CSRF indicators
- No CSRF tokens observed in headers or bodies for login-related responses.
- No anti-CSRF mechanisms (e.g., CSRF cookie with double-submit pattern) detected in baseline traffic.

4) Rate-limit sanity check on /rest/user/login
- Three invalid JSON login attempts, spaced ≥1 second each.
- Consistent response: 400 Bad Request.
- No evidence of throttling or lockout: no 429 responses and no account lock indications.
- No Set-Cookie changes across attempts (session state appears unchanged for invalid attempts).

5) Port 8080 authentication banners
- HEAD / and GET / both return 200 OK.
- No WWW-Authenticate header presented.

6) JavaScript token storage analysis
- Assets not found under /work/reports/<TARGET_IP>/evidence/assets/port80_*.js at time of analysis; analysis deferred.
- Next step: (re)download SPA JavaScript assets from port 80 and re-run the grep workflow.
- Reference path for future matches: /work/reports/<TARGET_IP>/evidence/auth/js_token_storage_matches.txt

7) Reference evidence files (as currently present)
- /work/reports/<TARGET_IP>/evidence/auth/js_token_storage_matches.txt
- /work/reports/<TARGET_IP>/evidence/auth/test_auth_write_20260214_102001.txt

Notes
- This summary consolidates observations from prior non-destructive checks and baseline HTTP interactions.
- Further testing will continue to respect safety constraints (≤ ~1 req/sec during manual probing for auth flows).
