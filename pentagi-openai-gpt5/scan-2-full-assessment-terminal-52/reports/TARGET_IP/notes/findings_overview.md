# Findings Overview

## 1. HTTP-only Service (No HTTPS/HSTS)
- **Affected Host/Port/Endpoint:** <TARGET_IP>:80 `/`
- **Severity:** High
- **Status:** Confirmed
- **Description:** Service does not enforce HTTPS or HSTS. All traffic on HTTP unencrypted and redirects to HTTPS absent.
- **Commands Executed:**
  ```bash
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sSI http://<TARGET_IP>/ | tee evidence/confirmed/http80_headers_${ts}.txt
  ts=$(date -u +%Y%m%dT%H%M%SZ); (curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sSI https://<TARGET_IP>/ || true) 2>&1 | tee evidence/confirmed/https443_probe_${ts}.txt
  ```
- **Evidence Files:**
  - `evidence/confirmed/http80_headers_*.txt`
  - `evidence/confirmed/https443_probe_*.txt`

## 2. Exposed Debug/Operational Endpoints (Unauthenticated)
- **Affected Host/Port/Endpoint:** <TARGET_IP>:8080 `/debug/vars`, `/debug/pprof/`, `/metrics`
- **Severity:** Medium
- **Status:** Confirmed
- **Description:** Unauthenticated access to debug and metrics endpoints exposes internals.
- **Commands Executed:**
  ```bash
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -i http://<TARGET_IP>:8080/debug/vars | tee evidence/confirmed/port8080_debug_vars_${ts}.txt
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sSI http://<TARGET_IP>:8080/debug/pprof/ | tee evidence/confirmed/port8080_debug_pprof_headers_${ts}.txt
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sSI http://<TARGET_IP>:8080/metrics | tee evidence/confirmed/port8080_metrics_headers_${ts}.txt
  ```
- **Evidence Files:**
  - `evidence/confirmed/port8080_debug_vars_*.txt`
  - `evidence/confirmed/port8080_debug_pprof_headers_*.txt`
  - `evidence/confirmed/port8080_metrics_headers_*.txt`

## 3. Insecure Session/Token Handling
- **Affected Host/Port/Endpoint:** <TARGET_IP>:80 `/` and JS assets
- **Severity:** Medium
- **Status:** Confirmed
- **Description:** Cookies lack Secure, HttpOnly, SameSite flags; JS assets store tokens in localStorage and use Authorization Bearer headers.
- **Commands Executed:**
  ```bash
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sSI http://<TARGET_IP>/ | tee evidence/confirmed/port80_headers_for_cookies_${ts}.txt
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sS http://<TARGET_IP>/assets/main.js -o evidence/confirmed/port80_main_js_${ts}.js
  ts=$(date -u +%Y%m%dT%H%M%SZ); curl -v --max-time 5 --connect-timeout 5 --fail-with-body --ipv4 -sS http://<TARGET_IP>/assets/vendor.js -o evidence/confirmed/port80_vendor_js_${ts}.js
  grep -nE "localStorage|sessionStorage|Authorization|Bearer|jwt|document.cookie" evidence/confirmed/port80_*_js_*.js | tee evidence/confirmed/js_token_storage_matches_${ts}.txt
  ```
- **Evidence Files:**
  - `evidence/confirmed/port80_headers_for_cookies_*.txt`
  - `evidence/confirmed/port80_main_js_*.js`
  - `evidence/confirmed/port80_vendor_js_*.js`
  - `evidence/confirmed/js_token_storage_matches_*.txt`
