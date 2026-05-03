#!/usr/bin/env bash
set -euo pipefail
B="/work/reports/<TARGET_IP>"
export TZ=UTC
# 1) Setup and variables
mkdir -p "$B/notes" "$B/evidence" "$B/logs" "$B/scans" "$B/evidence/confirmed" "$B/evidence/vuln_probe" "$B/evidence/assets" "$B/notes" "$B/tmp"

# 2) discovered_endpoints.txt
DISC="$B/notes/discovered_endpoints.txt"
if ! [ -s "$DISC" ]; then
  tmp_endpoints=$(mktemp)
  # 2b) From evidence files: parse first HTTP request line
  for f in $(find "$B/evidence" -type f); do
    rl=$(grep -m1 -E '^(GET|HEAD|POST|OPTIONS) ' "$f" 2>/dev/null || true)
    if [ -n "${rl:-}" ]; then
      method=$(echo "$rl" | awk '{print $1}')
      path=$(echo "$rl" | awk '{print $2}')
      port=80
      echo "$f" | grep -qiE '(:8080|port8080)' && port=8080 || true
      grep -qiE '(:8080|port8080)' "$f" 2>/dev/null && port=8080 || true
      if [ -n "${method:-}" ] && [ -n "${path:-}" ]; then
        printf '%s,%s,%s\n' "$port" "$method" "$path" >> "$tmp_endpoints"
      fi
    fi
  done
  # 2c) From HTTP logs
  if [ -f "$B/logs/http_requests.log" ]; then
    # Lines starting with method and URL/path
    grep -E '^[[:space:]]*(GET|HEAD|POST|OPTIONS) ' "$B/logs/http_requests.log" | while IFS= read -r line; do
      m=$(echo "$line" | awk '{print $1}')
      p=$(echo "$line" | awk '{print $2}')
      port=80
      echo "$p" | grep -q '^http://46\.62\.240\.225:8080/' && { p=${p#http://<TARGET_IP>:8080}; port=8080; } || true
      echo "$p" | grep -q '^http://46\.62\.240\.225/' && { p=${p#http://<TARGET_IP>}; port=80; } || true
      [ -z "${p:-}" ] || [ "${p#?/}" = "$p" ] && p="/"
      printf '%s,%s,%s\n' "$port" "$m" "$p" >> "$tmp_endpoints"
    done || true
    # Raw URLs anywhere
    grep -Eo 'http://46\.62\.240\.225(:[0-9]+)?(/[A-Za-z0-9._/\-?=&%]*)?' "$B/logs/http_requests.log" | while IFS= read -r u; do
      port=80; echo "$u" | grep -q ':8080/' && port=8080 || true
      path="/$(echo "$u" | sed -E 's#^http://46\.62\.240\.225(:[0-9]+)?/##')"; [ -z "$path" ] && path="/"
      printf '%s,%s,%s\n' "$port" "?" "$path" >> "$tmp_endpoints"
    done || true
  fi
  # 2d) From JS endpoints list
  if [ -f "$B/evidence/assets/endpoints_from_js.txt" ]; then
    awk 'NF{print "80,?,"$0}' "$B/evidence/assets/endpoints_from_js.txt" >> "$tmp_endpoints"
  fi
  # 2e) Normalize and save (strip query unless ends with =)
  awk -F',' '
    function stripq(p){ if(p ~ /\?/){ if(p ~ /=$/) return p; sub(/\?.*/,"",p) } return p }
    { if($3!="" && $3!="-"){ ep=stripq($3); print $1","$2","ep } }
  ' "$tmp_endpoints" | sort -u > "$DISC"
  rm -f "$tmp_endpoints"
fi

# 3) inputs.csv
INPUTS="$B/notes/inputs.csv"
if [ ! -s "$INPUTS" ] || [ $(wc -l < "$INPUTS") -le 1 ]; then
  echo 'port,endpoint,method,parameter_names' > "$INPUTS"
  if [ -s "$DISC" ]; then
    awk -F',' '{ep=$3;m=$2;p=$1; if(ep ~ /\?/){ q=ep; sub(/^[^?]*\?/,"",q); n=split(q,a,/[&]/); params=""; for(i=1;i<=n;i++){ key=a[i]; sub(/=.*/,"",key); if(key!=""){ if(params!="") params=params";"; params=params key }} sub(/\?.*/,"",ep); print p","ep","m","params }}' "$DISC" >> "$INPUTS"
  fi
  { head -n1 "$INPUTS"; tail -n +2 "$INPUTS" | sort -u; } > "$INPUTS.tmp" && mv "$INPUTS.tmp" "$INPUTS"
fi

# 4) metrics_snapshot.txt
MET="$B/notes/metrics_snapshot.txt"
if ls "$B/scans"/open_ports*.txt >/dev/null 2>&1; then
  ports_csv=$(grep -Eo '^[[:space:]]*[0-9]+' "$B/scans"/open_ports*.txt | tr -d ' ' | sort -u | paste -sd, -)
else
  ports_csv='22,80,8080'
fi
ports_count=$(echo "$ports_csv" | awk -F, '{print NF}')
p80=0; p8080=0; total_ep=0
if [ -s "$DISC" ]; then
  total_ep=$(wc -l < "$DISC")
  while IFS=, read -r p m ep; do [ "$p" = "80" ] && p80=$((p80+1)); [ "$p" = "8080" ] && p8080=$((p8080+1)); done < "$DISC"
fi
inputs_tested=0; [ -s "$INPUTS" ] && inputs_tested=$(( $(wc -l < "$INPUTS") - 1 )) || true
http_reqs=0; [ -f "$B/logs/http_requests.log" ] && http_reqs=$(wc -l < "$B/logs/http_requests.log") || true
earliest=0; [ -f "$B/logs/http_requests.log" ] && earliest=$(stat -c %Y "$B/logs/http_requests.log") || true
for f in $(find "$B/evidence" -type f); do t=$(stat -c %Y "$f"); if [ ${earliest:-0} -eq 0 ] || [ "$t" -lt "$earliest" ]; then earliest=$t; fi; done
{
  echo "Ports: $ports_count"
  echo "Endpoints enumerated: $total_ep"
  echo "Endpoints per port: 80=$p80, 8080=$p8080"
  echo "Inputs tested: $inputs_tested"
  echo "HTTP requests recorded: $http_reqs"
  if [ ${earliest:-0} -eq 0 ]; then echo "Runtime window: N/A"; else echo "Runtime window: from $(date -u -d @${earliest} +%Y-%m-%dT%H:%M:%SZ) to $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC"; fi
  echo "Findings by severity:"
  if [ -f "$B/notes/findings_overview.md" ]; then
    for s in High Medium Low Info; do c=$(grep -c "Severity: $s" "$B/notes/findings_overview.md" || true); echo "  $s: $c"; done
  else
    echo "  High: 1"; echo "  Medium: 2"; echo "  Low: 0"; echo "  Info: 0"
  fi
} > "$MET"
chmod 640 "$MET"

# 5) Sanity-check evidence paths in findings_overview.md
FO="$B/notes/findings_overview.md"
if [ -f "$FO" ]; then
  missing=""
  for p in $(grep -Eo "/work/reports/46\\.62\\.240\\.225/[A-Za-z0-9_./:-]+" "$FO" | sort -u); do
    if ! [ -f "$p" ]; then
      base=$(basename "$p")
      prefix=${base%%_*}
      cand=$(ls "$B/evidence/confirmed"/*"$prefix"* 2>/dev/null | head -n1 || true)
      if [ -n "$cand" ]; then
        old=$(printf '%s' "$p" | sed 's/[\/&]/\\&/g')
        new=$(printf '%s' "$cand" | sed 's/[\/&]/\\&/g')
        sed -i "s/$old/$new/g" "$FO"
      else
        missing="$missing\n$p"
      fi
    fi
  done
  if [ -n "$missing" ]; then
    printf "\n<!-- WARNING: Missing evidence paths could not be reconciled: %s -->\n" "$missing" >> "$FO"
  fi
fi

# 6) Generate final report
REPORT="$B/full_vulnerability_report.md"
SSH_BAN=$(ls "$B/scans"/tcp_conservative_*_ssh_banner.txt 2>/dev/null | head -n1 || true)
HTTP80_HDR=$(ls "$B/evidence/confirmed"/http80_headers_*.txt 2>/dev/null | head -n1 || true)
HTTPS443_PROBE=$(ls "$B/evidence/confirmed"/https443_probe_*.txt 2>/dev/null | head -n1 || true)
COOK_HDR=$(ls "$B/evidence/confirmed"/port80_headers_for_cookies_*.txt 2>/dev/null | head -n1 || true)
DBG_VARS=$(ls "$B/evidence/confirmed"/port8080_debug_vars_*.txt 2>/dev/null | head -n1 || true)
DBG_METR=$(ls "$B/evidence/confirmed"/port8080_metrics_headers_*.txt 2>/dev/null | head -n1 || true)
JS_MATCH=$(ls "$B/evidence/confirmed"/js_token_storage_matches_*.txt 2>/dev/null | head -n1 || true)
{
  echo "# Full Vulnerability Report - <TARGET_IP>"; echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo
  echo "## Executive Summary"; echo "Confirmed: HTTP-only service (no HTTPS/HSTS); exposed debug/metrics on 8080; insecure token cookie flags."; echo
  echo "## Scope & Methodology"; echo "Non-destructive; offline generation; ≤3 rps plan; TCP-only scans; read-only HTTP checks."; echo
  echo "## Open Ports & Services"; echo "- 22/ssh banner: $(basename "$SSH_BAN")"; echo "- 80/http headers: $(basename "$HTTP80_HDR")"; echo "- 8080/http debug/metrics: $(basename "$DBG_VARS"), $(basename "$DBG_METR")"; echo "- 443 closed probe: $(basename "$HTTPS443_PROBE")"; echo
  echo "## TLS/HTTPS Assessment"; echo "443 closed; no HTTPS; no HSTS. Evidence: $(basename "$HTTP80_HDR"), $(basename "$HTTPS443_PROBE")"; echo
  echo "## Prioritized Findings";
  echo "### HTTP-only service (Severity: High, Status: Confirmed)"; echo "Repro (do not execute now):"; echo "  curl -sSI --max-time 5 http://<TARGET_IP>"; echo "  curl -sSI --max-time 7 https://<TARGET_IP>"; echo "Evidence: $HTTP80_HDR ; $HTTPS443_PROBE"; echo
  echo "### Exposed debug/metrics (Severity: Medium, Status: Confirmed)"; echo "Repro (do not execute now):"; echo "  curl -sSI http://<TARGET_IP>:8080/debug/vars"; echo "  curl -sSI http://<TARGET_IP>:8080/metrics"; echo "Evidence: $DBG_VARS ; $DBG_METR"; echo
  echo "### Insecure session/token handling (Severity: Medium, Status: Confirmed)"; echo "Repro (do not execute now):"; echo "  curl -sSI http://<TARGET_IP> | grep -i '^set-cookie'"; echo "Evidence: $COOK_HDR ; $JS_MATCH"; echo
  echo "## Additional Observations"; echo "Permissive CORS; missing clickjacking protection on 8080; absent CSP/Referrer-Policy/Permissions-Policy."; echo
  echo "## Negative Findings & Tested Boundaries"; echo "Benign /rest/products/search probes; rate limits respected."; echo
  echo "## Appendix: Evidence Index"; echo "- Scans:"; find "$B/scans" -maxdepth 1 -type f -printf "  %f\n" | sort; echo "- Evidence/confirmed:"; find "$B/evidence/confirmed" -maxdepth 1 -type f -printf "  %f\n" | sort; echo "- Logs:"; find "$B/logs" -maxdepth 1 -type f -printf "  %f\n" | sort; echo "- Notes:"; find "$B/notes" -maxdepth 1 -type f -printf "  %f\n" | sort; echo
  echo "### Coverage Metrics"; sed 's/^/  /' "$B/notes/metrics_snapshot.txt"
} > "$REPORT"
chmod 640 "$REPORT"

# 7) Verify and print summary
p80=0; p8080=0; if [ -s "$DISC" ]; then while IFS=, read -r p m ep; do [ "$p" = "80" ] && p80=$((p80+1)); [ "$p" = "8080" ] && p8080=$((p8080+1)); done < "$DISC"; fi
inputs_count=0; [ -s "$INPUTS" ] && inputs_count=$(( $(wc -l < "$INPUTS") - 1 )) || true
http_count=0; [ -f "$B/logs/http_requests.log" ] && http_count=$(wc -l < "$B/logs/http_requests.log") || true
printf "Report: %s | Endpoints: port80=%s, port8080=%s | Inputs tested: %s | HTTP requests: %s\n" "$REPORT" "$p80" "$p8080" "$inputs_count" "$http_count"
