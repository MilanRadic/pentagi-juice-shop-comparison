# Assessment Workspace for <TARGET_IP>

Scope
- Target host: <TARGET_IP>
- Initial tasks: environment prep, reachability verification, baseline enumeration (non-destructive)

Safety Constraints
- Non-destructive testing only
- Rate limiting: ~5 requests/second cap (stricter pacing used during setup)
- No DoS, stress testing, or aggressive brute-force
- Minimal exploitation strictly for verification; avoid data modification

Logging Locations
- All logs: /work/reports/<TARGET_IP>/logs/
- Evidence (screens/outputs): /work/reports/<TARGET_IP>/evidence/
- Notes and findings: /work/reports/<TARGET_IP>/notes/
- Scan artifacts: /work/reports/<TARGET_IP>/scans/
- Temporary files: /work/reports/<TARGET_IP>/tmp/

Permissions
- Directories: 750; Files: 640 (adjust if collaboration requires broader read access)
