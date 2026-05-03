
import re
import json
import sys

nmap_input_file = '/work/reports/<TARGET_IP>_gemini/evidence/nmap_scan_results.nmap'
output_json_file = '/work/reports/<TARGET_IP>_gemini/evidence/parsed_services.json'

parsed_services = []
host_address = ""

try:
    with open(nmap_input_file, 'r') as f:
        nmap_output = f.readlines()
except FileNotFoundError:
    print(f"Error: Nmap input file not found at {nmap_input_file}", file=sys.stderr)
    sys.exit(1)
except IOError:
    print(f"Error: Could not read Nmap input file at {nmap_input_file}", file=sys.stderr)
    sys.exit(1)

# Regex to find host IP address
host_match = re.search(r'Nmap scan report for .*?\((.*?)\)', nmap_output[1] if len(nmap_output) > 1 else "")
if host_match:
    host_address = host_match.group(1)

for line in nmap_output:
    # Regex to parse service lines
    match = re.match(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$', line.strip())
    if match:
        portid = match.group(1)
        service_name = match.group(2)
        version_info = match.group(3).strip()

        product = ""
        version = ""
        extrainfo = ""

        # Attempt to parse product and version from version_info
        version_match = re.match(r'^([a-zA-Z0-9\s\.\-]+?)(?:\s([0-9\.\-]+))?(?:\s(.*))?$', version_info)
        if version_match:
            product = version_match.group(1).strip() if version_match.group(1) else ""
            version = version_match.group(2).strip() if version_match.group(2) else ""
            extrainfo = version_match.group(3).strip() if version_match.group(3) else ""

        service_info = {
            'port': int(portid),
            'protocol': 'tcp',
            'name': service_name,
            'product': product,
            'version': version,
            'extrainfo': extrainfo
        }

        # Filter for specific services/ports
        if (portid == '80' and service_name == 'http') or \
           (portid == '8080' and service_name == 'http') or \
           (portid == '22' and service_name == 'ssh'):
            parsed_services.append({
                'host': host_address,
                'service': service_info
            })

try:
    with open(output_json_file, 'w') as f:
        json.dump(parsed_services, f, indent=4)
    print(f"Successfully parsed Nmap results and saved to {output_json_file}")
except IOError:
    print(f"Error: Could not write to output JSON file at {output_json_file}", file=sys.stderr)
    sys.exit(1)
