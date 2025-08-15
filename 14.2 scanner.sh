#!/bin/bash
    
write_header() {
    local target="$1"
    echo "------------------------------"
    echo "  Network Security Scan Report  "
    echo "------------------------------"
    echo ""
    echo "Target: $target"
    echo ""
}

write_ports_section() {
    echo "--- Open Ports and Detected Services ---"
    nmap -sV "$TARGET" | grep "open"
    echo ""
}

write_vulns_section() {
    echo "--- Potential Vulnerabilities Identified ---"
    # Run nmap with version detection and vuln scripts
    SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET")
    # Grep for high-confidence vulnerabilities
    VULN_FOUND=$(echo "$SCAN_RESULTS" | grep "VULNERABLE")
    if [ -n "$VULN_FOUND" ]; then
        echo "$VULN_FOUND"
    else
        echo "No high-confidence vulnerabilities found by NSE scripts."
    fi
    echo ""

    # --- Service Version Parsing and NVD Query ---
    echo "$SCAN_RESULTS" | grep -Eo '^[0-9]+/tcp[ ]+open[ ]+[a-zA-Z0-9_-]+[ ]+[^ ]+[ ]+[^ ]+[ ]+.*' | while read -r line; do
        # Example line: 22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
        # Extract product and version using regex
        product_name=$(echo "$line" | awk '{for(i=4;i<=NF;i++){if($i ~ /^[A-Za-z0-9._-]+$/){print $i; exit}}}')
        product_version=$(echo "$line" | awk '{for(i=5;i<=NF;i++){if($i ~ /^[0-9][A-Za-z0-9._-]+$/){print $i; exit}}}')
        # Only query if both are found
        if [ -n "$product_name" ] && [ -n "$product_version" ]; then
            query_nvd "$product_name" "$product_version"
        fi
    done
    echo ""
}
query_nvd() {
    local product="$1"
    local version="$2"
    local results_limit=3
    echo
    echo "Querying NVD for vulnerabilities in: $product $version..."
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"
    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")
    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD. The API might be down or unreachable."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang==\"en\")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'
}

write_recs_section() {
    echo "--- Recommendations for Remediation ---"
    echo "1. Update all software and operating systems to the latest versions."
    echo "2. Change default credentials on all services immediately."
    echo "3. Implement and configure a firewall to restrict unnecessary access."
    echo "4. Conduct regular vulnerability scanning and penetration testing."
    echo ""
}

write_footer() {
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "--- End of Report ---"
    echo "Report Generated on: $timestamp"
}

main() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <target_ip_or_hostname>" >&2
        exit 1
    fi

    local TARGET="$1"
    local REPORT_FILE="network_security_report.txt"

    write_header "$TARGET" > "$REPORT_FILE"
    write_ports_section >> "$REPORT_FILE"
    write_vulns_section >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"

}

main "$@"
