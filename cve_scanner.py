# Vulnerability / CVE Scanner
# Grabs service banners from open ports on a host, then checks the detected
# service/version against the NVD (National Vulnerability Database) API for
# known CVEs. Produces a severity-sorted report.
#
# ONLY run this against hosts you own or have explicit permission to scan.

import socket
import re
import time
import json
import logging
import requests

logging.basicConfig(
    filename="cve_scan_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPORT_FILE = "cve_scan_report.json"
REQUEST_DELAY = 6  # NVD's public (no API key) rate limit is strict - stay well under it

findings = []


def grab_banner(host, port, timeout=2):
    # connects to a port and reads whatever the service announces about itself -
    # same socket approach as the Week 1 port scanner, but reading data back
    # instead of just checking open/closed
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # some services (like HTTP) need a nudge before they respond
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except Exception:
            pass

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else None

    except Exception:
        return None


def parse_service_version(banner):
    # very basic extraction - looks for common "Name/Version" or "Name Version" patterns
    # real-world tools (like nmap's service detection) use much larger signature databases;
    # this is a simplified version for learning purposes
    patterns = [
        r"Server:\s*([A-Za-z0-9_\-]+)/?([\d\.]+)?",   # HTTP header style
        r"SSH-[\d\.]+-([A-Za-z0-9_\-]+)[_\s]([\d\.]+)",  # SSH banner style
        r"([A-Za-z0-9_\-]+)/([\d\.]+)",                # generic Name/Version
    ]
    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            name = match.group(1)
            version = match.group(2) if match.lastindex and match.lastindex >= 2 else None
            return name, version
    return None, None


def query_nvd(product, version):
    # queries the public NVD API for CVEs matching this product/version keyword.
    # No API key = strict rate limit, hence the delay between calls.
    search_term = f"{product} {version}" if version else product
    params = {"keywordSearch": search_term, "resultsPerPage": 5}

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        logging.error(f"NVD query failed for '{search_term}': {e}")
        return []


def extract_severity(cve_entry):
    # CVSS data can live in a few different places depending on CVE age -
    # check v3.1 first, fall back to v2
    metrics = cve_entry.get("cve", {}).get("metrics", {})

    if "cvssMetricV31" in metrics:
        score_data = metrics["cvssMetricV31"][0]["cvssData"]
        return score_data["baseScore"], score_data["baseSeverity"]
    elif "cvssMetricV2" in metrics:
        score_data = metrics["cvssMetricV2"][0]["cvssData"]
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        return score_data["baseScore"], severity
    return None, "UNKNOWN"


def scan_port(host, port):
    print(f"\nChecking port {port}...")
    banner = grab_banner(host, port)

    if not banner:
        print(f"  No banner received on port {port} (closed, filtered, or silent service)")
        logging.info(f"Port {port} - no banner")
        return

    print(f"  Banner: {banner[:80]}")
    logging.info(f"Port {port} - banner: {banner[:200]}")

    product, version = parse_service_version(banner)

    if not product:
        print("  Could not parse a service/version from this banner.")
        logging.info(f"Port {port} - banner could not be parsed")
        return

    print(f"  Detected: {product} {version or '(version unknown)'}")
    print("  Querying NVD for known CVEs...")

    time.sleep(REQUEST_DELAY)  # respect rate limits before each API call
    cve_results = query_nvd(product, version)

    if not cve_results:
        print("  No CVE matches found.")
        logging.info(f"Port {port} - {product} {version} - no CVE matches")
        return

    for entry in cve_results:
        cve_id = entry["cve"]["id"]
        description = entry["cve"]["descriptions"][0]["value"]
        score, severity = extract_severity(entry)

        finding = {
            "port": port,
            "service": product,
            "version": version,
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": score,
            "description": description[:200],
        }
        findings.append(finding)
        print(f"  [FOUND] {cve_id} - Severity: {severity} (CVSS {score})")
        logging.info(f"Port {port} - {cve_id} - Severity: {severity} - CVSS {score}")


def save_report():
    # sort by severity so the most urgent findings are at the top - this is
    # the "triage" part of the task in practice
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f["severity"], 4))

    with open(REPORT_FILE, "w") as f:
        json.dump(sorted_findings, f, indent=2)

    print(f"\nReport saved to {REPORT_FILE}")


def run_scan(host, ports):
    print(f"Starting CVE scan on {host}")
    logging.info(f"--- New scan: {host} - ports {ports} ---")

    for port in ports:
        scan_port(host, port)

    print("\n--- Scan complete ---")
    if findings:
        print(f"{len(findings)} potential CVE match(es) found. See {REPORT_FILE} for the full severity-sorted report.")
    else:
        print("No CVE matches found for any detected services.")

    save_report()


if __name__ == "__main__":
    print("=== Vulnerability / CVE Scanner ===")
    print("WARNING: Only run this against hosts you own or have explicit permission to scan.\n")

    target_host = input("Target host/IP: ").strip()
    ports_input = input("Ports to check, comma-separated (e.g., 22,80,443): ").strip()
    ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]

    run_scan(target_host, ports) 