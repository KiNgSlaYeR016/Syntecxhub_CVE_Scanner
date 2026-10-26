# Vulnerability / CVE Scanner

A Python-based vulnerability scanner built as part of my Syntecxhub Cybersecurity internship (Week 4 task). It grabs service banners from open ports on a target, identifies the running service and version, and checks that against the official NVD (National Vulnerability Database) API for known CVEs, producing a severity-sorted report.

## What it does
For each port given, the scanner connects and grabs whatever banner the service announces about itself (e.g., an SSH version string, an HTTP server header), extracts a product name and version from it, then queries the NVD API for matching CVEs. Any matches are collected into a report sorted by severity, so the most urgent findings are easy to spot first.

## Features
- Banner grabbing on any given port (builds on the socket approach from my Week 1 Port Scanner)
- Basic service/version parsing from common banner formats (HTTP headers, SSH version strings)
- Live queries against the real NVD CVE API - not a mocked or local dataset
- Severity-sorted JSON report (Critical → High → Medium → Low → Unknown)
- Rate-limit-aware delay between API calls, since NVD's public (no API key) access is strictly limited
- Full scan logging, including ports with no banner or no CVE matches

## Technologies used
- Python 3
- `socket` - banner grabbing
- `requests` - querying the NVD REST API
- `re` - extracting product/version from raw banner text
- `json` - structured report output
- `logging` - persistent scan activity log

## How it works
The scanner connects to each target port the same way the Week 1 port scanner checks if a port is open, but here it also reads back whatever data the service sends in response - many services announce their own name and version unprompted (SSH does this immediately on connection; HTTP servers often do it in response to a basic request). That banner text is parsed with a few regex patterns to pull out a product name and version number. That information is then used as a search term against the NVD API, which returns any CVEs associated with that keyword, along with CVSS severity scores. Results are sorted by severity before being saved, so triage priority is immediately visible rather than requiring manual sorting.

## How to run
Install dependency:
```bash
pip install requests
```
Run:
```bash
python cve_scanner.py
```
When prompted:  Target host/IP: <your permitted target>
Ports to check, comma-separated: 22,80


## Responsible disclosure and triage basics
This task specifically asked to cover these concepts, so documenting them here rather than treating this as just a coding exercise:

**Responsible disclosure** is the practice of privately reporting a discovered vulnerability to the organization responsible for it, giving them reasonable time to fix it before any public disclosure. The general flow looks like: report the finding privately (often via a security contact email or a bug bounty platform) → the organization investigates and develops a fix → a disclosure timeline is agreed (commonly 30–90 days) → the vulnerability is disclosed publicly only after a fix is available, or after the agreed timeline passes. The goal is giving defenders a real chance to patch before attackers can learn about and exploit the flaw. Scanning or testing a system without authorization, even with good intentions - is not responsible disclosure and can be illegal; authorization has to come first.

**Triage basics** means not treating every finding as equally urgent. A few practical factors that drive real-world triage priority:
- **CVSS severity score** - the primary signal this scanner sorts by (Critical/High findings get addressed first)
- **Exploitability** - is there a known, public exploit for this CVE, or is it theoretical?
- **Exposure** - is the vulnerable service internet-facing, or only reachable internally? Internet-facing services with known exploits are the highest priority by far
- **Business impact** - what does this service actually do, and what's the cost if it's compromised?

A Critical-severity finding on an internet-facing, actively-exploited service would get immediate attention; a Low-severity finding on an internal, rarely-used service might be scheduled into regular patch cycles instead.

## Security considerations
- Only scan hosts you own or have explicit, documented permission to test — unauthorized scanning can violate terms of service or the law, independent of intent
- Banner-based detection can be inaccurate - some services deliberately obscure or spoof their version banners, which would cause false negatives (or occasionally false positives) here
- This tool identifies *potential* matches based on keyword search, not confirmed exploitability a real assessment would verify each finding manually before treating it as confirmed

## Limitations
- Regex-based banner parsing is basic and won't correctly extract every service's version format
- NVD's public API rate limit makes scanning many ports slow; a registered API key would allow much faster querying
- Keyword-based CVE search can return loosely related results, not always a perfect version match — results should be reviewed, not trusted blindly
- No exploit-availability checking, severity alone doesn't fully capture real-world risk

## Future improvements
- Use a proper signature database (like Nmap's service/version detection) instead of basic regex parsing
- Add support for an NVD API key to allow faster, higher-volume scanning
- Cross-reference findings with known exploit databases (e.g., Exploit-DB) to flag actively exploitable CVEs specifically
- Add CPE (Common Platform Enumeration) matching for more precise version-to-CVE mapping than keyword search

## Real-world relevance
This project mirrors the core workflow behind real vulnerability management tools (Nessus, OpenVAS, Qualys, etc.) at a simplified scale: discover what's running, check it against known vulnerabilities, prioritize by severity. Reading and triaging vulnerability scan output exactly like this is genuine day-to-day work in many SOC environments, arguably the most directly SOC-relevant project built so far this internship.
