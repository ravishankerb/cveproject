import json

def parse_snyk_report(file_path):
    print(f"Parsing Snyk report from {file_path}")
    with open(file_path, "r") as f:
        data = json.load(f)

    findings = []
    vulns = data.get("vulnerabilities", [])
    for vuln in vulns:
        # Extract CVE from identifiers.CVE array (first one if multiple)
        cve = "UNKNOWN"
        if "identifiers" in vuln and "CVE" in vuln["identifiers"]:
            cve_list = vuln["identifiers"]["CVE"]
            if cve_list and len(cve_list) > 0:
                cve = cve_list[0]  # Take first CVE if multiple
        
        findings.append({
            "cve": cve,
            "pkg": vuln.get("packageName"),
            "installed": vuln.get("version"),
            "fixed": vuln.get("nearestFixedInVersion"),
            "severity": vuln.get("severity"),
            "cvss": vuln.get("CVSSv3")
        })
    return findings

def parse_trivy_report(file_path):
    print(f"Parsing Trivy report from {file_path}")
    with open(file_path, "r") as f:
        data = json.load(f)
    
    findings = []
    for vuln in data.get("Vulnerabilities", []):
        findings.append({
            "cve": vuln["VulnerabilityID"],
            "pkg": vuln["PkgName"],
            "installed": vuln["InstalledVersion"],
            "fixed": vuln.get("FixedVersion"),
            "severity": vuln["Severity"]
        })
    return findings