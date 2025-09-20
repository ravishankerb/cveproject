import json

def parse_snyk_report(file_path):
    print(f"Parsing Snyk report from {file_path}")
    with open(file_path, "r") as f:
        data = json.load(f)

    findings = []
    vulns = data.get("vulnerabilities", [])
    for vuln in vulns:
        findings.append({
            "cve": vuln.get("id") or vuln.get("CVE", "UNKNOWN"),  # Snyk 'id' might be advisory ID (CVE if available)
            "pkg": vuln.get("packageName"),
            "installed": vuln.get("version"),
            "fixed": vuln.get("nearestFixedInVersion"),
            "severity": vuln.get("severity"),
            "cvss": vuln.get("cvssScore") or vuln.get("cvssV3")
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