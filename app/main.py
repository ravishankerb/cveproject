import json
import requests
import os

from typing import Dict, Any

from scan_parsers import parse_snyk_report
from llm_requests import analyze_with_llm

def get_nvd_cvss(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        return None
    
    data = r.json()
    try:
        cvss = data["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]
        return {
            "baseScore": cvss["baseScore"],
            "vector": cvss["vectorString"],
            "attackVector": cvss["attackVector"],
            "privilegesRequired": cvss["privilegesRequired"]
        }
    except KeyError:
        return None

def load_kev_catalog(file_path="kev.json"):
    print(f"In load_dev_catalog")
    with open(file_path, "r") as f:
        kev = json.load(f)
    return {item["cveID"]: item for item in kev["vulnerabilities"]}

def check_kev(cve_id, kev_db):
    return kev_db.get(cve_id, None)


def check_code_usage(pkg_name, repo_path="."):
    hits = []
    for root, _, files in os.walk(repo_path):
        for f in files:
            if f.endswith((".java", ".py", ".js")):  # extend as needed
                with open(os.path.join(root, f), "r", errors="ignore") as src:
                    if pkg_name in src.read():
                        hits.append(os.path.join(root, f))
    return hits

def tag_context(cve_entry, repo_path="."):
    usage = check_code_usage(cve_entry["pkg"], repo_path)
    cve_entry["used_in_code"] = len(usage) > 0
    # crude external-facing check
    cve_entry["external_facing"] = os.path.exists(os.path.join(repo_path, "Dockerfile"))
    return cve_entry


def enrich_findings(scanner_report, kev_db, repo_path="."):
    enriched = []
    for finding in scanner_report:
        cve = finding["cve"]
        nvd_data = get_nvd_cvss(cve)
        kev_hit = check_kev(cve, kev_db)
        finding["cvss"] = nvd_data
        finding["kev"] = True if kev_hit else False
        finding = tag_context(finding, repo_path)
        enriched.append(finding)
    return enriched


scan_details = parse_snyk_report("E:\\AgentAI\\enterprise-vuln-app\\snyk_report.json")
project_context = "This is a Java-based microservice exposed to the internet, handling sensitive customer data."
kev_db = load_kev_catalog(".\\data\\kev.json")
findings = enrich_findings(scan_details, kev_db)

import pandas as pd
results = []

for f in findings:
    result = analyze_with_llm(f, project_context)
    results.append({
        'CVE': f['cve'],
        'Package': f['pkg'],
        'Priority': result['priority'],
        'Explanation': result['explanation'][:100] + '...' if len(result['explanation']) > 100 else result['explanation']
    })
df = pd.DataFrame(results)
print(df.to_string(index=False))


