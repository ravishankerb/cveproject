import requests
import json
import os

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
                file_path = os.path.join(root, f)
                try:
                    with open(file_path, "r", errors="ignore") as src:
                        lines = src.readlines()
                        for line_num, line in enumerate(lines, 1):
                            if pkg_name in line:
                                hit_info = {
                                    "file": file_path,
                                    "line_number": line_num,
                                    "line_content": line.strip()
                                }
                                hits.append(hit_info)
                                print(f"Found usage of '{pkg_name}' in {file_path} at line {line_num}: {line.strip()}")
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    return hits

def tag_context(cve_entry, repo_path="."):
    usage = check_code_usage(cve_entry["pkg"], repo_path)
    cve_entry["used_in_code"] = len(usage) > 0
    cve_entry["usage_details"] = usage  # Include detailed usage information
    # crude external-facing check
    cve_entry["external_facing"] = os.path.exists(os.path.join(repo_path, "Dockerfile"))
    return cve_entry

def enrich_findings(scanner_report, kev_db, repo_path="."):
    enriched = []
    for finding in scanner_report:
        cve = finding["cve"]
        nvd_data = get_nvd_cvss(cve)
        kev_hit = check_kev(cve, kev_db)
        # finding["cvss"] = nvd_data
        finding["kev"] = True if kev_hit else False
        finding = tag_context(finding, repo_path)
        enriched.append(finding)
    return enriched