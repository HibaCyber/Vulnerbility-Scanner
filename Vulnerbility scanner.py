# Install dependencies (Colab may not have them by default)
!pip install requests

import os
import json
import csv
import platform
import re
import requests
import time
from google.colab import files  # for downloads

# ----------------- Helper Functions -----------------

def get_installed_packages():
    """Get installed Python packages (Colab environment)."""
    try:
        from importlib.metadata import distributions
        return [(d.metadata["Name"], d.version) for d in distributions()]
    except Exception:
        try:
            import pkg_resources
            return [(d.project_name, d.version) for d in pkg_resources.working_set]
        except Exception:
            return []

def normalize_version(v: str):
    """Normalize version for comparison."""
    if not v:
        return ()
    parts = []
    for seg in re.split(r"[._-]", v):
        if seg.isdigit():
            parts.append(int(seg))
        else:
            parts.append(seg.lower())
    return tuple(parts)

def cmp_versions(a: str, b: str):
    """Compare versions."""
    ta, tb = normalize_version(a), normalize_version(b)
    return (ta > tb) - (ta < tb)

# ----------------- NVD Query -----------------

def query_nvd(keyword, results=20):
    """Query NVD API for CVEs matching a keyword."""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": results}
    headers = {"User-Agent": "ColabVulnScanner/1.0"}
    try:
        r = requests.get(base_url, headers=headers, params=params, timeout=20)
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])
    except Exception as e:
        print("Error querying NVD:", e)
        return []

# ----------------- Main Scanner -----------------

def scan():
    findings = []

    # OS info
    os_info = f"{platform.system()} {platform.release()}"
    software = [(os_info, platform.version())]

    # Python packages
    software += get_installed_packages()

    print(f"🔍 Scanning {len(software)} software items with NVD...\n")

    for name, version in software[:10]:  # limit first 10 for demo (avoid hitting API limits)
        keyword = f"{name} {version}"
        cves = query_nvd(keyword, results=5)  # limit 5 CVEs per package
        for entry in cves:
            cve = entry["cve"]
            cve_id = cve["id"]
            desc = cve["descriptions"][0]["value"]
            severity = "UNKNOWN"
            score = "-"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                data = metrics["cvssMetricV31"][0]["cvssData"]
                score = data["baseScore"]
                severity = metrics["cvssMetricV31"][0]["baseSeverity"]

            findings.append({
                "software": name,
                "version": version,
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": score,
                "description": desc,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

    if not findings:
        print("✅ No vulnerabilities found (or API returned none).")
        return

    # Save reports
    with open("vuln_report.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    with open("vuln_report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=findings[0].keys())
        writer.writeheader()
        writer.writerows(findings)

    print("✅ Scan complete. Reports saved as vuln_report.json and vuln_report.csv")

    # Make files downloadable in Colab
    files.download("vuln_report.json")
    files.download("vuln_report.csv")

# ----------------- Run -----------------
scan()
