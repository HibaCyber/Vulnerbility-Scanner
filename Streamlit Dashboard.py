# Install dependencies
!pip install streamlit pyngrok requests pandas

# --- SETUP NGROK ---
from pyngrok import ngrok

# Set your ngrok auth token (get it free from https://ngrok.com)
# Replace "YOUR_NGROK_TOKEN" with your token
ngrok.set_auth_token("31bWf05jsqqy1ZGyspyq4Mj2Pdb_558uKiVetvM9SCYz4PdZR")

# Create tunnel
public_url = ngrok.connect(8501)
print("🌍 Streamlit App URL:", public_url)

# --- APP CODE (save to file) ---
app_code = r"""
import os
import json
import csv
import requests
import platform
import pandas as pd
import streamlit as st

# ----------------- Helper Functions -----------------
def get_installed_packages():
    try:
        from importlib.metadata import distributions
        return [(d.metadata["Name"], d.version) for d in distributions()]
    except Exception:
        try:
            import pkg_resources
            return [(d.project_name, d.version) for d in pkg_resources.working_set]
        except Exception:
            return []

def query_nvd(keyword, results=20):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": results}
    headers = {"User-Agent": "StreamlitVulnScanner/1.0"}
    try:
        r = requests.get(base_url, headers=headers, params=params, timeout=20)
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])
    except Exception as e:
        return []

# ----------------- Scanner -----------------
def run_scan(limit_soft=10, limit_cves=5):
    findings = []
    # OS
    os_info = f"{platform.system()} {platform.release()}"
    software = [(os_info, platform.version())]
    # Python packages
    software += get_installed_packages()

    for name, version in software[:limit_soft]:
        keyword = f"{name} {version}"
        cves = query_nvd(keyword, results=limit_cves)
        for entry in cves:
            cve = entry["cve"]
            cve_id = cve["id"]
            desc = cve["descriptions"][0]["value"]
            severity, score = "UNKNOWN", "-"
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
    return findings

# ----------------- Streamlit UI -----------------
st.title("🔍 Simple Vulnerability Scanner (NVD API)")

st.sidebar.header("⚙️ Settings")
limit_soft = st.sidebar.slider("Number of software items to scan", 5, 30, 10)
limit_cves = st.sidebar.slider("Max CVEs per software", 1, 20, 5)

if st.button("Run Scan"):
    st.info("Scanning... this may take a minute ⏳")
    findings = run_scan(limit_soft, limit_cves)

    if not findings:
        st.success("✅ No vulnerabilities found.")
    else:
        df = pd.DataFrame(findings)
        st.success(f"Found {len(df)} potential vulnerabilities.")
        st.dataframe(df)

        # Export buttons
        st.download_button("Download CSV", df.to_csv(index=False).encode("utf-8"), "vuln_report.csv", "text/csv")
        st.download_button("Download JSON", df.to_json(orient="records", indent=2).encode("utf-8"), "vuln_report.json", "application/json")
"""

# Save app code
with open("app.py", "w") as f:
    f.write(app_code)

# --- RUN STREAMLIT APP ---
!streamlit run app.py --server.port 8501 --server.headless true &>/dev/null &
