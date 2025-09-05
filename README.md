Vulnerability Scanner

This is a Python-based vulnerability scanner that uses the National Vulnerability Database (NVD) API to detect known vulnerabilities (CVEs) in software and Python packages. The project can be used in three ways: as a console-based scanner, in Google Colab with CSV/JSON reporting, or through an interactive Streamlit dashboard with export options.

Features

Detects CVEs in operating system and Python packages using the NVD API

Supports three usage modes:

Console scanner (basic use in Spyder or terminal)

Google Colab version (with CSV/JSON reporting)

Streamlit web dashboard (with filtering and export options)

Provides severity ratings, CVSS scores, and direct links to NVD entries

Exports results in CSV and JSON formats

Useful for learning security automation and vulnerability management

Installation
Clone the repository
git clone https://github.com/YourUsername/Vulnerability-Scanner.git
cd Vulnerability-Scanner

Install dependencies
pip install -r requirements.txt


Or manually:

pip install streamlit pyngrok requests pandas

Usage
1. Console Scanner (Spyder or Terminal)

Run the script to scan for vulnerabilities:

python scanner.py

2. Google Colab Notebook

Upload the notebook scanner_colab.ipynb to Google Colab and run it.

Generates CSV and JSON reports

Easy to use without local setup

3. Streamlit Web Application

Run the dashboard locally:

streamlit run app.py


If running in Google Colab, use Ngrok to create a tunnel:

from pyngrok import ngrok
ngrok.set_auth_token("YOUR_TOKEN")
public_url = ngrok.connect(8501)
print("App URL:", public_url)

Example Output

Severity levels: Low, Medium, High, Critical

Report includes: Software name, version, CVE ID, CVSS score, description, and NVD link

Use Cases

Security auditing

Risk management

Learning security automation and vulnerability scanning

Generating vulnerability reports for patching and remediation
