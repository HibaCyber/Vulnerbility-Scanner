Vulnerability Scanner

This is a Python-based vulnerability scanner that uses the National Vulnerability Database (NVD) API to detect known vulnerabilities (CVEs) in software and Python packages. The project can be used in three ways: as a console-based scanner, in Google Colab with CSV/JSON reporting, or through an interactive Streamlit dashboard with export options.

Features

Detects CVEs in operating systems and Python packages using the NVD API

Works in three modes: console scanner, Google Colab, and Streamlit dashboard

Provides severity levels, CVSS scores, and links to official NVD entries

Exports results in CSV and JSON format

Helps in learning security automation and vulnerability management

Installation

To use this project, clone the repository and install the required Python packages such as Streamlit, Pyngrok, Requests, and Pandas.

Usage

You can use this project in three ways:

Console Scanner – Run the scanner script directly from Spyder or your terminal.

Google Colab – Upload and run the Colab notebook to generate vulnerability reports in CSV or JSON.

Streamlit Dashboard – Start the web application for an interactive view of detected vulnerabilities with filtering and export options. If using Colab, Ngrok can be used to make the app publicly accessible.

Example Output

The scanner shows software name, version, CVE ID, severity, CVSS score, description, and a link to the NVD page. Results can also be exported for reporting.

Use Cases

Security auditing and assessments

Risk management and patch planning

Learning automation in cybersecurity

Generating reports for vulnerability remediation
