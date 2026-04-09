# CSC Research / NetVision

This repository contains two main surfaces:

## NetVision (FastAPI + React)

A **network scanning dashboard** with a **modular scanner plugin** system, JSON logging, optional **WebSocket** live output, CVE taxonomy APIs, and D3 graph visualization.

- **Backend:** `backend/` — run with `uvicorn app.main:app --reload --app-dir backend` (from repo root). Add new tools by implementing `ScannerPlugin` and registering them in `backend/app/scanners/plugins.py` (see `plugin_template.py` and `nmap_scanner.py`).
- **Frontend:** `frontend/` — `npm install && npm run dev` (Vite dev server proxies `/api` → `http://127.0.0.1:8000`). The UI loads available scanners from `GET /api/v1/scans/plugins`.
- **Details:** see [NETVISION.md](NETVISION.md).

---

# CVE-CWE-CAPEC-ATT&CK-D3FEND Mapper (Streamlit)

The project also includes a **Streamlit-based web application** that links software, firmware, and hardware vulnerabilities (CVE's) to related CWE's, CAPEC Attack Patterns, available MITRE Taxonomies (Att&CK, OWASP, and even the, now deprecated, WASC ID's), and MITRE D3FEND Techniques.   

Users can analyse a **Single CVE** or a **Batch of CVE's using appropriate CSV files**, explore relationships interactively, and export the results as a **PDF Report**

# Live Demo:

Use this link to access the hosted version:

https://csc-research-project-uekgmg9482bt7vjnc8my5j.streamlit.app/

To run the application locally, continue reading the following instructions for installations and required dependencies.

# Features:

  Single CVE Lookup: Enter a CVE ID to see all linked CWEs, CAPECs, ATT&CK techniques, and D3FEND mappings.
  
  CSV Upload: Upload multiple CSV files containing CVE IDs for batch processing.
  
  Interactive Viewer: Select CVEs, associated CWEs, CAPECs, and taxonomies via dropdowns.
  
  PDF Export: Download a comprehensive PDF report of all mappings.
  
  Persistent Session: Previously processed CVEs remain in session storage.

# Installation:

  Clone this repository:
  
    git clone[ https://github.com/Alex-F26/cve-mapper.git](https://github.com/Alex-F26/CSC-Research-Project.git)
   
    cd cve-mapper

Create and activate a virtual environment:
  
  python -m venv venv
 
 (Windows)
 
  venv\Scripts\activate
 
 (macOS/Linux)
 
  source venv/bin/activate


# Install dependencies:

  pip install -r requirements.txt

  Ensure the Linkers package with modules cve_cwe_linker, cwe_capec_linker, capec_taxonomy_linker, and attack_defend_linker is available in your project directory.

# Usage:
  
  Run the Streamlit app:
  
  streamlit run app.py

# Single CVE Lookup:
  
  Enter a CVE ID in the text box.
  
  View linked CWEs, CAPECs, ATT&CK techniques, D3FEND mitigations, OWASP, and WASC entries.

# CSV Batch Processing:
  
  Upload one or more CSV files containing a cveID column.
  
  Click Process CSVs.
  
  View results and download a PDF report using the Download All Mappings as PDF button.

# Interactive Selection:
 
 Select a CVE from the dropdown.
 
 Select associated CWE.
 
 Select associated CAPEC.
 
 View linked taxonomies (ATT&CK / OWASP / WASC).
 
 For ATT&CK, view linked D3FEND techniques.

# File Format for CSV Upload:

 Your CSV files must have at least the following in the first column:
 
 cveID
 
 CVE-2023-12345
 
 CVE-2022-54321

 (Basically just make sure that your csv file has your CVE ID's in the first column and you're good to go!)

 Sample CSV File:

 [known_exploited_vulnerabilities (1).csv](https://github.com/user-attachments/files/24253564/known_exploited_vulnerabilities.1.csv)

# Dependencies:
 
  Streamlit
  
  pandas
  
  fpdf
  
  Python 3.8+
  
  Linkers package with the CVE/CWE/CAPEC/ATT&CK/D3FEND mapping modules
  
  CSV package with the following CSV's: ATTACK_DEFEND.csv/CAPEC_ATTACK.csv/CWE_CAPEC.csv/test.csv

# Notes:

  D3FEND mappings are only available for MITRE ATT&CK techniques.
  
  The PDF generation automatically wraps long lists to avoid cutting off content.
  
  OWASP and WASC are included if present in the taxonomy mappings.

# Future Potential Additions

  Using the MITRE extractor tools, I plan to add full related mappings to as many CVE's as possible

# License:
 
 MIT License 

