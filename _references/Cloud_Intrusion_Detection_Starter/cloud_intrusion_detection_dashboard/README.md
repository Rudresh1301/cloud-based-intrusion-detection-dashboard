# 🛡️ Cloud-Based Intrusion Detection Dashboard (SOC)

[![Python](https://img.shields.io/badge/Python-3.10%2B-087FE5.svg?style=flat&logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.39%2B-FF4B4B.svg?style=flat&logo=streamlit)](https://streamlit.io/)
[![Plotly](https://img.shields.io/badge/Plotly-5.24%2B-8B5CF6.svg?style=flat&logo=plotly)](https://plotly.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4%2B-F7931E.svg?style=flat&logo=scikit-learn)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/Database-Firebase%20%7C%20SQLite3-00D68F.svg?style=flat)](https://firebase.google.com/)
[![Tests](https://img.shields.io/badge/Tests-20%20Passed-00A8FF.svg?style=flat)]()

An enterprise-grade, cloud-native **Security Operations Center (SOC)** intrusion detection and telemetry dashboard developed as a 5th-semester engineering mini project. The application analyzes web application and network access logs, identifies adversarial activity using deterministic heuristics and unsupervised machine learning, classifies threats by severity, and provides an interactive command center for incident investigation, threat hunting, and remediation auditing.

---

## 📸 Dashboard Preview

The user interface follows a modern dark navy cybersecurity SOC aesthetic with electric blue and neon cyan accents:

* **Dark Navy Interface:** `#080D19` (Main Background), `#0D1526` (Sidebar), `#121E32` (Cards)
* **Status Badges:** Critical (`#FF4560`), High (`#FFB020`), Medium (`#8B5CF6`), Low (`#00C8FF`), Normal (`#00D68F`)
* **Real-time Dual-Series Curves:** Plotly Spline curves depicting Normal Traffic vs Threat Incursions
* **Global Attack Telemetry Map:** Geographic scatter visualization of offending host origins

---

## 🚀 Key Features

### 1. Dual-Tier Intrusion Detection Engine
* **Rule-Based Heuristic Classifiers:**
  * **Brute Force Detection:** Aggregates repeated failed authentication events with configurable thresholds (5 = High, 10 = Critical).
  * **SQL Injection (SQLi):** Multi-token regex scanning for `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `BENCHMARK`, and comment bypasses.
  * **Cross-Site Scripting (XSS):** Identifies unsanitized `<script>`, JavaScript pseudo-protocols, event handlers (`onerror=`, `onload=`), and `eval` constructs.
  * **Command Injection (RCE):** Catches OS shell operators (`;ls`, `|cat`, `&&whoami`, `nc -e`, `/etc/passwd`).
  * **Path Traversal (LFI/RFI):** Detects directory escaping (`../`, `..\`, `%2e%2e%2f`) targeting sensitive files.
  * **Volumetric Flooding / DoS:** Identifies aggressive single-host request density.
  * **Privilege Probing:** Alerts on unauthorized reconnaissance of `/admin`, `/wp-admin`, `/.env`, and `/phpmyadmin`.
* **Unsupervised Machine Learning (Isolation Forest):**
  * Extracts per-host numerical behavioral feature vectors (`request_count`, `failed_count`, `failed_ratio`, `unique_endpoints`, `unique_users`, `suspicious_keyword_count`, `unique_event_types`).
  * Isolates statistical density outliers without requiring pre-labeled training data.
  * Generates explainable natural-language reasoning for why an IP host was flagged.

### 2. Eleven (11) Dedicated Navigation Modules
1. **📊 Dashboard:** Primary SOC overview with 4 KPI cards, dual-series attack timeline, category donut, global map, top hostile IPs, live alerts feed, circular risk gauge, and quick action controls.
2. **📤 Upload Logs:** Ingests custom CSV or TXT log files; performs 7-point validation (schema, nulls, duplicates, unparseable dates, invalid IPs), displays data preview, and triggers re-analysis.
3. **📡 Live Monitoring:** Interactive simulated live event stream demonstrating real-time packet ingestion, active threat notifications, and instant density gauges.
4. **🎯 Threat Analysis:** Deep forensic investigation console with multi-select severity/category filters, search, expandable technical evidence, and CSV export.
5. **🌐 IP Intelligence:** Comprehensive host profiling dossier with network zone classification (Public, RFC 1918 Private, Loopback), timeline charts, target endpoint breakdown, and 0–100 behavioral risk score.
6. **📈 Attack Analytics:** Advanced Plotly charts showing 24-hour hourly distributions, day-of-week trends, targeted endpoint saturation, and authentication pass/fail breakdowns.
7. **📋 Security Logs:** Complete searchable and filterable access log table with verdict tagging (`🚨 Suspicious` vs `✅ Normal`), pagination controls, and CSV export.
8. **🚨 Alerts Center:** Incident management triage board with active lifecycle state transitions (**New** → **Investigating** → **Resolved** / **False Positive**) that actively mutate the underlying database.
9. **📄 Reports:** One-click automated PDF executive security audit report compilation using **ReportLab** with executive summaries, metrics tables, and prioritized remediation recommendations.
10. **⚙️ Settings:** Real-time tuning of brute-force thresholds, volumetric trigger levels, ML contamination rates, signature toggles, and database configuration.
11. **ℹ️ About Project:** Engineering documentation, viva defense notes, technology stack mapping, and academic disclaimers.

### 3. Cloud Database & Local Fallback
* **Google Firebase Firestore:** Cloud-synchronized storage for alerts, analysis history, settings, and status audit logs.
* **Local SQLite3 Fallback:** Seamless zero-configuration fallback for offline development or college presentation environments when cloud credentials are not supplied.

---

## 📂 Project Architecture

```
cloud_intrusion_detection_dashboard/
│
├── app.py                     # Main Streamlit orchestration entry point
├── detector.py                # Backward-compatibility API wrapper
├── requirements.txt           # Verified Python package dependencies
├── README.md                  # Comprehensive documentation & setup guide
├── .gitignore                 # Secrets, local DB, and cache exclusion
│
├── config/
│   ├── __init__.py
│   ├── settings.py            # Central constants, color palette, & default thresholds
│   └── firebase_config.py     # Firebase Firestore authentication & connection logic
│
├── core/
│   ├── __init__.py
│   ├── detector.py            # IntrusionDetector master pipeline orchestrator
│   ├── rule_engine.py         # Signature & heuristic detection algorithms
│   ├── ml_detector.py         # Isolation Forest unsupervised anomaly model
│   ├── log_processor.py       # Log normalization, enrichment & summary statistics
│   ├── ip_analyzer.py         # IP network zoning & behavioral risk scoring
│   └── risk_calculator.py     # Composite posture evaluation & dynamic recommendations
│
├── database/
│   ├── __init__.py
│   ├── local_db.py            # Thread-safe SQLite3 fallback store
│   └── firebase_db.py         # Google Cloud Firestore cloud synchronization
│
├── utils/
│   ├── __init__.py
│   ├── helpers.py             # Number formatting, relative time, HTML badges
│   ├── validators.py          # CSV/IP/timestamp syntax validators & sanitizers
│   └── report_generator.py    # ReportLab automated PDF audit document builder
│
├── pages/
│   ├── __init__.py
│   ├── dashboard.py           # SOC Overview command center
│   ├── upload_logs.py         # Custom log ingestion & validation
│   ├── live_monitoring.py     # Real-time event simulation feed
│   ├── threat_analysis.py     # Forensic evidence inspection
│   ├── ip_intelligence.py     # Host reconnaissance dossier
│   ├── attack_analytics.py    # Plotly multi-dimensional analytics
│   ├── security_logs.py       # Filterable & paginated log explorer
│   ├── alerts_center.py       # Incident status triage workflow
│   ├── reports.py             # Executive PDF report exporter
│   ├── settings_page.py       # Heuristic & ML threshold tuning
│   └── about.py               # Academic engineering documentation
│
├── data/
│   ├── sample_logs.csv        # Realistic 150-row security telemetry dataset
│   └── README.md              # Dataset column specifications
│
└── tests/
    ├── __init__.py
    ├── test_detector.py       # Heuristics & pipeline unit tests
    ├── test_log_processor.py  # Enrichment & aggregation unit tests
    ├── test_validators.py     # Validation & sanitization unit tests
    └── test_components.py     # IP analyzer, risk, DB, & PDF report tests
```

---

## 🛠️ Local Installation & Execution

### Prerequisites
* Python 3.10 or higher
* Git (optional)

### Step 1: Clone or Navigate to the Directory
```powershell
cd c:\Users\Hp\Downloads\Cloud_Intrusion_Detection_Starter\cloud_intrusion_detection_dashboard
```

### Step 2: Create and Activate a Virtual Environment
```powershell
# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Run the Test Suite
Ensure all 19 test cases pass before launching:
```powershell
python -m pytest tests/ -v
```

### Step 5: Launch the Streamlit Dashboard
```powershell
streamlit run app.py
```
The application will automatically open in your default browser at `http://localhost:8501`.

---

## ☁️ Cloud Deployment (Streamlit Community Cloud)

1. Push your repository to **GitHub**.
2. Visit [Streamlit Community Cloud](https://share.streamlit.io/) and log in with GitHub.
3. Click **New app**, select your repository, branch (`main`), and set **Main file path** to `app.py` (or `cloud_intrusion_detection_dashboard/app.py` if deployed from the root).
4. *(Optional Firebase Integration)*:
   * Expand **Advanced settings...** > **Secrets**.
   * Paste your Firebase Service Account JSON credentials:
     ```toml
     [firebase]
     type = "service_account"
     project_id = "your-project-id"
     private_key_id = "your-key-id"
     private_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
     client_email = "firebase-adminsdk-...@your-project-id.iam.gserviceaccount.com"
     client_id = "..."
     auth_uri = "https://accounts.google.com/o/oauth2/auth"
     token_uri = "https://oauth2.googleapis.com/token"
     auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
     client_x509_cert_url = "https://www.googleapis.com/robot/v1/metadata/x509/..."
     ```
5. Click **Deploy!** The cloud deployment will automatically install `requirements.txt` and launch.

---

## 📊 CSV Log File Format Specification

Uploaded log files must contain the following header columns:

| Column | Data Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `timestamp` | Datetime / String | Date and time of the event | `2026-11-20 10:14:02` |
| `source_ip` | String (IPv4/IPv6) | Originating client host address | `103.21.45.67` |
| `username` | String | User identity associated with event | `admin`, `alice`, `unknown` |
| `event_type` | String | Categorical transaction classification | `login`, `page_view`, `query` |
| `status` | String | Result verdict of the operation | `success`, `failed`, `blocked` |
| `endpoint` | String | Targeted URI or resource path | `/search?id=1 OR 1=1` |

A sample dataset with 150 realistic events containing normal traffic and diverse attack incursions is provided in `data/sample_logs.csv` and can be downloaded directly from the **Upload Logs** tab.

---

## 🎓 Academic Viva & Mini Project Defense Highlights

When presenting this project to engineering evaluators, emphasize the following architectural design choices:

1. **Deterministic vs Stochastic Detection:** Explain why both are necessary. Heuristics catch known OWASP signatures instantly with zero false alarms; unsupervised Isolation Forest detects anomalous volumetric behavior and scanning patterns without requiring signature updates.
2. **No Data Leakage / Explainable ML:** Discuss how features are extracted at the per-IP behavioral level and normalized with `StandardScaler`. Emphasize that anomaly reasoning is explained to analysts by comparing feature standard deviations against the dataset mean.
3. **Resilient Dual Storage:** Show that the system detects whether Firebase credentials exist and switches automatically to local SQLite without crashing or showing broken interfaces.
4. **Immutable Evidence Trail:** Explain how alert status modifications (**New** → **Investigating** → **Resolved**) record an audit trail in `alert_status_log` with UTC timestamps.
5. **Ethical Compliance:** Reiterate that this is an educational intrusion detection prototype designed to process log records; it does not impersonate an inline network TAP or active packet firewall.

---

## 📄 License & Credits

* Developed for 5th-Semester Computer Science / Information Security Engineering Mini Project.
* Built using Python, Streamlit, Plotly, Scikit-learn, SQLite3, and ReportLab.
