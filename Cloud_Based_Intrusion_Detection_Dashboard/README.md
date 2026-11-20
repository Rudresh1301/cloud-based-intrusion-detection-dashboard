# CLOUD-BASED INTRUSION DETECTION DASHBOARD

[![Cloud Computing](https://img.shields.io/badge/Course-Cloud%20Computing-00A8FF.svg)](https://cloud.google.com)
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite%20%7C%20Tailwind-087FE5.svg)](https://react.dev)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.11%2B-00D68F.svg)](https://fastapi.tiangolo.com)
[![Cloud Database](https://img.shields.io/badge/Cloud%20Database-Firebase%20Firestore-FFB020.svg)](https://firebase.google.com)
[![Cloud Storage](https://img.shields.io/badge/Cloud%20Storage-Firebase%20Storage-FF4560.svg)](https://firebase.google.com)
[![ML Engine](https://img.shields.io/badge/Machine%20Learning-Isolation%20Forest%20(Scikit--Learn)-8B5CF6.svg)](https://scikit-learn.org)

An enterprise-grade, cloud-native Security Operations Center (SOC) monitoring and threat detection platform engineered for the **Cloud Computing** engineering curriculum.

The platform demonstrates genuine multi-cloud distributed integration: **React + Vite** hosted on **Vercel**, **FastAPI** microservices orchestrated on **Render (PaaS)**, and **Google Cloud Firebase (BaaS)** providing managed NoSQL persistence (**Cloud Firestore**), binary object storage (**Cloud Storage**), and identity federation (**Firebase Authentication**), backed by an offline-resilient local **SQLite** fallback.

---

## 1. Approved Visual Theme & SOC Aesthetics

The user interface strictly adheres to the approved Security Operations Center palette from the reference design:

| Element | Color Name | Hex Code | Purpose |
| :--- | :--- | :--- | :--- |
| **Main Background** | Deep Space Navy | `#080D19` | Primary viewport background |
| **Sidebar** | Midnight Slate | `#0D1526` | Navigation dock container |
| **Cards & Panels** | Obsidian Blue | `#121E32` | Metric tiles, data panels, charts |
| **Primary Accent** | Electric Cyan | `#00A8FF` | Active indicators, focus highlights |
| **Electric Blue** | Sapphire Glow | `#087FE5` | Primary action buttons, timeline curves |
| **Neon Cyan** | Laser Cyan | `#00C8FF` | Shield logos, icons, pulse highlights |
| **Purple** | Cosmic Violet | `#8B5CF6` | ML behavioral anomaly indicators |
| **Critical Red** | Crimson Alert | `#FF4560` | High/Critical severities, threat spikes |
| **Warning Orange** | Amber Warning | `#FFB020` | Medium alerts, investigation status |
| **Success Green** | Emerald Online | `#00D68F` | Resolved alerts, healthy telemetry |
| **Primary Text** | Frost White | `#F1F5F9` | Headings, metrics, prominent text |
| **Secondary Text** | Slate Muted | `#94A3B8` | Subtitles, labels, timestamps |

---

## 2. Core Cloud Computing Concepts Demonstrated

This project is built from the ground up for academic evaluation in **Cloud Computing**:

1. **Cloud Object Storage (Firebase Cloud Storage)**: Ingested log files and generated executive PDF audit reports are stored as binary objects in cloud storage buckets rather than database documents, ensuring zero document bloat.
2. **Cloud Database (Firebase Cloud Firestore)**: Serverless NoSQL document database providing low-latency indexed queries, stateful alert tracking, and multi-region replication.
3. **Backend as a Service (BaaS)**: Offloading infrastructure, user state management, token issuance, and binary asset hosting to Google Cloud Firebase.
4. **Platform as a Service (PaaS)**: Deploying the Python FastAPI backend to Render using containerized buildpacks and process managers (`Procfile`, `render.yaml`).
5. **Cloud Hosting & CDN (Vercel)**: Distributing production React Vite bundles across worldwide edge CDN locations with instant SSL termination.
6. **Cloud Authentication**: Cryptographically signed JSON Web Tokens (JWT) and Firebase Auth tokens verified by backend dependency gates.
7. **Cloud Elasticity & Horizontal Scalability**: Stateless API design enabling parallel replica autoscaling behind cloud load balancers.
8. **High Availability & Disaster Recovery**: Dual-engine architecture with automatic offline SQLite fallback ensuring zero operational downtime during cloud outages.
9. **Cloud Resource Management**: Chunked file ingestion, vectorized Pandas regex evaluation, and batch Firestore commits minimizing compute units and billing costs.
10. **Zero-Trust Cloud Security**: Environment variable secret injection, CORS restrictions, and payload sanitization without hardcoded secrets.
11. **Distributed Service Integration**: Decoupled multi-cloud communication between Vercel Edge, Render PaaS, and Google Cloud BaaS.
12. **API-Based Communication**: Standardized OpenAPI 3.0 / REST contracts with Pydantic type safety.

---

## 3. System Architecture & Telemetry Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             CLIENT LAYER (Vercel)                           │
│   React 18 + Vite SPA  ──  Tailwind CSS  ──  Recharts  ──  Axios Client    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTPS / REST API
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          APPLICATION PAAS LAYER (Render)                    │
│   FastAPI Gateway  ──  Uvicorn Runtime  ──  Pydantic Validation             │
│                                                                             │
│   ┌─────────────────────────┐             ┌─────────────────────────────┐   │
│   │   Rule-Based Engine     │             │    Isolation Forest ML      │   │
│   │   • SQLi, XSS, RCE      │             │    • Behavioral Outliers    │   │
│   │   • Brute Force Heuristic│            │    • Feature Scaling        │   │
│   │   • Path Traversal      │             │    • Unsupervised Scikit    │   │
│   └────────────┬────────────┘             └──────────────┬──────────────┘   │
│                └────────────────────┬────────────────────┘                  │
│                                     ▼                                       │
│                       Log Processor & IP Analyzer                           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌─────────────────────────────────────┐         ┌─────────────────────────────┐
│      FIREBASE BAAS (Primary)        │         │   LOCAL SQLITE (Fallback)   │
│ • Cloud Firestore (NoSQL Docs)      │         │ • data/local_soc.db         │
│ • Cloud Storage (CSV & PDF Buckets) │         │ • data/storage/             │
│ • Firebase Authentication           │         │ • Zero-setup local testing  │
└─────────────────────────────────────┘         └─────────────────────────────┘
```

---

## 4. Project Directory Structure

```
Cloud_Based_Intrusion_Detection_Dashboard/
├── backend/
│   ├── app/
│   │   ├── api/                  # Modular FastAPI route controllers
│   │   │   ├── alerts.py         # Alert management & status updates
│   │   │   ├── analytics.py      # Temporal trends & attack charts
│   │   │   ├── auth.py           # Login, registration, token verification
│   │   │   ├── dashboard.py      # SOC overview metrics & map aggregation
│   │   │   ├── health.py         # Real cloud connectivity health probes
│   │   │   ├── ip_intel.py       # IP geolocation & risk profiling
│   │   │   ├── live.py           # Simulated live monitoring telemetry
│   │   │   ├── logs.py           # Log upload, validation, export
│   │   │   ├── reports.py        # PDF audit report generation & download
│   │   │   └── settings.py       # Threshold tuning & database controls
│   │   ├── core/
│   │   │   └── config.py         # Environment variables & constants
│   │   ├── database/
│   │   │   ├── db_service.py     # Unified Database Manager (Firestore + SQLite)
│   │   │   ├── firestore.py      # Google Cloud Firestore integration
│   │   │   ├── sqlite_db.py      # Thread-safe SQLite fallback engine
│   │   │   └── storage.py        # Firebase Cloud Storage & local storage
│   │   ├── detection/
│   │   │   ├── ip_analyzer.py    # IP risk scoring & ASN geolocation
│   │   │   ├── ml_detector.py    # Scikit-learn Isolation Forest ML
│   │   │   ├── risk_calculator.py# Composite SOC organizational posture
│   │   │   └── rule_engine.py    # Vectorized regex heuristics (SQLi/XSS/RCE)
│   │   ├── schemas/
│   │   │   └── schemas.py        # Pydantic data contract models
│   │   ├── services/
│   │   │   ├── live_simulator.py # Simulated real-time packet generator
│   │   │   ├── log_processor.py  # Ingestion parser & pipeline coordinator
│   │   │   └── report_generator.py # ReportLab publication-ready PDF builder
│   │   └── main.py               # FastAPI entry point & CORS configuration
│   ├── .env.example              # Environment variables template
│   ├── Procfile                  # Render PaaS deployment directive
│   ├── render.yaml               # Render Infrastructure-as-Code specification
│   └── requirements.txt          # Python runtime dependencies
├── frontend/
│   ├── public/
│   │   └── shield.svg            # Favicon and branding asset
│   ├── src/
│   │   ├── charts/               # Recharts components matching SOC UI
│   │   │   ├── ActivityTimelineChart.jsx # Dual-line traffic overview
│   │   │   ├── AttackDonutChart.jsx      # Attack types donut chart
│   │   │   └── GlobalThreatMap.jsx       # Interactive SVG threat map
│   │   ├── components/           # Reusable UI widgets
│   │   │   ├── IPDetailModal.jsx         # Forensic IP inspection modal
│   │   │   ├── MetricCard.jsx            # Top 4 tiles with sparklines
│   │   │   ├── Navbar.jsx                # Title, heartbeat ECG, user profile
│   │   │   ├── RiskGauge.jsx             # Circular 85% risk gauge
│   │   │   ├── Sidebar.jsx               # 11 navigation links & status card
│   │   │   └── ThreatDetailModal.jsx     # Incident drilldown modal
│   │   ├── context/
│   │   │   └── AuthContext.jsx   # State management & token storage
│   │   ├── layouts/
│   │   │   └── DashboardLayout.jsx # Collapsible shell layout
│   │   ├── pages/                # 11 Dedicated views
│   │   │   ├── AboutProject.jsx  # Academic syllabus & concepts guide
│   │   │   ├── AlertsCenter.jsx  # Triage & state management
│   │   │   ├── AttackAnalytics.jsx # Diurnal hourly & weekly heatmaps
│   │   │   ├── Dashboard.jsx     # Approved reference design replica
│   │   │   ├── IPIntelligence.jsx# Host reputation & ASN lookup
│   │   │   ├── LiveMonitoring.jsx# Simulated live telemetry pulse
│   │   │   ├── LoginPage.jsx     # Analyst authentication view
│   │   │   ├── RegisterPage.jsx  # Identity provisioning view
│   │   │   ├── Reports.jsx       # PDF generation & download archive
│   │   │   ├── SecurityLogs.jsx  # Log explorer & CSV exporter
│   │   │   ├── SettingsPage.jsx  # Health checks & threshold tuning
│   │   │   └── UploadLogs.jsx    # Drag-and-drop ingestion & validation
│   │   ├── services/
│   │   │   └── api.js            # Axios client with interceptors
│   │   ├── App.jsx               # React Router DOM configuration
│   │   ├── index.css             # Tailwind CSS & animations
│   │   └── main.jsx              # React mounting root
│   ├── package.json              # NPM dependencies & build scripts
│   ├── tailwind.config.js        # SOC dark palette definitions
│   ├── vercel.json               # Vercel deployment & proxy rewrites
│   └── vite.config.js            # Vite bundler & backend dev proxy
├── data/
│   └── sample_logs.csv           # Benchmark security log dataset
├── docs/
│   └── CLOUD_COMPUTING_EVALUATION.md # Faculty syllabus evaluation guide
├── tests/
│   └── test_api_and_detection.py # Comprehensive 15-test Pytest suite
├── run_backend.bat               # Windows 1-click backend launcher
├── run_frontend.bat              # Windows 1-click frontend launcher
├── run_both.bat                  # Launches both frontend and backend
├── run_tests.bat                 # 1-click Pytest runner
└── README.md
```

---

## 5. Quick Start & Local Execution (Windows)

### Prerequisites
- **Python 3.10+**
- **Node.js 18+ & NPM**

### 1-Click Startup (Recommended)
Double-click `run_both.bat` in the project root:
```cmd
run_both.bat
```
This automatically launches:
- **FastAPI Backend**: `http://localhost:8000` (API Docs at `http://localhost:8000/docs`)
- **React Frontend**: `http://localhost:3000`

### Manual Step-by-Step Startup

#### Terminal 1: Backend
```cmd
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Terminal 2: Frontend
```cmd
cd frontend
npm install
npm run dev
```
Open your browser to `http://localhost:3000`.

---

## 6. Preconfigured Analyst Credentials

| Role | Email | Password |
| :--- | :--- | :--- |
| **SOC Administrator** | `admin@soc.cloud` | `admin123` |
| **Security Analyst** | `analyst@soc.cloud` | `password123` |

*New analysts can also be registered directly through the `/register` page.*

---

## 7. Firebase Cloud Configuration (Production Setup)

To connect the application to your personal Firebase cloud instance:

1. Navigate to the [Firebase Console](https://console.firebase.google.com/) and create a new project.
2. Enable **Cloud Firestore** in production mode.
3. Enable **Cloud Storage** and configure security rules for read/write access.
4. Enable **Authentication** (Email/Password provider).
5. Go to **Project Settings > Service Accounts**, click **Generate new private key**, and save the downloaded JSON file as `backend/config/firebase-credentials.json`.
6. Update `backend/.env`:
   ```ini
   DATABASE_TYPE="firebase"
   FIREBASE_CREDENTIALS_PATH="config/firebase-credentials.json"
   FIREBASE_PROJECT_ID="your-project-id"
   FIREBASE_STORAGE_BUCKET="your-project-id.appspot.com"
   ```
7. Restart the backend. The dashboard and settings pages will immediately report `Firebase Cloud Active` with genuine latency measurements!

---

## 8. Cloud Deployment Guide

### Deploying Frontend to Vercel
1. Push your repository to GitHub.
2. Sign in to [Vercel](https://vercel.com) and import the repository.
3. Set **Root Directory** to `frontend`.
4. Configure Environment Variable:
   - `VITE_API_URL`: URL of your deployed Render backend (e.g. `https://your-api.onrender.com`)
5. Click **Deploy**. Vercel will build and serve the application globally via edge CDN.

### Deploying Backend to Render (PaaS)
1. Sign in to [Render](https://render.com) and create a **New Web Service**.
2. Connect your GitHub repository.
3. Configure the service:
   - **Root Directory**: `backend`
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Set Environment Variables:
   - `ENVIRONMENT`: `production`
   - `CORS_ORIGINS`: Your Vercel frontend URL
   - `FIREBASE_PROJECT_ID`: Your Firebase Project ID
   - `FIREBASE_STORAGE_BUCKET`: Your Firebase Storage Bucket
5. Click **Deploy Web Service**.

---

## 9. Automated Testing & Verification

Run the comprehensive 15-test Pytest suite:
```cmd
run_tests.bat
```
or via terminal:
```cmd
python -m pytest tests/test_api_and_detection.py -v
```

### Verified Test Cases:
- `test_root_endpoint`: Verifies OpenAPI root status and cloud provider identification.
- `test_cloud_health_endpoint`: Asserts non-fabricated connectivity reporting for all cloud services.
- `test_brute_force_detection`: Validates 5-9 attempt High and 10+ attempt Critical severity escalations.
- `test_sqli_detection`: Verifies regex pattern matching against `UNION SELECT` and `OR 1=1` payloads.
- `test_xss_detection`: Verifies `<script>` and malicious DOM event payload interception.
- `test_command_injection`: Validates shell execution pattern detection (`; cat /etc/passwd`).
- `test_path_traversal`: Validates directory climbing sequences (`../../etc/shadow`).
- `test_normal_traffic_no_false_positives`: Verifies zero false alarms on legitimate application usage.
- `test_log_validation_missing_columns`: Checks strict mandatory schema enforcement.
- `test_log_validation_duplicates_and_invalid_ips`: Flags malformed IP addresses and repeated entries.
- `test_dashboard_overview`: Confirms metrics, timeline, and distribution calculations.
- `test_threats_list_and_filter`: Confirms faceted filtering and pagination.
- `test_ip_intelligence`: Validates IP correlation, risk scoring, and geolocation resolution.
- `test_alert_status_update`: Validates lifecycle state transitions (`New` -> `Investigating` -> `Resolved`).
- `test_report_generation`: Confirms ReportLab executive PDF generation.

---

## 10. Academic Evaluation Summary

| Subject | Academic Level | Practical Domain | Cloud Platform |
| :--- | :--- | :--- | :--- |
| **Cloud Computing** | 5th-Semester Engineering Mini Project | Cybersecurity Operations (SOC) | Google Cloud (Firebase) + Render + Vercel |

*Developed in compliance with academic syllabus requirements for distributed systems, cloud data architecture, and Platform-as-a-Service engineering.*
