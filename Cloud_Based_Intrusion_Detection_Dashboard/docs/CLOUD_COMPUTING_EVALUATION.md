# CLOUD COMPUTING MINI PROJECT – FACULTY EVALUATION BRIEF
## Subject: Cloud Computing (5th Semester B.Tech / B.E.)
### Project Title: Cloud-Based Intrusion Detection Dashboard

---

## 1. Executive Summary for Evaluators

This project fulfills the engineering requirements for **Cloud Computing** by building a production-ready, cloud-native Security Operations Center (SOC) dashboard.

Intrusion detection serves as the practical cybersecurity use case, while **cloud architecture, distributed services, Backend-as-a-Service (BaaS), and Platform-as-a-Service (PaaS)** form the technological foundation.

---

## 2. Direct Syllabus Mapping Matrix

| Cloud Computing Concept | Syllabus Objective | Implementation in this Project | Verified Source Code Location |
| :--- | :--- | :--- | :--- |
| **Cloud Object Storage** | Blob/Object storage lifecycle & decoupling | Uploaded CSV/TXT security logs and ReportLab PDF reports are streamed into **Firebase Cloud Storage** buckets with public/signed access tokens. Large files are never stored in the database. | `backend/app/database/storage.py` |
| **Cloud NoSQL Database** | Managed distributed document database | **Google Cloud Firestore** indexes telemetry events, threat alerts, IP reputation intelligence, and historical analysis snapshots with multi-region replication. | `backend/app/database/firestore.py` |
| **Backend as a Service (BaaS)** | Third-party managed cloud infrastructure | Utilizes Firebase platform services for serverless database persistence, identity lifecycle management, and object storage. | `backend/app/database/db_service.py` |
| **Platform as a Service (PaaS)** | Automated buildpacks, container orchestration | The Python FastAPI detection engine is packaged with `Procfile` and `render.yaml` for one-click autoscaling deployment on **Render**. | `backend/render.yaml`, `backend/Procfile` |
| **Edge Cloud Hosting (CDN)** | Static asset distribution & global caching | The React Vite frontend is configured with `vercel.json` for edge caching, client-side routing fallback, and automatic SSL termination on **Vercel**. | `frontend/vercel.json` |
| **Cloud Authentication & IAM** | Identity federation & cryptographic claims | Dual-layer authentication via **Firebase Authentication** and cryptographic JWT token inspection on backend endpoints. | `backend/app/api/auth.py`, `frontend/src/context/AuthContext.jsx` |
| **Horizontal Scalability & Elasticity** | Stateless application design | FastAPI endpoints are 100% stateless; workers can be scaled horizontally behind cloud load balancers without shared state or race conditions. | `backend/app/main.py` |
| **High Availability & Fallback** | Multi-zone redundancy & disaster recovery | Dual-engine database service: connects to Google Cloud in production, automatically provides a zero-setup SQLite fallback for local offline development, while accurately reporting connection health. | `backend/app/database/sqlite_db.py`, `backend/app/api/health.py` |
| **Cloud Resource Optimization** | Throttling, batching, and quota controls | Firestore writes use `batch()` operations (up to 500 records per transaction) to minimize write billing units and reduce latency. | `backend/app/database/firestore.py` |
| **Zero-Trust Cloud Security** | Secure secrets injection & least privilege | Zero hardcoded API keys; credentials injected via environment variables (`.env`, Render Secrets). | `backend/app/core/config.py` |
| **Distributed Microservice Integration** | Decoupled client-server-cloud topology | Independent frontend (React on Vercel), backend (FastAPI on Render), and cloud data services (Firebase on GCP) communicating via REST. | `frontend/src/services/api.js` |
| **API Contract & Validation** | RESTful architectural constraints | Type-safe JSON data contracts enforced at ingress using Pydantic schemas and OpenAPI 3.0 specs. | `backend/app/schemas/schemas.py` |

---

## 3. End-to-End Cloud Telemetry Workflow

1. **Ingestion**: The user uploads security logs via the React SPA on Vercel.
2. **Transfer**: The file is streamed to the FastAPI backend on Render.
3. **Object Storage**: The backend uploads the raw file to **Firebase Cloud Storage**.
4. **Detection Processing**:
   - Deterministic rule heuristics inspect SQLi, XSS, RCE, Path Traversal, and Brute Force patterns using vectorized Pandas regex.
   - An unsupervised **Isolation Forest (Scikit-learn)** model extracts multidimensional IP behavioral vectors to identify statistical anomalies.
5. **NoSQL Persistence**: Processed records, alert notifications, and calculated IP reputation profiles are committed in batch to **Google Cloud Firestore**.
6. **Dashboard Visualization**: The React frontend queries `/api/dashboard/overview`, rendering real-time metric cards, dual-line activity timelines, attack donut charts, and an interactive global threat map.
7. **Reporting**: The user clicks "Download Report ↓". The backend compiles an executive PDF audit report using ReportLab, stores it in Cloud Storage, and returns a direct download URL.

---

## 4. Key Questions & Answers for Viva Voce

### Q1: How does this project differ from a typical standalone cybersecurity script?
**A:** Standard cybersecurity scripts run locally and print to a console. This platform is a **distributed cloud application** with separated presentation (Vercel), application (Render PaaS), and storage/database (Google Cloud Firebase BaaS) tiers.

### Q2: Why is SQLite included if Firestore is the primary database?
**A:** In cloud computing, **high availability and graceful degradation** are fundamental design tenets. SQLite provides a local fallback so the application functions in offline development or when cloud credentials are not yet configured, without faking cloud connectivity status.

### Q3: How are large log files prevented from causing Firestore write bottlenecks?
**A:** By adhering to cloud object storage best practices: large raw files are stored as blobs in **Firebase Storage**, and only structured event metadata and document references are indexed in **Firestore**.
