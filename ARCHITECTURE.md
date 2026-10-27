# CloudVault: Digital Document & Certificate Portal
## Complete System Architecture, Cloud Models & Technical Operations Guide

> **Project Version**: 2.4.0 (Production)  
> **Target Cloud**: Microsoft Azure (Azure for Students Subscription)  
> **Live Production URL**: [https://cloudvault-app-dmgveggdbxacbuct.centralindia-01.azurewebsites.net](https://cloudvault-app-dmgveggdbxacbuct.centralindia-01.azurewebsites.net/)  
> **Source Code**: [github.com/AyushTodkar404/CloudVault](https://github.com/AyushTodkar404/CloudVault)  
> **Last Updated**: October 2026  

---

## 1. Executive Summary

**CloudVault** is an enterprise-grade, university cloud document and certificate registry built for high-security academic document archival, credential verification, and multimedia asset management. 

The application is architected from the ground up to utilize all five primary cloud service paradigms on **Microsoft Azure**:
1. **Platform as a Service (PaaS)** &mdash; Azure App Service Linux
2. **Database as a Service (DBaaS)** &mdash; Azure SQL Database
3. **Software / Storage as a Service (SaaS)** &mdash; Azure Blob Storage
4. **Security as a Service (SECaaS)** &mdash; Azure Key Vault & Managed Identity
5. **Infrastructure as a Service (IaaS)** &mdash; Azure Ubuntu Linux Virtual Machine in a dedicated VNet

### Student Project Team (Cloud Computing Mini Project)
* **Department**: Department of Computer Engineering / Information Technology
* **Academic Year**: 2025–2026

| Student Developer | Roll No | Project Role & Primary Responsibilities |
| :--- | :---: | :--- |
| **Ayush Todkar** | **57** | **Lead Cloud Architect & Full-Stack Developer** &bull; PaaS deployment orchestration, WSGI pipeline, multi-tenant document isolation, Google SSO, and UI/UX design. |
| **Yahiya Siddiqui** | **49** | **Database & Cloud Infrastructure Engineer** &bull; Azure SQL Database (DBaaS) relational schema, indexing, foreign keys, and IaaS VM uptime sentinel. |
| **Alister Varghese K.** | **03** | **Cloud Storage & Quota Systems Engineer** &bull; Azure Blob Storage integration, UUID namespaces, 5.0 GB student quota tracking (matching Azure Free Tier), and batch drag-and-drop. |
| **Jude Rebairo** | **31** | **Security, Access Control & QA Engineer** &bull; SECaaS security subsystem, scrypt password hashing, automated test suites (21 tests), and deep file integrity & threat scanner. |

---

## 2. High-Level Architecture Diagram

```text
                                  [ Students, Faculty & External Reviewers ]
                                                     │
                                                     ▼ HTTPS / TLS 1.3 (Port 443)
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. PaaS: Azure App Service (cloudvault-app)                                                            │
│    - Hostname: cloudvault-app-dmgveggdbxacbuct.centralindia-01.azurewebsites.net                      │
│    - Runtime: Python 3.12 / Linux Container                                                           │
│    - Production WSGI: Gunicorn (4 Worker Processes, Async Timeout: 600s)                              │
│    - Framework: Flask 3.0 + Jinja2 + Tailwind CSS 3 (Titanium Obsidian & Electric Iris Design)         │
│    - CI/CD: Automated GitHub Actions deployment from AyushTodkar404/CloudVault (branch: main)         │
└──────────────────┬─────────────────────────────┬────────────────────────────────────┬──────────────────┘
                   │                             │                                    │
   (System Managed Identity)          (SQL / TDS Connection)                 (Azure Storage SDK)
                   │                             │                                    │
                   ▼                             ▼                                    ▼
┌─────────────────────────────────┐ ┌───────────────────────────────┐ ┌──────────────────────────────────┐
│ 4. SECaaS: Azure Key Vault      │ │ 2. DBaaS: Azure SQL Database  │ │ 3. SaaS: Azure Blob Storage      │
│    (cloudvault-keyvault1)       │ │    (cloudvaultdb)             │ │    (cloudvault1)                 │
│    - Hardware Security Module   │ │    - Server: sqlserver-...    │ │    - Container: documents        │
│    - Secret: DatabaseUrl        │ │    - Relational multi-tenancy │ │    - Direct binary file store    │
│    - Secret: StorageConnString  │ │    - Encrypted password hashes│ │    - Previews & inline streaming │
│    - Zero plaintext in code     │ │    - Filtered unique indexing │ │    - 100MB universal upload size │
└─────────────────────────────────┘ └───────────────────────────────┘ └──────────────────────────────────┘
                   │
                   │ (Private Virtual Network: vnet-centralindia-1)
                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 5. IaaS: Azure Linux Virtual Machine (cloudvault1-vm)                                                  │
│    - OS: Ubuntu Server 22.04 LTS (Size: Standard_B1s Burstable Compute)                                │
│    - IP: cloudvault1-vm-ip | Network Security Group: cloudvault1-vm-nsg                                │
│    - Role: Edge network gateway, background monitoring daemon, and administrative bastion              │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 5 Cloud Computing Pillars: In-Depth Breakdown

### Pillar 1: PaaS (Platform as a Service)
* **Resource**: `cloudvault-app` (Azure App Service Linux)
* **Plan**: `ASP-rgcloudvaultlab-b081` (Free F1 / Basic B1)
* **What it does**:
  - Eliminates web server administration, operating system updates, and manual SSL certificate provisioning.
  - Automatically runs `startup.sh` on container boot, which executes:
    ```bash
    gunicorn --bind=0.0.0.0 --timeout 600 "app:create_app()"
    ```
  - Listens on internal port 8000 and maps externally to port 443 (HTTPS) with automated Microsoft SSL certificates.
  - Houses the complete Flask application factory (`create_app()`), routing tables, session state, and Jinja2 rendering pipeline.

### Pillar 2: DBaaS (Database as a Service)
* **Resource**: `sqlserver-cloudvault-xyz` &rarr; `cloudvaultdb` (Azure SQL Database)
* **Compute Tier**: Serverless Gen5 (1 vCore auto-scaling, auto-pausing)
* **What it does**:
  - Provides a managed relational database engine running Microsoft SQL Azure (RTM) - 12.0.2000.8.
  - Managed features: Automated daily backups, point-in-time recovery (PITR), threat detection, zero manual disk patching.
  - **Schema Highlights**:
    - `users`: Stores user identity, unique usernames, unique emails, scrypt-salted password hashes, and user roles (`student`, `admin`).
    - `documents`: Stores document title, student name, original filename, storage blob name, file size, MIME content type, star status, soft-delete flags, and foreign key reference (`user_id -> users.id`).
  - **SQL Server Specific Optimizations**:
    - Filtered unique index `ix_documents_share_token_filtered`: Accommodates Microsoft SQL Server's unique constraint behavior by allowing multiple `NULL` values (`WHERE share_token IS NOT NULL`).
    - Password URL-Sanitizer: Automatically translates special characters (e.g. `@` &rarr; `%40`) so connection strings parse flawlessly in all environments.

### Pillar 3: SaaS / Storage as a Service
* **Resource**: `cloudvault1` (Azure Storage Account)
* **Container**: `documents`
* **What it does**:
  - Serves as the high-durability, scalable object store for all physical files (PDFs, Word docs, Excel sheets, videos, audio, ZIPs).
  - Every uploaded file receives a cryptographically unique UUID prefix (e.g. `fcbf00c5b7_Resume.pdf`) to eliminate file collisions and directory traversal attacks.
  - Configures `Content-Disposition: inline` and dynamic MIME types so PDFs, images, code, and videos stream directly in browser preview modals.
  - Includes an automatic local filesystem fallback (`./uploads`) if running completely offline without Azure credentials.

### Pillar 4: SECaaS (Security as a Service)
* **Resource**: `cloudvault-keyvault1` (Azure Key Vault)
* **What it does**:
  - Implements **Zero-Trust Security**: No plaintext database credentials or storage keys are stored inside git repositories or plain configuration files.
  - Secrets stored:
    - `DatabaseUrl`: Full encrypted database connection string.
    - `StorageConnString`: Azure Blob Storage security token.
  - **System-Assigned Managed Identity**: `cloudvault-app` registers an Azure Active Directory (Entra ID) identity. The Key Vault assigns an Access Policy allowing only this specific identity to read keys via `@Microsoft.KeyVault(...)` syntax.

### Pillar 5: IaaS (Infrastructure as a Service)
* **Resource**: `cloudvault1-vm` (Azure Virtual Machine)
* **Network**: `vnet-centralindia-1` | **Security Group**: `cloudvault1-vm-nsg` | **Public IP**: `cloudvault1-vm-ip`
* **What it does**:
  - Demonstrates full root infrastructure control: custom kernel tuning, custom firewalls, and dedicated network interfaces (`cloudvault1-vm598`).
  - Acts as an asynchronous sentinel monitoring the health and uptime of the PaaS application over the `/health` endpoint.
  - Ready to serve as an asynchronous Celery task queue runner or private Nginx reverse proxy.

---

## 4. Authentication & Security Architecture

### 1. Modern Passwordless Google Sign-In
* Users can sign in with 1-click without creating passwords or entering credentials.
* **Dual-Mode Authentication**:
  1. **Emergent Zero-Config Mode**: Instant 1-click account chooser ([google_picker.html](file:///c:/CC_MINI_PROJECT/templates/google_picker.html)) allowing users to click their account card or type an institutional Google email to establish a secure authenticated session instantly.
  2. **Live OAuth 2.0 Mode**: Automatically redirects to `accounts.google.com/o/oauth2/v2/auth` when `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are supplied in production.
* Auto-provisions new users with a cryptographically randomized 256-bit password token, student role, and dedicated document vault.

### 2. Traditional Email & Password Auth
* Implements `werkzeug.security.generate_password_hash` utilizing the modern **scrypt** cryptographic key derivation function.
* Plaintext passwords are never logged, transmitted, or saved to the database.

### 3. Multi-Tenant Vault Isolation
* Document queries are strictly scoped to the active session user:
  ```python
  Document.query.filter_by(user_id=current_user.id, is_deleted=False)
  ```
* Users cannot view, modify, star, delete, or download documents belonging to other users.

### 4. Cryptographic Public Sharing
* Users can generate a public share link for any document.
* The link contains a high-entropy 256-bit URL-safe token (`secrets.token_urlsafe(32)`).
* Allows external examiners or employers to view and download certificates without needing an account, while keeping the main vault private.

---

## 5. File Upload & Processing Pipeline

```text
[ User Selects File ] ──> [ Client-Side Size & Type Validation ]
                                      │
                                      ▼ POST /upload (multipart/form-data)
                            [ Flask Application Worker ]
                                      │
                                      ▼
                      [ Deep File Integrity & Threat Scanner ]
                      - Magic binary header signature verification
                      - Polyglot / disguised executable block (MZ, ELF)
                      - Embedded script & webshell heuristic check
                      - Archive structure test (zipfile.testzip)
                      - Binary null flood check on text documents
                                      │
                ┌─────────────────────┴─────────────────────┐
                ▼                                           ▼
      [ Stream to Azure Blob ]                    [ Save Metadata to SQL ]
      - Generates UUID prefix                     - Student Name & Title
      - Sets MIME Content-Type                    - File Size & Extension
      - Uploads to container 'documents'          - Star & Delete Flags
      - Returns HTTPS blob URL                    - Links Foreign Key (user_id)
                │                                           │
                └─────────────────────┬─────────────────────┘
                                      │
                                      ▼
                        [ Flash Notification & UI Refresh ]
```

---

## 6. Project Directory Structure

```text
C:\CC_MINI_PROJECT\
│
├── .github/workflows/
│   └── main_cloudvault-app.yml   # Azure App Service CI/CD GitHub Actions workflow
│
├── instance/                     # Local SQLite fallback storage (when offline)
├── templates/
│   ├── base.html                 # Titanium Obsidian core master template + navbar
│   ├── index.html                # Main document registry dashboard & upload modal
│   ├── about.html                # Team, Technology Stack, 5 Models & Rubric
│   ├── login.html                # Secure sign-in portal with Google OAuth button
│   ├── signup.html               # Institutional student registration screen
│   ├── google_picker.html        # 1-Click Emergent Google Account Chooser
│   ├── share.html                # Public certificate & document viewer
│   └── 404.html                  # Custom glassmorphism error page
│
├── uploads/                      # Local offline storage folder (when Azure offline)
│
├── .env.example                  # Template configuration environment file
├── .gitignore                    # Ensures secrets, DBs, and virtualenvs never commit
├── app.py                        # Core Flask application factory, routing & auth
├── models.py                     # SQLAlchemy models (User, Document, ActivityLog)
├── requirements.txt              # Production Python package manifest
├── scanner.py                    # Deep byte integrity & malware heuristic engine
├── startup.sh                    # Linux App Service production Gunicorn boot script
├── storage.py                    # Azure Blob Storage SDK driver with scanner intercept
├── test_app.py                   # Automated test suite (21 integration & unit tests)
└── ARCHITECTURE.md               # This system architecture and operations manual
```

---

## 6. Enterprise Cloud Features (v2.5 Production Suite)

CloudVault includes 4 enterprise-grade capabilities that transition it into a complete, professional, production cloud storage platform:

### 1. Visual Storage Quota & Capacity Allocation Meter
- **Capacity Metering**: Real-time calculation of consumed bytes vs. 5.0 GB institutional cloud tier per tenant (matching Microsoft Azure Free Tier 5.0 GB Blob allocation).
- **Multi-Segment Color Spectrum**:
  - **Violet**: PDF credentials & research certificates.
  - **Cyan**: High-resolution imagery & photographs.
  - **Amber**: Audio recordings & video media.
  - **Emerald**: Excel, CSV, and tabular data spreadsheets.
  - **Rose**: Word documents & institutional summaries.
  - **Indigo**: Code repositories, compressed archives, and miscellaneous assets.
- **Quota Enforcement**: Backend intercept prevents storage exhaustion by rejecting uploads when the user's quota is reached.

### 2. Desktop Drag-and-Drop Multi-File Batch Uploader
- **Global Dropzone**: Full-screen reactive frosted glass overlay appears automatically when dragging files over any window surface.
- **Batch Processing**: Simultaneous multi-file upload (`request.files.getlist("file")`) with automatic title normalization and clean document titling.
- **Asynchronous AJAX Telemetry**: Real-time progress bar with live byte transfer percentages and automatic vault synchronization.

### 3. Quick Sorting & Smart Time Filtering
- **Multi-Vector Sorting**: Sort by Newest First, Oldest First, Name (A-Z), Name (Z-A), Largest Size, and Smallest Size.
- **Time Range Filtering**: Instant filtering by All Time, Today (past 24h), Past 7 Days, and Past 30 Days.
- **Hybrid Performance**: Instant zero-latency client-side filtering combined with server-side query parameter persistence (`?sort=...&time=...&category=...`).

### 4. Cloud Security Audit & Activity Telemetry (SECaaS)
- **Immutable Audit Trail**: Chronological event tracking table (`ActivityLog`) in Azure SQL Database.
- **Tracked Security Actions**:
  - `SIGNUP`: New account registrations and Google SSO provisioning.
  - `LOGIN` / `LOGOUT`: Credential verifications and session terminations.
  - `UPLOAD`: File ingestion with byte size and integrity hash tracking.
  - `STAR` / `UNSTAR`: Bookmark and favorite state changes.
  - `SHARE`: Cryptographic public token generation.
  - `TRASH` / `RESTORE`: Recycle bin state transitions.
  - `DELETE`: Permanent blob removal from hot storage.
  - `BATCH`: Multi-file bulk operations (ZIP export, bulk delete, bulk restore).
- **In-App SECaaS Viewer**: Interactive modal drawer with color-coded badges, masked client IP logging, and live synchronization via `/api/activity-log`.

---

## 7. Automated Test Suite & Quality Verification

Run the comprehensive test suite locally:
```powershell
python test_app.py
```

### Verified Test Cases:
1. `test_home_redirect_when_anonymous`: Unauthenticated visitors redirect to `/login`.
2. `test_user_registration`: Account creation, password hashing, duplicate rejection.
3. `test_user_login_logout`: Authentication credentials verification and session invalidation.
4. `test_authenticated_dashboard`: Logged-in user accesses dashboard.
5. `test_document_upload_and_tenant_isolation`: Verifies User A cannot see User B's files.
6. `test_cloud_storage_manager_fallback`: Validates seamless fallback when Azure keys are absent.
7. `test_universal_file_upload_categories`: Verifies Word, Excel, PDF, Audio, Video, Archives.
8. `test_cloud_storage_advanced_features`: Tests starring, soft-delete, restore, and public sharing.
9. `test_google_oauth_flow`: Validates OAuth initiation, state tracking, and token callback.
10. `test_emergent_zero_config_google_login`: Tests 1-click passwordless login and account picker.
11. `test_multi_file_batch_upload_and_ajax`: Verifies batch multi-upload and AJAX drag-and-drop response.
12. `test_storage_quota_calculation_and_enforcement`: Verifies 5.0 GB quota calculations and enforcement.
13. `test_quick_sorting_and_time_filtering`: Validates alphabetical sorting, time ranges, and category filters.
14. `test_security_audit_activity_log_and_api`: Verifies SQL telemetry tracking and `/api/activity-log` endpoint.

---

## 8. Continuous Deployment (Local to Cloud Workflow)

Whenever you make updates to the codebase:

```powershell
# 1. Stage changes
git add .

# 2. Commit with a message
git commit -m "feat: added new cloud capability"

# 3. Push to GitHub
git push origin main
```

**Automated CI/CD**:
1. GitHub Actions triggers `.github/workflows/main_cloudvault-app.yml`.
2. Builds dependencies from `requirements.txt`.
3. Deploys code to `cloudvault-app` in Central India.
4. Live site reflects changes in ~60-90 seconds with zero downtime.

---

## 9. Viva / Lab Examination Cheatsheet

### Q1: What makes this application a true PaaS architecture?
> **Answer**: The application is deployed to **Azure App Service (Linux)**. The cloud provider handles OS updates, hardware provisioning, web server routing (reverse proxy), TLS/SSL certificate renewal, and horizontal scaling. We only maintain the application code and WSGI configuration (`startup.sh`).

### Q2: Why use DBaaS instead of hosting SQL on an IaaS Virtual Machine?
> **Answer**: **Azure SQL Database** is a managed Database as a Service. It provides built-in automated daily backups, point-in-time recovery, threat detection, high availability (99.99% SLA), and automated patching without requiring us to manage database server daemons, storage partitions, or disk space manually.

### Q3: What is the benefit of Azure Blob Storage (SaaS) over local disk storage?
> **Answer**: Local disks in containerized cloud environments are ephemeral (they reset on restart or scaling). **Azure Blob Storage** provides durable, multi-region replicated object storage. Uploaded files exist independently of web app restarts and scale up to petabytes without disk re-partitioning.

### Q4: How does Azure Key Vault implement SECaaS?
> **Answer**: Storing database passwords in configuration files or code commits is a major vulnerability. With **Azure Key Vault** and **System-Assigned Managed Identity**, the web app authenticates to the vault via Azure Active Directory. Passwords are never written in plaintext, enabling automated secret rotation and centralized security auditing.

### Q5: How is IaaS integrated into this project?
> **Answer**: We have an **Azure Linux Virtual Machine (`cloudvault1-vm`)** deployed within our private **Virtual Network (`vnet-centralindia-1`)**. Unlike PaaS where we cannot touch the OS, the IaaS VM provides complete root shell access to configure network routing, custom daemons, and background maintenance services.

---

## 10. Genuine Upload Protection & File Validation Engine

CloudVault enforces strict, multi-layered file validation to guarantee that only genuine, legitimate files enter the cloud storage repository:

1. **Extension Whitelisting**:
   - Only permitted file formats: documents (`pdf`, `doc`, `docx`, `txt`, `rtf`, `odt`), spreadsheets (`xls`, `xlsx`, `csv`), presentations (`ppt`, `pptx`), images (`png`, `jpg`, `webp`, `svg`), media (`mp4`, `webm`, `mp3`, `wav`), archives (`zip`, `tar`, `gz`, `7z`), and source code (`py`, `js`, `json`, `sql`, `md`).
2. **Malware & Executable Blacklisting**:
   - Dangerous formats (`.exe`, `.bat`, `.cmd`, `.sh`, `.ps1`, `.vbs`, `.msi`, `.dll`, `.com`, `.scr`, `.pif`, `.reg`, `.wsf`, `.hta`, `.cpl`, `.jar`) are blocked at both client and server boundaries.
3. **Empty File (0-Byte) Rejection**:
   - Files with 0 bytes are rejected immediately before storage dispatch, preventing empty blobs and wasted cloud resources.
4. **Filename Sanitization**:
   - `secure_filename()` strips directory traversal attempts (`../`) and illegal character sequences before assigning unique cryptographic storage identifiers.
5. **Test Environment Isolation**:
   - Automated tests run against ephemeral temporary storage directories (`tempfile.TemporaryDirectory()`), completely isolating developer test runs from production upload directories.

---

*CloudVault &bull; Engineered with Microsoft Azure Cloud Architecture &bull; 2026*
