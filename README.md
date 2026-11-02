# CloudVault: Digital Document & Certificate Portal

A secure, responsive, production-grade cloud portal designed for a University Cloud Computing Lab. **CloudVault** enables students and faculty to upload digital documents, diplomas, certificates, and lab reports, securely storing binaries in **Azure Blob Storage** while managing relational metadata in **Azure SQL Database** (or local SQLite/PostgreSQL) via **SQLAlchemy**.

> [!IMPORTANT]
> ### 🔑 Cloud Prerequisite: Active Microsoft Azure Account Required
> To use CloudVault with full cloud persistence, live storage, and multi-service capabilities, you **must have an active Microsoft Azure account** (e.g., *Azure for Students* with \$100 free credit, or an *Azure Free Tier* subscription).
> 
> * **Sandboxed Offline Mode**: Without Azure credentials, the app operates in local fallback mode (saving files to `./uploads` and metadata to SQLite).
> * **Full Cloud Mode**: To activate all 5–6 cloud services (**SaaS**, **PaaS**, **DBaaS**, **SECaaS**, **IaaS**, and **SSO**), follow the [Connecting Your Azure Account Guide](#-connecting-your-azure-account-all-56-cloud-services) below to link your Azure resources when running on any device.

---

## 👥 Engineering Team & Developers

| Name | Roll No. | Project Responsibility |
|:---|:---:|:---|
| **Ayush Todkar** | **57** | Lead Cloud Architect & Full-Stack Developer (Azure App Service PaaS, Flask, UI, CI/CD) |
| **Yahiya Siddiqui** | **49** | Database & Cloud Infrastructure Engineer (Azure SQL DBaaS, Schema, Sentinel) |
| **Alister Varghese K.** | **03** | Cloud Storage & Quota Systems Engineer (Azure Blob Storage SaaS, 5GB Quotas, Batch Upload) |
| **Jude Rebairo** | **31** | Cloud Security & Threat Protection Engineer (Zero-Trust SECaaS, Magic-Byte Scanner) |

---

## ☁️ 5 Core Cloud Computing Service Models Implemented

CloudVault directly demonstrates and validates five essential Cloud Computing service delivery models:

| Service Model | Implementation in CloudVault | Cloud Provider & Tech Stack | Key Capabilities & Evaluation Rubric |
|:---|:---|:---|:---|
| **SaaS**<br>*(Software as a Service)* | **CloudVault Web Application & Portal** | Azure Blob Storage & Watermelon UI | End-user document vault, direct in-browser PDF/image/media preview, 1-click downloads, 5.0 GB per-user quota allocation, and offline queueing with IndexedDB auto-sync. |
| **PaaS**<br>*(Platform as a Service)* | **Managed Web Compute Runtime** | Azure App Service (Linux B1 Plan, Central India) | Containerized Python 3.12 / Flask / Gunicorn WSGI pipeline, automatic TLS 1.3 termination, zero server patching, automated CI/CD via GitHub Actions. |
| **DBaaS**<br>*(Database as a Service)* | **Relational Metadata Store** | Azure SQL Database (`cloudvaultdb`) | Fully managed relational database, ACID transactions, foreign keys (`users.id` -> `documents.user_id`), automated daily backups, auto-indexing. |
| **SECaaS**<br>*(Security as a Service)* | **Zero-Trust Security & Threat Scanner** | Custom `scanner.py` + Scrypt / Key Vault | Deep magic-byte inspection (blocking disguised executables, webshells, corrupt archives), per-user data isolation, SHA-256 integrity anchors, security audit trail. |
| **IaaS**<br>*(Infrastructure as a Service)* | **Virtual Network Linux Sentinel** | Azure Ubuntu Linux VM (`cloudvault1-vm`) | Dedicated Ubuntu Linux VM inside a private Virtual Network (VNet) with custom Network Security Group (NSG) firewall rules polling `/health`. |

---

## 🏛️ Cloud Architecture Overview

```
                                      +---------------------------------------------+
                                      |             Azure Key Vault                 |
                                      |  (Stores Storage Keys & DB Credentials)    |
                                      +----------------------+----------------------+
                                                             | Key Vault Reference
                                                             v
+------------------+         HTTPS          +---------------------------------------+
|  Client Browser  | <====================> |       Azure App Service (Linux)       |
| (Watermelon UI)  |                        |       Python 3.12 / Flask / Gunicorn  |
+------------------+                        +-------------------+-------------------+
        ^                                                       |
        |                                      +----------------+---------------+
        |                                      |                                |
        | Direct Link (Download/View)          v                                v
+-------+--------------------+      +----------------------+        +-----------------------+
| Azure Blob Storage         |      | Azure Blob SDK       |        | SQLAlchemy Driver     |
| Container: `documents`     | <=== | `azure-storage-blob` |        | Azure SQL / SQLite    |
| (Hot Tier Object Store)    |      +----------------------+        +-----------+-----------+
+----------------------------+                                                  |
                                                                                v
                                                                    +-----------------------+
                                                                    | Azure SQL Database    |
                                                                    | (Metadata & Records)  |
                                                                    +-----------------------+
```

---

## 🔌 Connecting Your Azure Account (All 5–6 Cloud Services)

When running CloudVault locally on your computer or deploying it to your own cloud instance, follow this guide to connect all **5–6 Azure services** from your active Azure account:

### 1. SaaS & Object Storage: Azure Blob Storage
* **Step A (Create Account)**: In [Azure Portal](https://portal.azure.com), navigate to **Storage accounts** > click **+ Create** > select your subscription & resource group > give it a name (e.g., `cloudvaultstore1`) > set redundancy to **Standard LRS**.
* **Step B (Create Container)**: Open your new Storage account > go to **Data storage > Containers** > click **+ Container** > name it **`documents`** > click **Create**.
* **Step C (Copy Key)**: In the storage account menu, select **Security + networking > Access keys** > click **Show keys** next to **key1** > copy the **Connection string**.
* **Step D (Configure)**: Set in your `.env` file (or Azure App Service App Settings):
  ```env
  AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=<your-account-name>;AccountKey=<your-key>;EndpointSuffix=core.windows.net"
  AZURE_STORAGE_CONTAINER_NAME="documents"
  ```

---

### 2. DBaaS: Azure SQL Database
* **Step A (Create Database)**: In Azure Portal, search for **SQL databases** > click **+ Create** > select database name **`cloudvaultdb`** > click **Create new** under Server > provide a server name (e.g., `sqlserver-cloudvault-<name>`), admin login, and password > select **Compute + storage: Basic** or **Serverless Gen5**.
* **Step B (Configure Firewall)**: Open your SQL Server resource > under **Security**, select **Networking** > check **"Allow Azure services and resources to access this server"** > click **+ Add your client IPv4 address** so your local device can connect > click **Save**.
* **Step C (Copy Connection String)**: Open your `cloudvaultdb` database resource > click **Settings > Connection strings** > copy the **ODBC** or **ADO.NET** string.
* **Step D (Configure)**: Set in your `.env` file:
  ```env
  DATABASE_URL="mssql+pyodbc://<admin-user>:<admin-password>@<your-server>.database.windows.net:1433/cloudvaultdb?driver=ODBC+Driver+18+for+SQL+Server"
  ```
  *(Or if using the pure-Python driver without installing ODBC drivers: `mssql+pymssql://<admin-user>:<admin-password>@<your-server>.database.windows.net:1433/cloudvaultdb`)*.

---

### 3. PaaS: Azure App Service (Linux Web App)
* **Step A (Create Web App)**: In Azure Portal, search for **App Services** > click **+ Create** > select **Web App**:
  * **Runtime stack**: `Python 3.12`
  * **Operating System**: `Linux`
  * **Pricing Plan**: `Basic B1` (or `Free F1`)
* **Step B (Inject Environment Variables)**: Go to your App Service > select **Settings > Environment variables** (Application settings) > add:
  * `AZURE_STORAGE_CONNECTION_STRING` = `[Your Connection String from Step 1]`
  * `AZURE_STORAGE_CONTAINER_NAME` = `documents`
  * `DATABASE_URL` = `[Your SQL Database URL from Step 2]`
  * `SECRET_KEY` = `[Generate a secure 64-char random hex string]`
  * `SCM_DO_BUILD_DURING_DEPLOYMENT` = `true`
* **Step C (Startup Command)**: Under **Settings > Configuration > General settings**, ensure the startup command is set to:
  ```bash
  startup.sh
  ```
  *(Or: `gunicorn --bind=0.0.0.0 --timeout 600 "app:create_app()"`)*.

---

### 4. SECaaS: Azure Key Vault & Managed Identity
* **Step A (Create Key Vault)**: Search for **Key Vaults** in Azure Portal > click **+ Create** > choose your resource group > name your vault (e.g., `kv-cloudvault-<name>`).
* **Step B (Add Secrets)**: Under **Objects > Secrets**, click **+ Generate/Import**:
  * Name: `BlobStorageConn` &bull; Value: `[Your Storage Connection String]`
  * Name: `DatabaseUrl` &bull; Value: `[Your SQL Database Connection String]`
* **Step C (Assign Web App Identity)**: Open your Azure App Service > under **Settings**, select **Identity** > set **System assigned** status to **On** > click **Save**.
* **Step D (Grant Key Vault Access)**: Open your Key Vault > **Access policies** (or Azure role assignments) > add policy > select Secret permissions: **Get**, **List** > select the Web App's managed identity > click **Save**.
* **Step E (Reference Secrets)**: In App Service Environment variables, reference your Key Vault directly:
  ```env
  AZURE_STORAGE_CONNECTION_STRING="@Microsoft.KeyVault(VaultName=<your-kv-name>;SecretName=BlobStorageConn)"
  ```

---

### 5. IaaS: Azure Linux Virtual Machine (Uptime Sentinel)
* **Step A (Deploy Ubuntu VM)**: In Azure Portal, search for **Virtual machines** > click **+ Create** > select:
  * **OS**: `Ubuntu Server 22.04 LTS`
  * **Size**: `Standard_B1s` (burstable compute)
  * **VNet**: Place within `vnet-centralindia-1` (or your regional VNet)
  * **Inbound Ports**: Allow SSH (Port 22)
* **Step B (Run Health Sentinel)**: SSH into your VM and run the automated health monitoring daemon querying your PaaS `/health` endpoint:
  ```bash
  ssh azureuser@<your-vm-ip>
  
  # Probe your PaaS endpoint to verify uptime & cloud storage connectivity
  curl -s https://<your-app-name>.azurewebsites.net/health | jq
  ```

---

### 6. Identity & Google SSO (Optional 6th Service)
* **Zero-Config Instant Chooser**: CloudVault includes an instant Google Account Chooser UI enabled by default.
* **Live Google OAuth 2.0 Mode**:
  1. Visit [Google Cloud Console](https://console.cloud.google.com/) > **APIs & Services > Credentials**.
  2. Create an **OAuth 2.0 Web Client ID**.
  3. Add Authorized redirect URIs:
     * `http://localhost:5000/login/google/callback` (Local)
     * `https://<your-app-name>.azurewebsites.net/login/google/callback` (Production)
  4. Add to `.env`:
     ```env
     GOOGLE_CLIENT_ID="<your-client-id>.apps.googleusercontent.com"
     GOOGLE_CLIENT_SECRET="<your-client-secret>"
     ```

---

## 📂 Project Structure

```text
c:\CC_MINI_PROJECT\
├── app.py                  # Flask application factory, auth routes & document controller
├── models.py               # SQLAlchemy User, Document & ActivityLog database schemas
├── storage.py              # Azure Blob Storage integration & fallback manager
├── scanner.py              # Deep security & integrity scanner (magic bytes, webshells, archives)
├── requirements.txt        # Production dependencies (Flask, Flask-Login, azure-storage-blob)
├── startup.sh              # Gunicorn WSGI startup script for Azure App Service Linux
├── .env.example            # Environment variables configuration template
├── .gitignore              # Ignored files (venv, .env, *.db, temporary uploads)
├── test_app.py             # Automated test suite (29 unit & integration tests)
├── ARCHITECTURE.md         # Full cloud architectural specifications & operations manual
├── README.md               # Architecture documentation, local setup & Azure connection guide
└── templates/
    ├── base.html           # Watermelon UI layout, navigation bar, Activity Log modal & theme
    ├── index.html          # Document registry dashboard, metrics, filters & batch dropzone
    ├── about.html          # Team, technology stack, and 5 Cloud Service Models breakdown
    ├── share.html          # Secure public recipient view for shared documents
    ├── login.html          # Clean sign-in page with 1-click Google account picker
    ├── signup.html         # User registration page with real-time strength validation
    ├── google_picker.html  # Dark theme Google account picker interface
    ├── loading.html        # Snappy resilient transition loading interface
    ├── privacy.html        # Institutional privacy governance policy
    ├── terms.html          # Acceptable use and academic data terms
    └── 404.html            # Clean 404 error page
```

---

## 🚀 Quickstart: Local Development Setup

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.12)
- **Git**
- **Active Microsoft Azure Account** (for live cloud storage & database)

### 2. Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/AyushTodkar404/CloudVault.git
cd CloudVault

# Create virtual environment
python -m venv venv

# Activate on Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Or on Linux/macOS:
# source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Your Local `.env` File
Copy `.env.example` to `.env`:
```bash
copy .env.example .env
```

Open `.env` and configure your credentials from the [Azure Connection Guide](#-connecting-your-azure-account-all-56-cloud-services):
```env
# Flask Security
SECRET_KEY=generate-a-strong-secret-key-3.14

# Database Configuration (DBaaS)
# Option A: Local SQLite development fallback
DATABASE_URL=sqlite:///cloudvault.db
# Option B: Live Azure SQL Database
# DATABASE_URL=mssql+pyodbc://<admin-user>:<admin-password>@<your-server>.database.windows.net:1433/cloudvaultdb?driver=ODBC+Driver+18+for+SQL+Server

# Azure Blob Storage Configuration (SaaS)
AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=<your-storage-account>;AccountKey=<your-account-key>;EndpointSuffix=core.windows.net
AZURE_STORAGE_CONTAINER_NAME=documents

# Optional: Set to 'true' if running strictly offline without Azure access
LOCAL_STORAGE_FALLBACK=false
```

### 5. Run the Application
```bash
python app.py
```
Open your browser and navigate to **`http://localhost:5000`**.

### 6. Verify Cloud Connectivity
Verify that your local instance connects to your Azure services:
```bash
curl http://localhost:5000/health
```
Expected response when connected:
```json
{
  "app": "CloudVault",
  "cloud_storage_connected": true,
  "container": "documents",
  "status": "healthy",
  "storage_diag": null
}
```

### 7. Run Automated Tests
Execute the complete test suite:
```bash
python -m unittest test_app.py -v
```
*(All 29 test vectors should pass with `OK`).*

---

## ☁️ Azure Cloud Deployment Guide (Azure CLI)

To provision and deploy CloudVault directly from the Azure CLI:

### Step 1: Set Variables & Create Resource Group
```bash
RESOURCE_GROUP="rg-cloudvault-lab"
LOCATION="centralindia"
STORAGE_ACCOUNT="cloudvaultstore$RANDOM"
CONTAINER_NAME="documents"
SQL_SERVER="cloudvault-sql-$RANDOM"
SQL_DB="cloudvaultdb"
SQL_ADMIN="cloudadmin"
SQL_PASSWORD="<YourStrongPasswordHere123!>"
APP_PLAN="plan-cloudvault"
APP_NAME="cloudvault-app-$RANDOM"

# Create Resource Group
az group create --name $RESOURCE_GROUP --location $LOCATION
```

### Step 2: Provision Azure Blob Storage (SaaS)
```bash
# Create Storage Account
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS

# Retrieve Connection String
AZURE_STORAGE_CONNECTION_STRING=$(az storage account show-connection-string \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --query connectionString -o tsv)

# Create Documents Container
az storage container create \
  --name $CONTAINER_NAME \
  --account-name $STORAGE_ACCOUNT
```

### Step 3: Provision Azure SQL Database (DBaaS)
```bash
# Create Azure SQL Server
az sql server create \
  --name $SQL_SERVER \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --admin-user $SQL_ADMIN \
  --admin-password "$SQL_PASSWORD"

# Allow Azure Services to access the SQL Server
az sql server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --server $SQL_SERVER \
  --name "AllowAzureServices" \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0

# Create the Database
az sql db create \
  --resource-group $RESOURCE_GROUP \
  --server $SQL_SERVER \
  --name $SQL_DB \
  --service-objective Basic
```

### Step 4: Deploy to Azure App Service (PaaS)
```bash
# Create App Service Plan (Basic B1 or Free F1)
az appservice plan create \
  --name $APP_PLAN \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --is-linux \
  --sku B1

# Create Web App with Python 3.12 runtime
az webapp create \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_PLAN \
  --name $APP_NAME \
  --runtime "PYTHON:3.12"

# Configure Application Settings (Environment Variables)
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --settings \
    AZURE_STORAGE_CONNECTION_STRING="$AZURE_STORAGE_CONNECTION_STRING" \
    AZURE_STORAGE_CONTAINER_NAME="$CONTAINER_NAME" \
    DATABASE_URL="mssql+pyodbc://$SQL_ADMIN:$SQL_PASSWORD@$SQL_SERVER.database.windows.net:1433/$SQL_DB?driver=ODBC+Driver+18+for+SQL+Server" \
    SECRET_KEY="$(openssl rand -hex 32)" \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true

# Deploy Code via Zip or Azure CLI
az webapp up \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME
```

---

## 🔒 Security & Best Practices Implemented

- **Password Cryptography**: Passwords salted and hashed with `werkzeug.security` using modern `scrypt`.
- **Two-Factor Authentication (MFA / 2FA)**: RFC 6238 Time-Based One-Time Passwords (TOTP) natively supported via standard authenticator apps (Google Authenticator, Microsoft Authenticator, Apple Passwords).
- **Tenant Vault Isolation**: `@login_required` enforced on all repository data; documents are strictly filtered by `current_user.id`.
- **Zero Credentials in Code**: Database passwords and storage keys are never committed; loaded via environment variables or encrypted secrets.
- **Cryptographic Filenames**: Prefixed with `uuid4().hex[:10]` preventing file collision and directory traversal attacks.
- **Deep Threat Scanning**: Inspects binary magic numbers, blocks disguised executables (`.exe`, `.dll`, `.elf`), detects webshell injection patterns, and tests archive integrity.
- **OWASP Top 10 Headers**: Automated emission of HSTS, CSP, X-Frame-Options (SAMEORIGIN), X-Content-Type-Options (nosniff), and X-XSS-Protection.

---

## 📜 License
Developed for Academic & University Cloud Computing Labs. MIT License &copy; 2026.
