# CloudVault: Digital Document & Certificate Portal

A secure, responsive, production-ready cloud portal designed for a University Cloud Computing Lab. **CloudVault** enables students and faculty to upload digital documents, diplomas, certificates, and lab reports, securely storing binaries in **Azure Blob Storage** while managing relational metadata in **Azure SQL Database** (or local SQLite/PostgreSQL) via **SQLAlchemy**.

---

## 👥 Engineering Team & Developers

| Name | Roll No. | Project Responsibility |
|:---|:---:|:---|
| **Ayush Todkar** | **57** | Lead Cloud Architect & Full-Stack Developer (Azure App Service PaaS, Flask, UI, CI/CD) |
| **Yahiya Siddiqui** | **49** | Database & Cloud Infrastructure Engineer (Azure SQL DBaaS, Schema, Sentinel) |
| **Alister Varghese K.** | **03** | Cloud Storage & Quota Systems Engineer (Azure Blob Storage SaaS, 5GB Quotas, Batch Upload) |
| **Jude Rebairo** | **31** | Cloud Security & Threat Protection Engineer (Zero-Trust SECaaS, Magic-Byte Scanner) |

---

## ☁️ 4 Core Cloud Computing Service Models Implemented

CloudVault directly demonstrates and validates four essential Cloud Computing service delivery models:

| Service Model | Implementation in CloudVault | Cloud Provider & Tech Stack | Key Capabilities & Evaluation Rubric |
|:---|:---|:---|:---|
| **SaaS**<br>*(Software as a Service)* | **CloudVault Web Application & Portal** | Azure Blob Storage & Modern Quartz UI | End-user document vault, direct in-browser PDF/image/media preview, 1-click downloads, 5.0 GB per-user quota allocation, and offline queueing with IndexedDB auto-sync. |
| **PaaS**<br>*(Platform as a Service)* | **Managed Web Compute Runtime** | Azure App Service (Linux B1 Plan, Central India) | Containerized Python 3.12 / Flask / Gunicorn WSGI pipeline, automatic TLS 1.3 termination, zero server patching, automated CI/CD via GitHub Actions. |
| **DBaaS**<br>*(Database as a Service)* | **Relational Metadata Store** | Azure SQL Database (`cloudvaultdb`) | Fully managed relational database, ACID transactions, foreign keys (`users.id` -> `documents.user_id`), automated daily backups, auto-indexing. |
| **SECaaS**<br>*(Security as a Service)* | **Zero-Trust Security & Threat Scanner** | Custom `scanner.py` + Scrypt / PBKDF2-SHA256 | Deep magic-byte inspection (blocking disguised executables, webshells, corrupt archives), per-user data isolation, SHA-256 integrity anchors, security audit trail. |
| *(Bonus) **IaaS***<br>*(Infrastructure as a Service)* | **Virtual Network Linux Sentinel** | Azure Ubuntu Linux VM (`cloudvault1-vm`) | Dedicated Ubuntu Linux VM inside a private Virtual Network (VNet) with custom Network Security Group (NSG) firewall rules. |

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
| (Tailwind UI)    |                        |       Python 3.12 / Flask / Gunicorn  |
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

### Integrated Azure Services
1. **Azure App Service (Linux Web App)**: Hosts the containerized or native Python Flask backend running under Gunicorn.
2. **Azure Blob Storage**: High-durability, scalable cloud object storage for binary files (PDFs, certificates, images) with inline viewing capabilities.
3. **Azure SQL Database**: Relational cloud database storing student credentials, file sizes, timestamps, and blob locator URIs.
4. **Azure Key Vault**: Safeguards connection strings, database passwords, and app secrets, consumed via Azure App Service Key Vault references (`@Microsoft.KeyVault(...)`).

---

## 📂 Project Structure

```text
c:\CC_MINI_PROJECT\
├── app.py                  # Flask application factory, auth routes & document controller
├── models.py               # SQLAlchemy User & Document database schemas & password hashing
├── storage.py              # Cloud storage integration & local fallback manager
├── scanner.py              # Deep security & integrity scanner (magic bytes, webshells, archives)
├── requirements.txt        # Production dependencies (Flask, Flask-Login, azure-storage-blob)
├── .env.example            # Environment variables configuration template
├── .gitignore              # Ignored files (venv, .env, *.db, temporary uploads)
├── test_app.py             # Automated test suite (23 unit tests covering auth, upload, SECaaS)
├── README.md               # Architecture documentation, local setup & VM deployment guide
└── templates/
    ├── base.html           # Layout with dynamic session header, preview modal & OfflineVault
    ├── index.html          # Dashboard: Metrics, view switcher, drag-and-drop, offline queue
    ├── about.html          # Project summary, developers, tech stack & cloud service models
    ├── share.html          # Secure public recipient view for shared documents
    ├── login.html          # Modern quartz glassmorphic sign in page
    ├── signup.html         # User registration page with institutional validation
    └── 404.html            # User-friendly 404 error page
```

---

## 🚀 Quickstart: Local Development Setup

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.12)
- **Git**

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

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
copy .env.example .env
```
Open `.env` and configure your settings:
```env
SECRET_KEY=generate-a-strong-secret-key
DATABASE_URL=sqlite:///cloudvault.db
AZURE_STORAGE_CONNECTION_STRING=your_azure_storage_connection_string
AZURE_STORAGE_CONTAINER_NAME=documents
LOCAL_STORAGE_FALLBACK=false
```
> **Note for Offline/Sandbox Testing:** If you haven't provisioned Azure credentials yet, CloudVault automatically operates in **Local Vault Mode**, saving files safely to a local `uploads/` folder while keeping the exact same UI and route behaviors.

### 5. Run the Application
```bash
python app.py
```
Open your browser and navigate to **`http://localhost:5000`**.

### 6. Run Automated Tests
```bash
python -m unittest test_app.py -v
```

---

## ☁️ Azure Cloud Deployment Guide

Follow these steps using the **Azure CLI** to deploy CloudVault into production.

### Step 1: Set Variables & Create Resource Group
```bash
# Variables
RESOURCE_GROUP="rg-cloudvault-lab"
LOCATION="eastus"
STORAGE_ACCOUNT="cloudvaultstore$RANDOM"
CONTAINER_NAME="documents"
SQL_SERVER="cloudvault-sql-$RANDOM"
SQL_DB="cloudvaultdb"
SQL_ADMIN="cloudadmin"
SQL_PASSWORD="SecureVaultPassword123!"
APP_PLAN="plan-cloudvault"
APP_NAME="cloudvault-portal-$RANDOM"

# Create Resource Group
az group create --name $RESOURCE_GROUP --location $LOCATION
```

### Step 2: Provision Azure Blob Storage
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

# Create Public Blob Container
az storage container create \
  --name $CONTAINER_NAME \
  --account-name $STORAGE_ACCOUNT \
  --public-access blob
```

### Step 3: Provision Azure SQL Database
```bash
# Create Azure SQL Server
az sql server create \
  --name $SQL_SERVER \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --admin-user $SQL_ADMIN \
  --admin-password $SQL_PASSWORD

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

### Step 4: Deploy to Azure App Service (Linux)
```bash
# Create App Service Plan (Free or Basic tier for labs)
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

# Deploy Code via Zip or Git
az webapp up \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME
```

### Step 5: (Optional) Azure Key Vault Secret Integration
For maximum security in production, store secrets in **Azure Key Vault** and reference them in App Service:
```bash
KEYVAULT_NAME="kv-cloudvault-$RANDOM"

# 1. Create Key Vault
az keyvault create --name $KEYVAULT_NAME --resource-group $RESOURCE_GROUP --location $LOCATION

# 2. Store Secrets
az keyvault secret set --vault-name $KEYVAULT_NAME --name "BlobStorageConn" --value "$AZURE_STORAGE_CONNECTION_STRING"

# 3. Enable System-Assigned Identity on Web App
PRINCIPAL_ID=$(az webapp identity assign --name $APP_NAME --resource-group $RESOURCE_GROUP --query principalId -o tsv)

# 4. Grant Web App permission to read secrets
az keyvault set-policy --name $KEYVAULT_NAME --object-id $PRINCIPAL_ID --secret-permissions get

# 5. Set App Service Key Vault Reference
az webapp config appsettings set --name $APP_NAME --resource-group $RESOURCE_GROUP --settings \
  AZURE_STORAGE_CONNECTION_STRING="@Microsoft.KeyVault(VaultName=$KEYVAULT_NAME;SecretName=BlobStorageConn)"
```

---

## 🖥️ Azure VM Deployment & Sync Guide

To deploy or update CloudVault on your remote Azure Linux VM (`ayushtodkar404@20.198.67.116:~/cloudvault-app`):

### 1. Database Reset / Migration Command
Because the schema now includes the `users` table and `documents.user_id` foreign key:
```powershell
# On Local Machine or Remote VM to cleanly recreate schema:
python -c "from app import app, db; with app.app_context(): db.create_all(); print('Database schema updated successfully.')"
```
*(If using SQLite and starting fresh, you can remove `cloudvault.db` and the app will auto-create the new schema on boot).*

### 2. Sync Files from Local Machine to Azure VM via `scp`
Run the following PowerShell command from `C:\CC_MINI_PROJECT`:
```powershell
# Transfer project files excluding local caches & environments:
scp -r app.py models.py storage.py requirements.txt .env.example README.md templates test_app.py ayushtodkar404@20.198.67.116:~/cloudvault-app/
```

### 3. Remote VM Execution & Service Restart
SSH into the Azure VM and start or restart the application:
```bash
ssh ayushtodkar404@20.198.67.116

# Navigate to application directory
cd ~/cloudvault-app

# Activate virtualenv and install updated dependencies
source venv/bin/activate
pip install -r requirements.txt

# Run database schema migration/creation
python -c "from app import app, db; with app.app_context(): db.create_all()"

# Restart with Gunicorn or systemd service
# If running via systemd:
sudo systemctl restart cloudvault
# Or running in background with Gunicorn:
gunicorn -w 4 -b 0.0.0.0:5000 app:app --daemon
```

---

## 🔒 Security & Best Practices Implemented

- **Password Cryptography**: Passwords salted and hashed with `werkzeug.security` (PBKDF2-SHA256).
- **Session Isolation**: `@login_required` enforced on all repository data; documents are bound to `current_user.id`.
- **Zero Credentials in Code**: Database and storage secrets dynamically sourced from `.env` via `os.getenv`.
- **Cryptographic Filenames**: Prefixed with `uuid4().hex[:10]` preventing file collision attacks.
- **Path Sanitization**: `werkzeug.utils.secure_filename` protects against directory traversal.
- **Strict File Type & Size Limits**: Whitelisted formats (PDF, PNG, JPG, DOCX) and 16MB maximum request ceiling.

---

## 📜 License
Developed for Academic & University Cloud Computing Labs. MIT License &copy; 2026.
