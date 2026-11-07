# Architecture Map: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

## System Overview
CloudVault is an enterprise document registry and credential validation platform built on Microsoft Azure's 5 core cloud service pillars:
1. **PaaS (Azure App Service):** Web application hosting, Python 3.12 container, TLS termination, automatic SSL renewal.
2. **DBaaS (Azure SQL Database):** Relational schema storage for users, metadata, audit trails, and share tokens.
3. **SaaS / Object Storage (Azure Blob Storage):** Direct binary file store with UUID isolation, automatic MIME classification, and pre-signed streaming.
4. **SECaaS (Azure Key Vault & Managed Identity):** Hardware security module for secret and connection string management.
5. **IaaS (Azure Linux Virtual Machine):** Private virtual network sentinel and administrative bastion.

## Multi-Tenant Data Isolation
- Each document in the database carries a mandatory foreign key `user_id -> users.id`.
- User routes (`/`, `/api/documents`, `/upload`, `/delete`) enforce tenant boundaries: `Document.query.filter_by(user_id=current_user.id)`.
- Public document sharing is mediated via 64-character cryptographically secure tokens (`share_token`), decoupling external review from user accounts.

## Request Pipeline
```text
Browser Client
   │ (HTTPS / TLS 1.3)
   ▼
Azure App Service (PaaS)
   │
   ├── Security Headers Middleware (@app.after_request)
   ├── Sliding Window Rate Limiter (@rate_limit)
   ├── CSRF Verification (Origin Header + HMAC Token)
   │
   ├── Authentication Subsystem (Flask-Login + scrypt)
   │      │
   │      ▼
   │   Azure SQL Database (DBaaS)
   │
   └── Document Management Subsystem
          │
          ├── Integrity & Threat Inspection (scanner.py)
          ├── Quota Verification (current_user.storage_quota_bytes)
          └── Binary Storage Dispatch (storage.py)
                 │
                 ▼
              Azure Blob Storage Container (SaaS)
```

