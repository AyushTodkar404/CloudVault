# External Integrations: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

## 1. Microsoft Azure App Service (PaaS)
- **Role:** Web application hosting and runtime environment.
- **Runtime:** Linux / Python 3.12.
- **Entrypoint:** `startup.sh` running `gunicorn --bind=0.0.0.0 --timeout 600 "app:create_app()"`.
- **TLS/SSL:** Managed Azure certificates with automatic HTTPS redirection.

## 2. Microsoft Azure SQL Database (DBaaS)
- **Role:** Central transactional datastore for users, document metadata, audit logs, and access tokens.
- **Protocol:** TDS (Tabular Data Stream) via `pymssql` or `pyodbc` over port 1433.
- **Failover:** Automatic transparent fallback to local SQLite when external database is unreachable.

## 3. Microsoft Azure Blob Storage (SaaS / Object Storage)
- **Role:** Binary document archival and streaming.
- **SDK:** `azure-storage-blob` (v12.x).
- **Target Container:** `documents`.
- **Isolation:** UUIDv4 filename prefix prevents key collision and directory traversal.

## 4. Microsoft Azure Key Vault (SECaaS)
- **Role:** Secret storage and cryptographic key management.
- **Managed Identity:** System-assigned managed identity eliminates plaintext database passwords in container configurations.

## 5. Microsoft Azure Linux Virtual Machine (IaaS)
- **Role:** Edge network gateway, background monitoring daemon, and administrative bastion in dedicated VNet.

