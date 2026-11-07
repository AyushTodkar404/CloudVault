# Codebase Conventions: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

## Architectural Patterns
- **Application Factory:** Code initializes inside `create_app(test_config=None)` in `app.py`. Tests override configuration in memory without altering environment variables.
- **Fail-Safe Graceful Fallbacks:**
  - If Azure SQL Database is unreachable, the engine falls back to local SQLite (`instance/cloudvault.db`).
  - If Azure Blob Storage credentials are not configured, files stream to local `./uploads`.
- **Zero Raw SQL Interpolation:** All queries use SQLAlchemy 2.0 ORM expressions (`db.session.get()`, `filter_by()`) or parameterized text.
- **Zero Plaintext Secrets:** Sensitive connection strings reside in Azure Key Vault or `.env` (gitignored).

## Coding Standards & Safety
- **Strict Redirect Validation:** Never pass unvalidated URLs to `redirect()`. All targets must satisfy `is_safe_redirect_url(target)`.
- **File Upload Boundaries:**
  - Filenames sanitized with `werkzeug.utils.secure_filename`.
  - Extension checked against `ALLOWED_EXTENSIONS` whitelist and `BLOCKED_EXTENSIONS` blacklist.
  - Zero-byte files rejected.
  - Byte stream inspected via `scanner.py` for binary header mismatches, webshell strings, and double-extension evasion.
- **Password Security:** Multi-round scrypt hashing via `generate_password_hash(method='scrypt')`.
- **Error Handling:** Centralized handlers for 400, 403, 404, 413, and 500 render `templates/404.html` with masked incident references and zero traceback leakage.

