# Testing Patterns & Verification: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

## Test Runner & Execution
- **Framework:** `unittest` + `pytest` (Python 3.12)
- **Run Command:**
  ```bash
  py -3.12 -m pytest
  ```
- **Verbose Run:**
  ```bash
  py -3.12 -m pytest -v
  ```

## Test Organization
All tests are centralized in `test_app.py`:
- `CloudVaultAuthTestCase`: User authentication, scrypt hashing, login/logout, multi-tenant document isolation, storage fallback.
- `CloudVaultProfessionalFeaturesTestCase`: Multi-file uploads, storage quota limits, sorting/filtering, activity audit logging, deep integrity scanner (magic bytes, webshells, corrupted archives, disguised executables).
- `CloudVaultRealProductionFeaturesTestCase`: Open redirect protection, custom error handlers (400, 403, 404, 413, 500), CSRF token enforcement, accessible skip-link & semantic landmarks, production secret key assertion.

## Test Environment Isolation
- Uses in-memory SQLite: `"SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"`
- Uses isolated temporary directory for file upload operations: `tempfile.TemporaryDirectory()`
- Database tables created in `setUp()` and dropped in `tearDown()`.

