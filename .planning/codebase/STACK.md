# Technology Stack: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

## Backend Infrastructure
- **Runtime:** Python 3.12 (WSGI execution)
- **Web Framework:** Flask 3.0+
- **Application Factory:** Modular `create_app(test_config=None)` pattern in `app.py`
- **WSGI Production Server:** Gunicorn (with gevent/async workers on Linux)

## Data Layer & Persistence
- **ORM / Abstraction:** Flask-SQLAlchemy 3.1+ / SQLAlchemy 2.0+
- **Production Database:** Microsoft Azure SQL Database (Serverless Gen5 tier)
- **Local Fallback Database:** SQLite 3 (`instance/cloudvault.db`)
- **Password Hashing:** `werkzeug.security` with scrypt (salted multi-round hashing)
- **Token Serialization:** `itsdangerous.URLSafeTimedSerializer` for expiring reset tokens

## Storage Layer
- **Cloud Provider:** Microsoft Azure Blob Storage (via `azure-storage-blob` SDK)
- **Default Container:** `documents`
- **Blob Naming Strategy:** `UUID4(hex) + "_" + secure_filename(original_filename)`
- **Local Storage Fallback:** Configurable `uploads/` directory for offline development

## Security Engine & Middleware
- **Integrity Scanner:** `scanner.py` with multi-layer checks:
  - Magic byte binary header validation (PDF, PNG, JPG, ZIP, etc.)
  - Disguised binary detection (MZ PE, ELF, Mach-O, MSCF)
  - Polyglot and webshell pattern heuristics (PHP, eval, base64 payloads)
  - SVG XSS script vector filtering
- **Rate Limiting:** Sliding-window in-memory IP rate limiter (`@rate_limit`)
- **CSRF Defense:** Flask-Login session + HMAC CSRF token verification + Origin header validation
- **HTTP Security Headers:** Defense-in-depth headers applied in `@app.after_request`:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy`

## Frontend & User Experience
- **Template Engine:** Jinja2
- **Styling Architecture:** Tailwind CSS (JIT compiler via CDN) with custom CSS variables
- **Design System:** Unslopped quiet neutral palette (`--cv-canvas`, `--cv-surface`, `--cv-border`, `--cv-ink`) + deep vault accent (`--cv-accent`)
- **Typography:** Plus Jakarta Sans (UI) and JetBrains Mono (figures/metrics/hashes)
- **Icons:** FontAwesome 6.5.1
- **Accessibility:** WCAG 2.1 AA compliant skip link, `:focus-visible` outlines, semantic landmarks (`<main id="main-content">`), `prefers-reduced-motion` overrides

