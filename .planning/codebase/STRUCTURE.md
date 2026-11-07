# Directory Structure & Component Map: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

```text
E:\cloudvault
├── app.py                     # Main application factory, routes, security middleware, error handlers
├── models.py                  # SQLAlchemy models (User, Document, ActivityLog) & helper methods
├── storage.py                 # Azure Blob Storage SDK integration & local fallback manager
├── scanner.py                 # Deep binary file integrity, threat, & webshell inspection engine
├── test_app.py                # Comprehensive test suite (33 automated unit & integration tests)
├── requirements.txt           # Python dependency specifications
├── startup.sh                 # Linux container startup script (Gunicorn execution)
├── ARCHITECTURE.md            # High-level architecture specification & Azure cloud breakdown
├── README.md                  # Project overview, installation instructions, & deployment guide
├── AGENTS.md                  # Canonical Antigravity multi-framework standards (GSD, Ponytail, ECC, OWASP, Unslop)
│
├── .planning/                 # GSD planning directory & durable codebase intelligence
│   └── codebase/
│       ├── ARCHITECTURE.md    # Multi-tenant cloud architecture & request lifecycle
│       ├── CONCERNS.md        # Technical debt ledger & security audit log
│       ├── CONVENTIONS.md     # Engineering patterns, conventions, & safety standards
│       ├── INTEGRATIONS.md    # External cloud service integrations (PaaS, DBaaS, SaaS, SECaaS, IaaS)
│       ├── STACK.md           # Runtime, framework, and tooling specifications
│       ├── STRUCTURE.md       # Component hierarchy and module directory map
│       └── TESTING.md         # Automated test verification runner & pattern guide
│
├── templates/                 # Jinja2 HTML templates
│   ├── base.html              # Core layout, navigation, skip link, dark mode, design tokens
│   ├── index.html             # Document registry, drag-and-drop uploader, quota dashboard
│   ├── login.html             # Secure user sign-in
│   ├── signup.html            # User registration
│   ├── forgot_password.html   # Password recovery request
│   ├── reset_password.html    # Cryptographic password reset form
│   ├── share.html             # Token-authorized public document preview & download
│   ├── about.html             # Architecture showcase, cloud paradigms, student team
│   ├── 404.html               # Unified error template (400, 403, 404, 413, 429, 500)
│   ├── loading.html           # Authentication transition screen
│   ├── privacy.html           # Privacy policy
│   └── terms.html             # Terms of service
│
├── instance/                  # Local SQLite database fallback folder (gitignored)
│   └── cloudvault.db
└── uploads/                   # Local binary file storage fallback folder (gitignored)
```

