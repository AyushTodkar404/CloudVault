# CloudVault: Developer & Agent Standards

This repository adheres to the unified 5-framework engineering standard for Antigravity AI agents and human contributors: **GSD**, **Ponytail**, **ECC**, **OWASP**, and **Unslop**.

---

## 1. Ponytail (Lazy Senior Dev Mode)

The best code is the code never written. Solve the whole problem with the least new code.
- **Before you write:** Inspect the task and affected code. Trace callers, tests, fixtures, config, and exports.
- **Smallest complete change:**
  1. Does it need to exist? Skip features, options, and flexibility nobody asked for.
  2. Already in this codebase? Reuse existing helpers, services, or models (`storage_manager`, `scanner`, `db.session`, etc.).
  3. Standard library or Flask/SQLAlchemy feature? Use it.
  4. Never add a dependency for a few lines.
  5. Shortest working diff wins.
- **Never cut:** Trust boundary validation, error handling, security checks, accessibility, or tests.
- **Self-checks:** Non-trivial logic requires a focused test in `test_app.py`.
- **End of turn:** State what was skipped or not checked, and any material remaining risk.

---

## 2. GSD (Get Shit Done Workflow)

- **Source of Truth:** The `.planning/` directory contains current architecture, stack, conventions, testing, and concerns. Read it before taking action.
- **Verification:** Always verify changes by running the test suite:
  ```bash
  py -3.12 -m pytest
  ```
- **Continuity:** Document technical debt, known limits, and architectural decisions directly in `.planning/codebase/CONCERNS.md`.

---

## 3. ECC (Enterprise & Coding Craft)

- **Security Checklist:**
  - Zero hardcoded secrets (use Azure Key Vault or environment variables).
  - External input validated at boundaries.
  - Parameterized queries via SQLAlchemy ORM (zero raw SQL string interpolation).
  - Sanitized redirect targets using `is_safe_redirect_url()`.
  - Scrubbed error responses: 400, 403, 404, 413, and 500 error handlers must never expose raw stack traces.
- **Delivery Standards:**
  - Conventional commits (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`).
  - Keep functions focused and files organized.

---

## 4. OWASP (Web Application Security Standards)

- **Authentication & Sessions:** Secure cookies (`HttpOnly`, `SameSite=Lax`, `Secure` in production), scrypt password hashing, session quotas, and sliding window rate limiting.
- **Injection Defense:** All uploaded files are scanned via `scanner.py` for magic numbers, double extensions, polyglots, and webshell payload signatures.
- **CSRF Defense:** `WTF_CSRF_ENABLED` with dual validation: origin header check and cryptographic HMAC CSRF token verification.
- **Open Redirects:** All `next` URL parameters must pass `is_safe_redirect_url()` to reject protocol-relative (`//`) or backslash (`\`) targets.
- **Security Headers:** Enforce defense-in-depth headers on all HTTP responses: CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`.

---

## 5. Unslop (Frontend Quality & Accessibility)

- **Visual Quality:**
  - Restrained quiet neutral palette (`--cv-canvas: #FAFAF9`, `--cv-surface: #FFFFFF`, `--cv-border: #E5E7EB`, `--cv-ink: #1C1917`) paired with a purposeful deep vault accent (`--cv-accent: #9F1239` light / `#FB7185` dark).
  - No generic AI slop: no purple/indigo neon gradient soup or card soup.
  - Dark mode supported natively via `.dark` class with matching low-luminance neutral backgrounds.
- **Accessibility (WCAG 2.1 AA):**
  - Accessible skip link (`<a href="#main-content" class="skip-link">Skip to main content</a>`) present on all pages.
  - High-contrast `:focus-visible` outlines on all interactive buttons, links, and inputs.
  - Semantic landmarks: `<header>`, `<main id="main-content" tabindex="-1">`, `<footer>`.
  - Full support for `prefers-reduced-motion: reduce`.

