# Technical Concerns & Debt: CloudVault

**Project:** CloudVault (Digital Document & Credential Registry)  
**Analysis Date:** 2026-11-07  

## Mitigated Vulnerabilities & Risks

1. **Open Redirect Boundary Protection:**
   - *Previous state:* The `/login` endpoint checked `next_page.startswith('/')`, which allowed protocol-relative bypasses (e.g. `//attacker.com` or `/\attacker.com`).
   - *Mitigation:* Centralized `is_safe_redirect_url(target)` enforcing relative-only URLs (no scheme, no netloc, no double leading slashes, no backslashes).

2. **Information Disclosure via Unhandled Error Traces:**
   - *Previous state:* Only 404 was explicitly handled; 400, 403, 413, and 500 could expose default Flask or Werkzeug debug output in non-hardened environments.
   - *Mitigation:* Explicit custom error handlers render clean `templates/404.html` with random hex incident references and structured server-side logging.

3. **Accessibility Gap (WCAG 2.4.1 / 2.4.7):**
   - *Previous state:* Missing skip-to-content navigation link and high-contrast keyboard focus indicators.
   - *Mitigation:* Added accessible `.skip-link` and `:focus-visible` styling with `#main-content` landmark target.

## Active Monitoring Points
- **Sliding-Window In-Memory Rate Limiting:**
  - `_rate_limit_cache` and `_failed_login_cache` run in worker memory. In multi-worker Gunicorn deployments or auto-scaled App Service plans, rate limit state is per-worker. For multi-node scaling, upgrade cache backend to Redis or Azure Cache for Redis.
- **Client IP behind Proxies:**
  - `request.remote_addr` reads the immediate peer. In Azure App Service with front doors, ensure `werkzeug.middleware.proxy_fix.ProxyFix` is active if using `X-Forwarded-For`.

