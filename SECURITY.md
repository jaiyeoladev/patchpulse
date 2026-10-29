# Security policy

## Design principles

- **Read-only by design.** The Microsoft Graph client only implements `GET` requests and the app asks for
  read-only permissions. Nothing is ever written back to your tenant or security tools.
- **Least privilege.** The exact permissions required are listed on the *Connection & permissions* page and in
  the README.
- **Secrets stay in the environment.** Credentials are read from environment variables (or a local `.env`
  file that is git-ignored) and are never stored in the database, logs or exports.
- **Hardened web layer.** Strict Content-Security-Policy (no inline scripts or styles), `X-Frame-Options: DENY`,
  CSRF tokens on every state-changing form, `SameSite=Lax` signed session cookies, login throttling,
  constant-time credential comparison, open-redirect protection and spreadsheet formula-injection
  neutralisation in CSV exports.
- **Accountability.** Sign-ins, failed sign-ins, scans, exports, setting changes and every action on a finding
  are written to the audit log.

## Deploying safely

1. Set `DEMO_MODE=false`, a long random `SECRET_KEY` and an `ADMIN_PASSWORD` of at least 12 characters
   (the app refuses to start in live mode without them).
2. Serve it over HTTPS behind a reverse proxy (Azure App Service, Container Apps, Nginx, Caddy) and set
   `SESSION_COOKIE_SECURE=true`.
3. Restrict network access (private endpoint, IP allow-list or an identity-aware proxy such as Entra
   Application Proxy).
4. Use a short-lived client secret or, better, a certificate stored in Key Vault, and rotate it.
5. Back up the data volume — it holds findings history, risk acceptances and the audit log.

## Reporting a vulnerability

Please do not open a public issue. Email the maintainer with details and steps to reproduce; you will get an
acknowledgement within five working days.
