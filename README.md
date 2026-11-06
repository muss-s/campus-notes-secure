# Campus Notes (repaired)

Lab project, local use only (127.0.0.1, synthetic data, disposable DB). Never deploy.

## Setup
1. PHP 8.1+ with `pdo_mysql`, local MySQL. Import `schema.sql` as a MySQL admin (fresh DB).
2. Create a local MySQL user with SELECT/INSERT/UPDATE/DELETE on `notes_lab` only.
3. Set `LAB_DB_USER` and `LAB_DB_PASSWORD` (optional `LAB_DB_HOST`, default 127.0.0.1). No fallback to root. Do not commit credentials.
4. Hash the demo accounts: `php tools/reset_demo_users.php`
5. `php -S 127.0.0.1:8000`, open http://127.0.0.1:8000. Demo logins: see lab handout (public, throwaway).

## Layout
- `index.php` web UI/controller, `api.php` JSON API
- `src/bootstrap.php` session, headers, DB, escaping, CSRF helpers
- `src/auth.php` register/login, `src/notes.php` owner-scoped note queries
- `tools/reset_demo_users.php` CLI re-hash of demo accounts

## Limitations
No HTTPS locally (set secure cookies on HTTPS), no rate limiting/lockout, no password reset, no per-request CSP nonces, built-in PHP server is dev-only.
