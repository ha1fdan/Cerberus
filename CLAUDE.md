# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cerberus is a self-hosted forward-auth SSO gateway (🐕 "guards the gate") that sits in front of Nginx-proxied apps on a homelab domain. Nginx calls `GET /verify` via `auth_request` for every protected request; a 200 lets the request through (with `X-SSO-User` set), a 401 triggers Nginx to redirect the browser to Cerberus's own `/login`. See `nginx.conf` / `nginx/*.conf` for the reference `auth_request` + `@login` redirect pattern other apps are expected to use.

Auth is passkey/WebAuthn only — there is no password login. It also bundles a small admin panel, per-user profile page, and a homelab-style apps-overview dashboard.

## Commands

```bash
uv sync                                   # install/update deps (incl. dev group)
uv run uvicorn app.main:app --reload      # run dev server (port 5000 by default via Docker; pass --port for local)
uv run pytest                             # run the full test suite
uv run pytest tests/test_admin.py -k reset_passkeys   # run a single test
```

Local (non-Docker, non-`example.com`) testing requires overriding the production-oriented defaults, since cookies default to `Secure` and scoped to `.example.com`, and WebAuthn's RP ID/origin default to `example.com`:

```bash
COOKIE_SECURE=false COOKIE_DOMAIN=127.0.0.1 RP_ID=127.0.0.1 ORIGIN=http://127.0.0.1:8010 \
  uv run uvicorn app.main:app --host 127.0.0.1 --port 8010
```

`tests/test_static_js.py` shells out to `node` to exercise client-side redirect-safety logic directly; it skips itself if `node` isn't on PATH.

No lint/format tooling is configured yet.

For real deployments, `RP_ID`/`ORIGIN`/`COOKIE_DOMAIN` (and `JWT_SECRET`/`ALGORITHM`) are set explicitly in `docker-compose.yml`'s `environment:` block rather than relying on the `example.com` code defaults — update that file (and `nginx.conf`/`nginx/*.conf`, which use their own placeholder domains) for the actual deployment domain.

## Architecture

**Data layer (`app/db.py`)**: raw `sqlite3`, no ORM. Each query function opens its own short-lived connection via the `get_db()` context manager and commits on exit — **never chain two `get_db()` calls when reading back a just-written row inside the same logical operation**; a second connection won't see an uncommitted write from the first (this was a real bug — see `create_user`, which now reads the inserted row back through the *same* connection). `DB_PATH` (default `app/data/cerberus.db`, gitignored) is a module-level global read at call time, not cached — tests monkeypatch `db.DB_PATH` per-test for isolation (see `tests/conftest.py`).

Tables: `users` (has `token_version`, bumped to invalidate all of a user's outstanding JWTs — e.g. on an admin-triggered passkey reset), `credentials` (WebAuthn passkeys, owned by `user_id`), `invites` (single-use, SHA-256-hashed tokens with expiry — used both for first-time enrollment and admin-triggered resets), `apps` (dashboard tiles).

**Auth flow (`app/security.py`, `app/webauthn_service.py`, `app/routes/auth.py`)**:
- Registration/login are WebAuthn ceremonies with two round trips each (`/begin` generates a challenge, `/complete` verifies the browser's response). In-flight challenges live in an in-memory dict in `webauthn_service.py` (`_challenges`), keyed by a random `state` token returned to the client and passed back on `/complete` — this assumes a single uvicorn worker process (true per the `Dockerfile` `CMD`); it would need a shared store to scale past one worker.
- Login is **discoverable/usernameless**: registration requires a resident key, so `/login` never asks for a username — the browser lists eligible passkeys for the RP ID and the server identifies the user from the credential ID returned at `/webauthn/authenticate/complete`.
- Sessions are a JWT in an `sso_session` cookie carrying `uid` and `tv` (token_version). `security.get_current_user` re-checks both against the DB on every request, so a deleted user or a bumped `token_version` invalidates the session immediately — it does not wait for JWT expiry.
- Two dependency flavors exist for the same check: `get_current_user`/`require_admin` (used by JSON/fetch endpoints — returns a bare 401/403) vs. `require_user_page`/`require_admin_page` (used by full-page GET routes — raises `security.RedirectToLogin`, caught by an app-wide exception handler in `main.py` that redirects the browser to `/login?rd=...`).

**Routing**: `app/main.py` wires up routers from `app/routes/{auth,profile,admin,dashboard}.py` and owns the `/verify` endpoint (the one Nginx actually calls) plus first-run bootstrap: on an empty `users` table it creates an admin account and logs a one-time `/register/{token}` enrollment link to stdout (there's no email system).

**Templates (`app/templates/`, rendered via the shared `app/templating.py` Jinja2 env)**: all extend `base.html`. **Never interpolate a Jinja variable into an inline event-handler attribute** (`onclick="...{{ x }}..."`) — HTML-escaping does not protect a JS string-literal context there, since browsers HTML-decode attribute values before compiling them as JS (this was a real stored-XSS finding, fixed by moving confirmations to `data-confirm` attributes read by a real `addEventListener` — see `admin.html`). Similarly, any redirect target read from a query param (like `rd`) must be validated as a same-origin relative path before assignment to `window.location` — see `isSafeRedirectPath()` in `app/static/webauthn.js`, used by `login.html`.

**WebAuthn client glue (`app/static/webauthn.js`)**: shared base64url encode/decode and `navigator.credentials.create/get` wrappers used by `login.html`, `register.html`, and `profile.html`.

## Testing conventions

`tests/conftest.py`'s `client` fixture spins up a real `TestClient` against a fresh temp SQLite DB per test (via `monkeypatch.setattr(db, "DB_PATH", ...)`) and patches `security`/`webauthn_service` module globals for a `testserver`-compatible cookie/RP config — module-level config constants are read dynamically at call time throughout the app specifically so this works.

Full WebAuthn ceremonies (registration + discoverable login) are exercised for real using the `soft-webauthn` software authenticator rather than mocked — see `tests/webauthn_helpers.py` for the encode/decode glue that mirrors `app/static/webauthn.js` on the Python side. When a test needs two independent, simultaneously-authenticated users, spin up a second `TestClient(app)` inside the test rather than reusing one client's cookie jar (see `test_admin.py::test_reset_passkeys_invalidates_target_session`).
