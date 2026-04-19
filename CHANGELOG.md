# Changelog

All notable changes to K8s-Janus are documented here.

## [1.0.7] - 2026-04-19

### Changed
- **K8s/CNCF Design** — Accent color switched from indigo (#6366f1) to Kubernetes blue (#326CE5) across all pages and CSS variables
- **SVG Logo** — Replaced raster PNG with a fully vector SVG logo (blue rounded heptagon + white Janus faces); no white-background artifact, scales perfectly at any size
- **Setup Page** — Removed "Open Janus" nav link and user dropdown from setup wizard header for a cleaner onboarding flow

### Fixed
- **Setup WebSocket 403** — `/ws/setup/*` was blocked by the auth middleware; now correctly bypassed so the setup progress stream works when auth is enabled
- **Pod info namespace** — `loadPodInfo` now uses the pod's actual namespace from `_podData` instead of always using the first requested namespace — fixes 404 errors for multi-namespace requests
- **Terminal WebSocket reconnecting** — `BaseHTTPMiddleware` silently dropped WebSocket upgrade requests; replaced with a pure ASGI middleware that handles both HTTP and WebSocket correctly
- **Terminal timeout** — Added `_request_timeout=15` to the interactive exec stream; previously only the shell probe had a timeout, leaving stuck connections with no recovery
- **Idle revocation** — `idleTimeoutSeconds` now defaults to `0` (disabled); previously defaulted to 900s causing unexpected session termination on 8h requests

### Added
- **Terminal button highlight** — Active session terminal button is now filled accent blue (not a plain outline) making it easier to spot at a glance
- **Admin user list refresh** — Added a Refresh button next to "New user" in the admin users page
- **Requests nav label** — Renamed "My Requests" to "Requests" in the admin header nav

---

## [1.0.6] - 2026-03-15

### Added
- **MFA/TOTP Support** — Optional two-factor authentication before terminal access
  - QR code setup for authenticator apps (Google Authenticator, Authy, etc.)
  - 8 single-use backup recovery codes with encrypted storage
  - Configurable verification timeout (default: 5 minutes)
  - Full UI in profile modal for enable/disable/backup codes
  - Fernet encryption for TOTP secrets and backup codes
  - New dependencies: `pyotp==2.9.0`, `qrcode==8.0`, `cryptography==44.0.0`
  - New database table: `user_mfa` with encrypted fields
  - New API routes: `/api/mfa/status`, `/api/mfa/setup`, `/api/mfa/enable`, `/api/mfa/disable`, `/api/mfa/verify`, `/api/mfa/backup-codes`
  - New standalone MFA verification page: `/mfa-verify`

- **Native High Availability** — Multi-replica deployments without Redis
  - Sticky sessions (`sessionAffinity: ClientIP`) route same user to same pod
  - Controller uses leader election (built into kopf) — one active, others standby
  - Database-backed user profiles for shared state across replicas
  - Pod anti-affinity spreads replicas across nodes
  - PodDisruptionBudget ensures minimum availability during updates
  - PostgreSQL recommended (not required) for HA — memory fallback when disabled

### Changed
- **User Profiles** — Now stored in PostgreSQL when enabled (fallback to memory)
  - New database table: `user_profiles` with name and photo
  - Enables profile consistency across multiple webui replicas
  - Automatic migration via `db_migrate.py`

- **Database Schema** — Migration adds `user_mfa` and `user_profiles` tables
  - Idempotent DDL with `CREATE TABLE IF NOT EXISTS`
  - Encrypted columns for MFA secrets using Fernet symmetric encryption

### Documentation
- Updated `values.yaml` with comprehensive HA documentation
- Added MFA configuration examples and security best practices
- Documented sticky session behavior and timeout settings

---

## [1.0.5] - 2026-03-14

### Fixed
- **Colored PS1** — Now works in bash using `--norc --noprofile` to prevent rc files from overwriting it
- **Quick Commands TDZ Error** — `_cmdsEnabled` now declared before `setActivePane` to fix ReferenceError on pod click
- **Status Page** — `approved-by` field now shown for Active/Expired/Revoked phases; cancel button grouped with terminal link for better UX

---

## [1.0.4] - Earlier

### Added
- Dark/Light mode toggle with localStorage persistence
- Terminal session management improvements
- Profile modal with name/photo customization

---

## Format

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) principles:
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes
