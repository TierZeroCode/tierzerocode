---
name: Tier Zero C.O.D.E — Project Overview & Audit Status
description: Commercial open-source SaaS security dashboard built on Django 6.0 / Python 3.12. Tracks a 53-issue code quality audit across 3 phases.
type: project
---

Commercial open-source SaaS security dashboard (Tier Zero C.O.D.E). Django 6.0 / Python 3.12. Hosted and self-hosted Docker deployments.

GitLab: gitlab.awbtech.org, project: tier-zero-code-llc/tier-zero-code
Workflow: branch from dev, create MR.

Django apps: authhandler, code_packages, emailhandler, logger, login_app, main

**Why:** A 4-agent code quality audit produced 53 GitLab issues across 3 phases. Work is being systematically resolved via MRs.

**How to apply:** Always check current MR status and remaining issue list before recommending next work. Phase 1 (security blockers) must be fully resolved before Phase 2 and 3 carry significant urgency.

---

## MR History (as of 2026-03-26)

| MR | Work | Status |
|----|------|--------|
| !1 | #15, #16, #17, #18, #19, #20 — Security blockers (test endpoint, accountcreation auth, OAuth state, JWT validation, superuser checks, require POST) | Merged |
| !2 | #22, #23, #29, #30 — Credential logging, print statements, db.sqlite3 audit, default DB creds | Merged |
| !3 | #46, #47 — Login rate limiting, SSO redirect validation | Merged |
| !4 | #27, #45, #43 — SECRET_KEY guard, timezone fix, Qualys session safety | Merged |
| !5 | #66, #67, #65, #64, #61, #50, #48, #40 — HSTS, dead code removal, wildcard imports, bare except, email field, duplicate definitions | Merged |
| !6 | Docker deployment overhaul — healthchecks, start.sh entrypoint, .env.example | Merged |
| !7 | Remove start.sh, inline migrate into compose | Merged |
| !8 | TZC_ prefix on all env vars | Merged |
| !9 | Fix migrate race condition — only web runs migrations | Merged |
| !10 | Align docker-compose.yml with production config | Merged |
| !11 | Fix pg_isready healthcheck to target correct database | Pending review |

## Issues Closed: 24 of 53 audit issues
Closed: #15, #16, #17, #18, #19, #20, #21, #22, #23, #27, #29, #30, #40, #43, #45, #46, #47, #48, #50, #61, #64, #65, #66, #67
Note: #21 was resolved as part of MR !1 (fix was included in #16 work). #40, #43, #45 were resolved in MRs !4 and !5.

## Audit Issue Tracker (as of 2026-03-26)

### Phase 1 — Security Blockers

| # | Title | Status |
|---|-------|--------|
| #15 | Remove /test data-destruction endpoint | MERGED (!1) |
| #16 | Protect /identity/accountcreation | MERGED (!1) |
| #17 | Implement proper OAuth state parameter | MERGED (!1) |
| #18 | JWT signature validation against Microsoft JWKS | MERGED (!1) |
| #19 | Superuser checks on integration management views | MERGED (!1) |
| #20 | @require_POST on mutation views, fix open redirect | MERGED (!1) |
| #21 | Remove plaintext password from flash message | MERGED (!1) |
| #22 | Remove client_secret from error logs | MERGED (!2) |
| #23 | Replace print(response.text) with structured logging | MERGED (!2) |
| #24 | Remove TAP credential value from audit log | REMAINING |
| #25 | Remove client_secret from Django admin export fields | REMAINING |
| #26 | Encrypt client_secret at rest in database | REMAINING |
| #27 | Fail fast if SECRET_KEY is unset | MERGED (!4) |
| #28 | Add Redis authentication and re-enable protected-mode | REMAINING |
| #29 | Confirm db.sqlite3 never in git history | MERGED (!2) |
| #30 | Remove hardcoded default DB credentials | MERGED (!2) |
| #46 | Add django-ratelimit to login endpoint | MERGED (!3) |
| #47 | Validate SSO redirect URL against allowed hosts | MERGED (!3) |

### Phase 2 — Reliability & Performance

| # | Title | Status |
|---|-------|--------|
| #31 | N+1 query fix | REMAINING |
| #32 | N+1 query fix | REMAINING |
| #33 | N+1 query fix | REMAINING |
| #34 | N+1 query fix | REMAINING |
| #35 | N+1 query fix | REMAINING |
| #36 | N+1 query fix | REMAINING |
| #37 | N+1 query fix | REMAINING |
| #38 | N+1 query fix | REMAINING |
| #39 | Add HTTP request timeouts to all external API calls | REMAINING |
| #40 | CrowdStrike auth fix | MERGED (!5) |
| #41 | Fix CrowdStrike pagination logic | REMAINING |
| #42 | Sophos Central pagination + regional API discovery | REMAINING |
| #43 | Qualys session logout in finally block | MERGED (!4) |
| #44 | Add transaction.atomic() to all sync functions | REMAINING |
| #45 | Fix datetime.now() → timezone.now() | MERGED (!4) |

### Phase 3 — Code Quality

| # | Title | Status |
|---|-------|--------|
| #48 | (dead code / wildcard) | MERGED (!5) |
| #49 | Deduplicate _fetch_paginated_data across 4 files | REMAINING |
| #50 | (duplicate definitions) | MERGED (!5) |
| #51 | Fix integration name case mismatches | REMAINING |
| #52 | Add null guard to cleanAPIData | REMAINING |
| #53 | Fix Device.__str__ crash on hostname=None | REMAINING |
| #54 | Replace device_data['key'] with .get('key') in Intune | REMAINING |
| #55 | Add tailscale to ComplianceSettingsForm | REMAINING |
| #56 | Fix personaMetrics broken FK query | REMAINING |
| #57 | Remove migration HTTP endpoint | REMAINING |
| #58 | Fix Notification.objects.get() outside try/except | REMAINING |
| #59 | Add allowlist validation for integration URL parameter | REMAINING |
| #60 | Cap export API memory usage | REMAINING |
| #61 | (bare except) | MERGED (!5) |
| #62 | Fix hardcoded persona names list | REMAINING |
| #63 | Unbounded Notification.objects.all() on every page | REMAINING |
| #64 | (email field) | MERGED (!5) |
| #65 | (wildcard imports) | MERGED (!5) |
| #66 | HSTS header | MERGED (!5) |
| #67 | (dead code removal) | MERGED (!5) |

### Pre-existing Issues (6)

| # | Status |
|---|--------|
| #5 | REMAINING |
| #6 | REMAINING |
| #8 | REMAINING |
| #9 | REMAINING |
| #11 | REMAINING |
| #12 | REMAINING |
