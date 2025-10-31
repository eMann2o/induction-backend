# Backend Engineer Summary — induction / training system (concise, implementation-ready)

This is a compact, developer-focused summary of the full design and behavior we brainstormed. It assumes you’re building the backend services (API, DB, token service, grading, audit, notifications). No UI or front-end details beyond what the backend must support.

---

# High-level purpose

Provide session-gated training tests where trainees only gain access by scanning a facilitator-generated QR. All domain objects use internal IDs (not phone) as primary keys. Phone numbers are stored as metadata only. System supports SuperAdmin, HR, HSE, Facilitator, and Trainee roles. Strong audit, ephemeral access tickets, retake flow, and RBAC.

---

# Actors & responsibilities (backend view)

* **SuperAdmin**: full system control, settings, backups, audit access.
* **HR**: create trainee records, bulk uploads, assign trainees to sessions.
* **HSE**: create trainings & question banks, create sessions, assign facilitators.
* **Facilitator**: generate QR tokens, proctor, issue retake/override, view participants.
* **Trainee**: ephemeral access via QR scan → take test (no persistent login by default).

---

# Core data model (primary collections/tables & key fields)

Use internal IDs (UUID *`npm install uuid`) for all records.

Essential tables:

* `trainees` — `trainee_id`, `name`, `phone` (metadata), `department`, `active`, `meta`
* `accounts` — `account_id`, `email`, `role_id`, `is_super_admin`, `password_hash`, `meta`
* `roles` — `role_id`, `name`
* `trainings` — `training_id`, `name`, `passing_score`, `created_by`
* `questions` — `question_id`, `training_id`, `type`, `options_json`, `correct_answer`, `points`
* `sessions` — `session_id`, `training_id`, `facilitator_id`, `scheduled_at`, `max_retries`
* `session_assignments` — `assignment_id`, `session_id`, `trainee_id`, `assigned_by`, `assigned_at`
* `session_qrcodes` — `qrcode_id`, `token`, `session_id`, `created_by`, `created_at`, `expires_at`, `max_uses`, `used_count`
* `ephemeral_tickets` — `ticket_id`, `qrcode_id`, `session_id`, `trainee_id`, `issued_by`, `expires_at`, `single_use`, `metadata`
* `attempts` — `attempt_id`, `session_id`, `training_id`, `trainee_id`, `attempt_number`, `answers_json`, `score_pct`, `passed`, `created_at`, `proctored_by`, `override_meta`
* `audit_logs` — `audit_id`, `actor_id`, `actor_role`, `action`, `resource_type`, `resource_id`, `details_json`, `created_at`

Design notes:

* Use FK constraints for referential integrity.
* Keep answers & options as JSON for flexibility.
* `ephemeral_tickets` should be stored in cache (Redis) for fast expiration, but also persisted to DB/audit when issued.

---

# Core API endpoints (purpose & minimal inputs/outputs)

(Implement with role-based middleware; JWT auth + is\_super\_admin bypass)

Authentication

* `POST /auth/login` — returns JWT (for HR/HSE/Facilitator/SuperAdmin). Trainees typically do not log in persistently.

HR

* `POST /hr/trainees` — create bulk/single trainee. Returns `trainee_id`.
* `POST /hr/assign` — assign trainees by `trainee_id` to a `session_id`.

HSE

* `POST /trainings` — create training + meta.
* `POST /trainings/:id/questions` — upload question bank.
* `POST /sessions` — create a session and set facilitator.

Facilitator

* `GET /facilitator/sessions` — list sessions & participants.
* `POST /sessions/:id/qrcode` — generate QR token & return `token`, `expires_at` (and a URL). Creates `session_qrcodes`.
* `POST /sessions/:id/qrcode/new` — create retake / override token (logged differently).

Public / Scan flow

* `GET /scan?token=xxx` — scan landing page (frontend).
* `GET /api/qrcode/:token/verify?identifier=...` — server maps identifier → `trainee_id`, validates assignment, returns allowed/denied and issues ephemeral ticket (or returns reason code).
* `POST /api/attempts` — submit answers (requires valid ephemeral ticket or server-side verification). Returns grading result, `attempt_number`, `passed`.

Reports / Admin

* `GET /reports/...` — aggregation endpoints (training, facilitator, time window).
* SuperAdmin endpoints for backups, audits, invalidations, high-risk actions.

---

# QR / token / ticket lifecycles & rules

* **QR token**: short random token stored server-side as `session_qrcodes`. Default expiry: **\~2–4 hours** (recommended default 3h). `max_uses` configurable.
* **Scan verification**: client sends identifier (employee ID / phone / OTP). Server maps it to `trainee_id`.
* **Ephemeral ticket**: created after successful verification; short-lived (recommend **15 minutes**), single-use per attempt. Tickets stored in Redis for speed and revoked on use or submit.
* **Retake tokens**: facilitator creates a new QR (or special retake token). Optionally mark `override_meta` if facilitator issued an ad-hoc override.
* **Ticket enforcement**: backend must validate ticket for testing actions (start test, resume, submit). Tickets cannot be reused.

---

# Verification logic & denial handling

Server check order:

1. Token existence & expiry & usage limit.
2. Map identifier to `trainee_id` (0 / 1 / many matches).
3. If 0 → `NOT_FOUND`.
4. If multiple → `MULTIPLE_MATCH`.
5. If single → check `session_assignments` for that `trainee_id`. If missing → `NOT_ASSIGNED`.
6. Check trainee active, `max_retries` not exceeded.
7. If allowed → create ephemeral ticket; respond allowed.

Facilitator options when lookup fails:

* Deny (default).
* Correct mapping (pick trainee record).
* Add to session (create `session_assignments`).
* One-time override (issue ephemeral ticket with override metadata).
  All facilitator actions write a structured `audit_logs` entry with justification and are subject to policy limits.

---

# Attempt lifecycle & grading

* Auto-grade MCQ/TF by comparing `answers_json` to `questions.correct_answer`. Short answers go into manual grading queue.
* Compute `score_pct` and `passed = score_pct >= training.passing_score`.
* Persist an immutable `attempts` row with `attempt_number` (increment per trainee+session or per training policy).
* Notify facilitator via notification service (WebSocket) for pass/fail and for manual grading tasks.
* For fails, facilitator can generate retake token; system links attempts for improvement metrics.

---

# RBAC & SuperAdmin specifics

* Roles enforced on API layer. `is_super_admin` bypass for critical checks (but still audited).
* SuperAdmin endpoints: system status, backup/restore, audit queries, invalidate QR/JWT, set global configs.
* Require MFA, IP allow-list or VPN for SuperAdmin, and two-person approval for destructive ops.

---

# Audit & logging requirements (immutable)

* Log every: token generation, verification attempt (with presented identifier), facilitator actions (add/override), attempt submission, grade results, audit config changes.
* Capture structured details: `actor_id`, `action`, `resource_id`, `identifier_provided`, `ip`, `timestamp`, `justification`.
* Retention: configurable; consider WORM storage for critical audit logs.

---

# Security & data privacy (must-haves)

* TLS for all traffic.
* Never encode PII in QR payloads (only `token`).
* Server-side validation for every client action.
* Rate-limit verification attempts & attempt submissions.
* Short JWT lifetimes + refresh tokens, with revocation lists.
* Encrypt sensitive fields at rest (phone optional per policy).
* MFA mandatory for admin and SuperAdmin.
* Limit facilitator override actions via quotas; require 2nd approval for high-risk use.

---

# Edge cases & recommended handling

* **No device**: facilitator can issue one-time supervised override (logged); or record attempt offline and sync later (must include facilitator attestation).
* **Network loss mid-test**: allow resume only while ephemeral ticket valid and attempt marked in-progress; otherwise require new scan.
* **Duplicate identifiers**: block and escalate; require facilitator or HR to resolve duplicates in DB.
* **Fraud detection**: flag many identifier attempts from same IP or many token usages → expire token & alert.

---

# Performance, scaling & caches

* Use Redis for: token lookup, ephemeral tickets, rate-limiting counters, and issuance quotas.
* DB for durable records & analytics (Postgres/MySQL). Keep `attempts` and `audit_logs` indexed for reporting (partitioning by date recommended for scale).
* Design endpoints idempotent where appropriate. Use background workers for heavy tasks (grading, exports).
* WebSocket or push for real-time facilitator notifications.

---

# Observability, testing & QA

* Metrics: QR generations/time, verify attempts/success rate, attempts submitted, pass/fail rates, override counts per facilitator.
* Logs: structured JSON logs for easier querying.
* Tests: unit tests for verify logic, integration tests for end-to-end scan→ticket→attempt flows, security tests for token expiry, replay attacks, rate limits.
* DR: scheduled DB backups + SuperAdmin-triggerable manual backups; test restore routines.

---

# Deployment & infra suggestions

* Containerized backend (Docker) behind API gateway.
* Redis cluster for ephemeral state.
* RDBMS for persistent data. Consider read replicas for reporting.
* Object storage for exports/certificates.
* CI/CD pipelines with DB migrations. Secrets in vault.

---

# Priority backlog for backend (MVP → next)

MVP

1. Auth + RBAC, roles, SuperAdmin flag.
2. Trainee CRUD, trainings, questions, sessions, assignments.
3. QR token generation & server-side storage.
4. Scan verification → ephemeral ticket issuance (Redis).
5. Attempt submission endpoint + auto-grading MCQ/TF.
6. Persist attempts + basic audit logs.
7. Facilitator endpoints: list sessions, generate QR, view participants.
8. Basic reports (pass rates).

v1 (post-MVP)

* Retake/override flows, facilitator quotas, audit UI endpoints.
* Manual grading queue.
* Robust reporting & CSV export.
* Notifications (WebSocket).
* Rate-limiting, fraud detection rules.

v2+ (scale & hardening)

* SSO/LDAP, two-person approvals, WORM audit storage, advanced analytics, certificate generation service, disaster recovery automation.

---

# Quick defaults & settings to enforce (start here)

* QR expiry: **3 hours** (configurable).
* Ephemeral ticket validity: **15 minutes**.
* Override ticket validity: **10 minutes**.
* Max overrides per facilitator/day: configurable (default 2).
* Default passing\_score: 70% (per-training override allowed).


