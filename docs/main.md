# Technical Specification: `main.py`

## Overview
`main.py` serves as the core orchestration engine for **SentryLog**. It implements a high-performance asynchronous web server using **FastAPI**, an integrated **SQLite / SQLAlchemy** persistence layer, and a robust **AAA (Authentication, Authorization, and Accounting)** security framework.

---

## Architecture & Design Choices

### 1. The AAA Security Model
* **Authentication:** Handled via header-based API key validation (`X-API-Key`). Instead of open access, endpoints require a cryptographically valid token cross-referenced against an authorized vault (`VALID_API_KEYS`).
* **Authorization / Validation:** Enforced using **Pydantic** data models (`TelemetryPayload`, `FirewallLogPayload`). Incoming JSON packets are strictly typed and validated *before* touching application logic or database transactions, preventing malformed data injection.
* **Accounting (Audit Logging):** Every successful ingestion, query, or failed access attempt is captured by Python's native `logging` module (`SENTRY-AUDIT`), creating an immutable trace for SOC analysis.

### 2. Database Persistence Layer (SQLAlchemy & SQLite)
* **Why SQLite?** For a self-contained telemetry agent, SQLite provides zero-configuration, lightning-fast local storage without requiring external containerized database dependencies during local development.
* **Session Management:** Implements a generator dependency (`get_db()`) that yields transactional sessions and guarantees safe closure (`db.close()`) even if exceptions occur during commits, preventing database locks.

---

## Endpoints Breakdown

- `GET /`: Health check endpoint verifying engine status and database readiness.
- `POST /api/v1/telemetry`: Ingests general security events (e.g., failed logins, system anomalies), auto-scores severity, and commits records to SQLite with timestamp ordering.
- `POST /api/v1/firewall-event`: Parses raw network packet rules (`BLOCK` vs `ALLOW`), translating firewall triggers into structured threat metrics.
- `GET /api/v1/logs`: Secure retrieval endpoint allowing analysts to query historical logs ordered by recency (`desc()`) with customizable result limits.
