**SentryLog** is a lightweight, high-performance security telemetry and firewall log ingestion engine built with **FastAPI**, **SQLAlchemy**, and **SQLite**. It features AAA (Authentication, Authorization, and Accounting) API key verification, automated threat-severity scoring, and persistent historical log auditing.

---

## Features

- **AAA Security Framework:** Header-based API key validation (`X-API-Key`) with structured access logging.
- **Dual Ingestion Pipelines:** Dedicated endpoints for general security telemetry and raw firewall packet events (`BLOCK`/`ALLOW`).
- **Database Persistence:** Automated SQLite storage via SQLAlchemy for robust incident tracking.
- **Log Retrieval API:** Query stored security records sorted by recency with customizable limits.

---

## Getting Started

### 1. Clone & Set Up Virtual Environment
```bash
git clone [https://github.com/your-username/sentry-log.git](https://github.com/your-username/sentry-log.git)
cd sentry-log

python3 -m venv venv
source venv/bin/activate