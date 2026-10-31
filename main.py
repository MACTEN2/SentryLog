"""
================================================================================
SentryLog Engine - Core Orchestration Module (main.py)
================================================================================
Author: SentryLog Development Team
Architecture: FastAPI + SQLAlchemy + Pydantic + AAA Security Framework

PURPOSE:
This module acts as the primary telemetry ingestion and audit pipeline for 
SentryLog. It intercepts incoming network security events, enforces strict 
header-based API key authentication, validates payloads against strict Pydantic 
schemas, and securely persists historical records into a local SQLite database.

DESIGN RATIONALE:
- Asynchronous FastAPI routes ensure high throughput when handling bursts of logs.
- Pydantic models shield the database layer from malformed or malicious payloads.
- SQLAlchemy ORM decouples business logic from raw SQL string queries.
- Immutable audit logging guarantees traceability for every ingress attempt.
================================================================================
"""

import logging
from datetime import datetime
from typing import Dict, Any
from fastapi import FastAPI, Header, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Setup Accounting / Audit Logging (AAA Framework)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] SENTRY-AUDIT: %(message)s"
)
logger = logging.getLogger("sentry_audit")

# --- Database Setup (SQLite & SQLAlchemy) ---
DATABASE_URL = "sqlite:///./sentry_logs.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class LogEntryModel(Base):
    """SQLAlchemy ORM model representing historical security log entries."""
    __tablename__ = "security_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    client_identity = Column(String, index=True)
    event_type = Column(String)
    source_ip = Column(String, index=True)
    severity = Column(String, index=True)
    message = Column(String)

Base.metadata.create_all(bind=engine)

def get_db():
    """Yields a safe database session and ensures closure after request lifecycle."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- FastAPI App Initialization ---
app = FastAPI(
    title="SentryLog - Security Telemetry & Firewall Ingestion Engine",
    version="0.2.0",
    description="A vigilant, AAA-enforced log monitoring and database-backed persistence pipeline."
)

VALID_API_KEYS = {
    "sec_ops_key_9981": "SOC_Analyst_Node_1",
    "firewall_node_02": "Perimeter_FW_East"
}

# --- Pydantic Schemas ---
class TelemetryPayload(BaseModel):
    source_ip: str
    event_type: str
    severity: str
    message: str

class FirewallLogPayload(BaseModel):
    source_ip: str
    destination_ip: str
    action: str  
    protocol: str  
    port: int

# --- AAA Authentication Dependency ---
async def verify_api_key(x_api_key: str = Header(..., description="API Key for ingestion authentication")) -> str:
    """
    Validates the incoming X-API-Key header against authorized vault keys.
    Raises HTTP 401 Unauthorized if the key is missing or invalid.
    """
    if x_api_key not in VALID_API_KEYS:
        logger.warning(f"UNAUTHORIZED ACCESS ATTEMPT - Invalid Key provided: {x_api_key[:4] if x_api_key else 'NONE'}***")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid or missing X-API-Key header."
        )
    return VALID_API_KEYS[x_api_key]

# --- Endpoints ---
@app.get("/")
async def root() -> Dict[str, str]:
    return {"system": "SentryLog Engine", "status": "online", "db": "active"}

@app.post("/api/v1/telemetry", status_code=status.HTTP_202_ACCEPTED)
async def ingest_telemetry(
    payload: TelemetryPayload, 
    client_identity: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    timestamp = datetime.utcnow()
    db_log = LogEntryModel(
        timestamp=timestamp,
        client_identity=client_identity,
        event_type=payload.event_type,
        source_ip=payload.source_ip,
        severity=payload.severity.upper(),
        message=payload.message
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    
    logger.info(
        f"ACCEPTED & STORED (ID: {db_log.id}) | Client: {client_identity} | "
        f"Event: {payload.event_type} | Severity: {payload.severity} | SrcIP: {payload.source_ip}"
    )
    
    return {
        "status": "ingested_and_persisted",
        "record_id": db_log.id,
        "timestamp": timestamp.isoformat(),
        "authenticated_as": client_identity
    }

@app.get("/api/v1/logs", status_code=status.HTTP_200_OK)
async def get_security_logs(
    limit: int = 10,
    client_identity: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    logs = db.query(LogEntryModel).order_by(LogEntryModel.timestamp.desc()).limit(limit).all()
    
    formatted_logs = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "client": log.client_identity,
            "event_type": log.event_type,
            "source_ip": log.source_ip,
            "severity": log.severity,
            "message": log.message
        }
        for log in logs
    ]
    
    logger.info(f"RETRIEVAL | Client {client_identity} queried the last {len(formatted_logs)} log records.")
    
    return {
        "status": "success",
        "count": len(formatted_logs),
        "logs": formatted_logs
    }